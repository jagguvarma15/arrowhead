# Deploying a reference instance

This runbook stands up a public reference deployment of Arrowhead on Render
with WorkOS AuthKit for authentication. It is written for a showcase instance,
not a multi-tenant SaaS: one instance, a persistent disk for the corpus, and
managed Redis.

## Prerequisites

- A Render account and this repository connected to it.
- A WorkOS account with an AuthKit project (or any OAuth 2.1 IdP for the `jwt`
  provider path — Keycloak works well self-hosted).
- The public URL Render will assign (e.g. `https://arrowhead.onrender.com`), or
  a custom domain. This URL is the server's **canonical resource URI** and must
  match the token audience.

## 1. Configure WorkOS AuthKit

1. In the WorkOS dashboard, create or open an AuthKit project.
2. Note the AuthKit domain (e.g. `https://your-project.authkit.app`).
3. AuthKit serves the OAuth metadata MCP clients discover, so no manual client
   registration is needed on this server's side.

The `workos` provider is configuration sugar over the standard JWKS path: it
derives the issuer (`https://<domain>`) and the JWKS URI
(`https://<domain>/oauth2/jwks`) from the AuthKit domain, and the server
verifies tokens with its in-house verifier exactly as it would for any OAuth 2.1
issuer. AuthKit-specific conveniences beyond token verification and RFC 9728
discovery are not part of this path; pointing `jwt` at the same issuer and JWKS
URI is equivalent.

## 2. Deploy on Render

The blueprint in `deploy/render.yaml` declares the web service, a managed Redis
instance, and a persistent disk for the corpus. Create the service from the
blueprint, then set these environment variables (the blueprint marks them
`sync: false` so they are entered in the dashboard, not committed):

| Variable | Value |
|---|---|
| `ARROWHEAD_OAUTH_PROVIDER` | `workos` |
| `ARROWHEAD_OAUTH_AUTHKIT_DOMAIN` | your AuthKit domain |
| `ARROWHEAD_SERVER_PUBLIC_URL` | the service's public URL (canonical resource URI) |
| `ARROWHEAD_ALLOWED_HOSTS` | the public hostname |
| `ARROWHEAD_ALLOWED_ORIGINS` | the public origin |

`ARROWHEAD_REDIS_URL` and `ARROWHEAD_DOCS_ROOT` are wired by the blueprint (the
Redis connection string and the disk mount path). Auth is enabled and the
transport is HTTP by default in the blueprint.

For the bring-your-own-IdP path instead, set `ARROWHEAD_OAUTH_PROVIDER=jwt` and
`ARROWHEAD_OAUTH_ISSUER`, `ARROWHEAD_OAUTH_AUDIENCE` (= the public URL's
resource), and `ARROWHEAD_OAUTH_JWKS_URI`.

Render terminates TLS and routes HTTPS to the container. The health check
points at `/health`, which needs no token.

## 3. Verify the live instance

```bash
# Liveness and readiness (no token needed)
curl https://<your-service>/health
curl https://<your-service>/ready

# Discovery metadata (RFC 9728)
curl https://<your-service>/.well-known/oauth-protected-resource/mcp
```

Then connect an MCP client (MCP Inspector, or Claude) to
`https://<your-service>/mcp`. The client performs the OAuth flow against WorkOS,
obtains a token, and can call the tools its scopes allow. Confirm `doc_write`
then `doc_read` round-trip.

## 4. Observability (optional)

Point traces and metrics at a collector by setting
`ARROWHEAD_OTEL_EXPORTER_OTLP_ENDPOINT` (OTLP/HTTP base URL) and, if needed,
`ARROWHEAD_OTEL_EXPORTER_OTLP_HEADERS`. Without an endpoint, telemetry is a
no-op. Audit logs are JSON on stdout and can be shipped via Render's log
stream.

## 5. Rollback

Render keeps previous deploys. To roll back, open the service's Deploys tab and
redeploy the last known-good deploy. Because the corpus lives on the persistent
disk (not the image), a rollback does not lose written documents.

## 6. Corpus backup and restore

The document corpus is on the Render disk mounted at
`/var/lib/arrowhead/documents`.

- **Backup**: use Render's disk snapshots, or copy the directory out with a
  one-off shell into the instance (`tar czf - /var/lib/arrowhead/documents`).
- **Restore**: extract a backup into the same path and restart the service.

## 7. Load smoke

Against a local stack (auth off), sanity-check concurrency and rate limiting:

```bash
docker compose -f deploy/docker-compose.yml up --build -d
uv run python scripts/loadtest.py http://localhost:8000 200
docker compose -f deploy/docker-compose.yml down -v
```

It reports health, readiness, latency percentiles, and how many calls were
rate-limited under the burst.

## Choosing a profile

Set `ARROWHEAD_PROFILE` to expose only the tool families the deployment serves:
`core`, `docs`, `coding`, or `full` (the default). A smaller profile keeps the
tool list that rides in every connected model's context lean. A `coding`
deployment must also set `ARROWHEAD_REPO_ROOT` to the source tree the repo
tools serve (read-only, mounted into the container); without it the repo jail
points at a `repo` directory that does not exist and every repo tool fails.

## Enabling sandboxed execution

The `exec` family is doubly gated. Set `ARROWHEAD_EXEC_ENABLED=true` and grant
the `execute` action in the authorization policy; both are required. Prefer the
container runner in production: set `ARROWHEAD_EXEC_RUNNER=container` and
`ARROWHEAD_EXEC_CONTAINER_IMAGE` to an image with the tools a snippet needs. The
container runner adds `--network none` and a read-only root filesystem that the
default subprocess runner cannot; the subprocess runner bounds resources but
leaves network and filesystem reads to OS permissions. `run_tests` also needs
`ARROWHEAD_EXEC_TEST_COMMAND` set to the argv that runs the suite inside the
copied subtree.

## Fronting a local model

To back the assist tools with a local model server (Ollama, vLLM, LM Studio),
set `ARROWHEAD_LLM_PROVIDER=openai`, point `ARROWHEAD_LLM_ENDPOINT` at its
OpenAI-compatible chat-completions URL, and name its exact `host:port` in
`ARROWHEAD_LLM_INTERNAL_HOSTS` so the SSRF guard admits it. For a hosted model,
use `ARROWHEAD_LLM_PROVIDER=anthropic` (or `openai` against a cloud endpoint)
and supply `ARROWHEAD_LLM_API_KEY` out of band.

## Scaling note

A persistent disk attaches to a single instance, so the reference deployment
runs one instance and the write corpus stays consistent. Scaling the request
tier to many replicas means moving the corpus behind object storage. The task
and working-set registries are likewise in-process today; a shared backend (the
rate limiter already uses Redis) is the seam for a multi-instance deployment.
