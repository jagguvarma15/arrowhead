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
3. AuthKit serves the OAuth metadata and supports the Dynamic Client
   Registration MCP clients use, so no manual client registration is needed.

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

## Scaling note

A persistent disk attaches to a single instance, so the reference deployment
runs one instance and the write corpus stays consistent. Scaling the request
tier to many replicas means moving the corpus behind object storage; see the
roadmap in the plan.
