# Architecture

Arrowhead is a FastMCP v3 application served over streamable HTTP in stateless
mode (stdio for local development). Stateless means the server keeps no
per-session state, so any replica can serve any request and horizontal scaling
needs no sticky sessions. Shared state that must survive across replicas — the
rate-limit buckets — lives in Redis, keyed explicitly rather than by transport
session.

## Request flow

Every `tools/call` passes through the same chain before and after the tool
runs. The middleware is ordered so the trace span wraps everything and the
audit line records the outcome of even the requests that never reach a tool.

```
client
  |
  v
[ TLS termination ]            platform / reverse proxy (not FastMCP)
  |
  v
[ Host / Origin check ]        rejects rebinding of the endpoint
  |
  v
[ OAuth 2.1 verification ]     signature, issuer, expiry, audience -> 401 on failure
  |
  v
[ Tracing middleware ]         opens an OpenTelemetry span, joins caller trace context
  |
  v
[ Audit middleware ]           will log caller, tool, arg shapes, status, latency
  |
  v
[ Kill switch ]                refuses disabled tools
  |
  v
[ Rate limiter ]               per-caller, per-tool token bucket (Redis-backed)
  |
  v
[ Scope check ]                caller must hold the tool's scope, else the tool is invisible
  |
  v
[ Tool handler ]               input validation -> guarded action -> result
  |                              (ssrf_guard / sandbox / path jail)
  v
[ Audit middleware ]           emits one structured log line
  |
  v
[ Tracing middleware ]         closes the span with ok/error status
  |
  v
client
```

A refusal at any stage (401, kill switch, rate limit, or a validation failure
inside the tool) still produces an audit line and a closed span, so nothing is
invisible to operators.

## Authentication flow

```
1. Client calls the server without a token.
2. Server responds 401 with a pointer to
   /.well-known/oauth-protected-resource/mcp (RFC 9728).
3. Client reads that metadata, discovers the authorization server, and
   completes an OAuth 2.1 + PKCE flow against it (not against Arrowhead).
4. Client retries with the bearer token.
5. Server verifies signature (JWKS or static key), issuer, expiry, and that
   the audience names this server, then checks the tool's required scope.
```

Arrowhead issues no tokens and stores no client secrets. It is purely a
resource server.

## Module layout

```
src/arrowhead/
  server.py              builds the app: auth provider + middleware + tools
  config.py              all settings, ARROWHEAD_-prefixed environment vars
  cache.py               ttlMs / cacheScope hints on tools/list
  auth/
    oauth.py             resource server + mandatory audience validation
    scopes.py            tool -> required scope
    identity.py          caller identity from the validated token only
  tools/
    registry.py          registers the three tools with annotations + scopes
    safe_fetch.py        SSRF-guarded fetch
    calculate.py         validation + sandboxed evaluation
    read_file.py         path-jailed reader
  security/
    ssrf_guard.py        resolve, block private ranges, pin the address
    input_validation.py  shared allowlist validators
    sandbox.py           AST arithmetic interpreter (no eval)
    rate_limit.py        token-bucket limiter, memory or Redis store
    kill_switch.py       per-tool disable
  observability/
    audit_log.py         structured, source-redacted audit line
    tracing.py           OpenTelemetry span + W3C trace context
```

## Deployment shape

```
                 +-------------------+
   HTTPS  ---->  |  platform / proxy |  (TLS termination)
                 +---------+---------+
                           | HTTP
                           v
                 +-------------------+        +-----------+
                 |  arrowhead (N x)  | <----> |   Redis   |  (rate-limit buckets)
                 |  stateless HTTP   |        +-----------+
                 +-------------------+
                           |
                           v
                 external OAuth 2.1 authorization server
                 (token issuance, JWKS)
```

Because the server is stateless, `N` replicas run behind the platform's load
balancer with no coordination beyond the shared Redis. See `deploy/` for the
container image and the Render and Fly.io blueprints.
