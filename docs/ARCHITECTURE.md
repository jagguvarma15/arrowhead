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
[ Tool handler ]               input validation
  |                              -> per-resource authorization (document tools)
  |                              -> guarded action
  |                              -> content sanitization + provenance (read side)
  |                              (ssrf_guard / sandbox / path jail / authz / content)
  v
[ Audit middleware ]           emits one structured log line
  |
  v
[ Tracing middleware ]         closes the span with ok/error status
  |
  v
client
```

The scope check is a capability gate (may this caller use this tool at all).
The per-resource authorization inside the document tools is a separate, finer
gate (may this caller act on this specific document): identity comes from the
validated token, the default policy is deny, and a denial is audited as an
`AuthorizationError` refusal without echoing the resource.

A refusal at any stage (401, kill switch, rate limit, scope, per-resource
authorization, or a validation failure inside the tool) still produces an audit
line and a closed span, so nothing is invisible to operators.

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
    scopes.py            tool -> required scope, split by verb
    identity.py          caller identity from the validated token only
  authz/
    policy.py            default-deny per-resource ABAC + Authorizer seam
    enforce.py           enforcement point the document tools call
    confirmation.py      elicitation confirmation for destructive actions
  store/
    document_store.py    jailed corpus: read, list, stat, atomic write
  content/
    provenance.py        untrusted-data wrapping with randomized delimiters
    json_safe.py         bounded JSON parsing
    markdown_safe.py     HTML and image-exfiltration removal
    text_safe.py         ANSI / control / invisible-character stripping
  tools/
    registry.py          registers all tools with annotations + scopes
    safe_fetch.py        SSRF-guarded fetch
    calculate.py         validation + sandboxed evaluation
    read_file.py         path-jailed reader
    doc_search.py        bounded, read-filtered corpus search
    doc_read.py          format-aware sanitized document read
    doc_retrieve.py      SSRF-guarded external fetch + sanitize
    doc_scan.py          secrets / PII scan with redaction
    doc_write.py         atomic, confirmed document write
  security/
    ssrf_guard.py        resolve, block private ranges, pin the address
    input_validation.py  shared allowlist validators
    sandbox.py           AST arithmetic interpreter (no eval)
    search_match.py      ReDoS-safe literal / timed-regex matcher
    secret_scan.py       fixed-pattern secret and PII detection
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
