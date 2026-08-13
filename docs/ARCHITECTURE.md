# Architecture

Arrowhead is an application on the official MCP Python SDK (the `mcp` package,
version 2), served over streamable HTTP in stateless mode (stdio for local
development). Stateless means the server keeps no per-session state, so any
replica can serve any request and horizontal scaling needs no sticky sessions.
Shared state that must survive across replicas — the rate-limit buckets — lives
in Redis, keyed explicitly rather than by transport session.

One endpoint serves both protocol eras. A request carrying the reserved `_meta`
envelope takes the sessionless 2026-07-28 leg; a request that sends the
`initialize` lifecycle takes the handshake-era leg, negotiated down to the
latest handshake version. The SDK routes between them; the application
configures nothing.

## Request flow

The guards do not live in message middleware. Each tool, resource, and prompt is
registered wrapped in a guard chain (`arrowhead.runtime.guards`) that reproduces
the prior middleware order on the component itself, so an import-and-call
invocation (`Arrowhead.call`) runs the identical path as an HTTP request with no
duplicated logic. Two thin SDK middlewares remain, and neither refuses: one
records the request `_meta` for trace-context propagation, the other filters
list results by the kill switch and scope. Every refusal lives in the wrapper.

```
client
  |
  v
[ TLS termination ]            platform / reverse proxy (not the server)
  |
  v
[ Host / Origin check ]        rejects rebinding of the endpoint (when configured)
  |
  v
[ Token verification ]         JWKS signature, issuer, expiry, audience -> 401 on failure
  |
  v
[ meta-capture middleware ]    records request _meta for trace propagation (never refuses)
  |
  v
--- guard wrapper on the component ---------------------------------
  |
  v
[ Tracing span ]               opens an OpenTelemetry span, joins caller trace context
  |
  v
[ Audit ]                      times the call; will log caller, name, arg shapes, status
  |
  v
[ Kill switch ]                refuses disabled tools
  |
  v
[ Rate limiter ]               per-caller, per-tool token bucket (Redis-backed)
  |
  v
[ Scope check ]                caller must hold the scope, else the component is unknown
  |
  v
[ Handler ]                    input validation
  |                              -> per-resource authorization (document, repo, exec)
  |                              -> guarded action
  |                              -> content sanitization + provenance (read side)
  |                              (ssrf_guard / runner / path jail / authz / content)
  |
  v
[ Exception boundary ]         ToolError re-raised verbatim; anything else masked
  |
  v
[ Audit ]                      emits one structured log line (ok / refused / error)
  |
  v
[ Tracing span ]               closes with ok/error status
--------------------------------------------------------------------
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
  server.py              builds the MCPServer: verifier + cache hints + components
  app.py                 importable facade: call, read_resource, get_prompt
  config.py              all settings, ARROWHEAD_-prefixed environment vars
  errors.py              the project ToolError every guard and tool raises
  runtime/
    guards.py            per-component guard wrappers + listing filter
  auth/
    oauth.py             resource server wiring + mandatory audience validation
    verifier.py          in-house JWKS bearer verifier (pyjwt)
    scopes.py            component -> required scope, split by verb
    identity.py          caller identity from the validated token only
    principal.py         in-process principal for the import path
  authz/
    policy.py            default-deny per-resource ABAC + Authorizer seam
    enforce.py           enforcement point every component calls
    confirmation.py      Resolve-based confirmation for destructive actions
  store/
    document_store.py    jailed corpus: read, list, stat, atomic write
  repo/
    store.py             jailed, read-only source tree
    symbols.py           symbol extraction (ast / tree-sitter / heuristic)
    dependencies.py      bounded Python import graph
  content/
    provenance.py        untrusted-data wrapping with randomized delimiters
    render.py            shared format-aware document renderer
    chunking.py          bounded character windows
    code_chunking.py     structure-aware chunking for source files
    json_safe.py, markdown_safe.py, text_safe.py   format sanitizers
  tools/
    catalog.py           the component contract: specs, families, profiles
    registry.py          registers in-profile components behind the guards
    integrity.py         the pinned tool-surface digest
    <tool>.py            one module per tool
  connectors/
    sql.py               vetted read-only SQL over a pooled async engine
    pgvector.py          pgvector search with server-side tenant isolation
    hybrid.py            vector + full-text fusion retrieval
    pgvector_index.py    diff-aware chunk-and-embed ingestion
    tasks.py             handle-based async tasks, owner-scoped
  embeddings/            the embedding provider seam
  llm/
    base.py, transport.py, anthropic_http.py, openai_http.py, factory.py
                         the completion provider seam, one hardened HTTP path
  exec/
    base.py              the runner seam: request and outcome
    subprocess_runner.py rlimit-bounded, env-scrubbed subprocess
    container_runner.py  network-none, read-only container runner
  workingsets.py         owner-scoped working set registry
  resources/, prompts/, completions/                the non-tool primitives
  security/
    ssrf_guard.py        resolve, block private ranges, pin; trusted-internal gate
    input_validation.py  shared allowlist validators
    sandbox.py           AST arithmetic interpreter (no eval)
    search_match.py      ReDoS-safe literal / timed-regex matcher
    secret_scan.py       fixed-pattern secret/PII detection and redaction
    rate_limit.py        token-bucket limiter, memory or Redis store
    kill_switch.py       per-component disable
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
                 |     arrowhead     | <----> |   Redis   |  (rate-limit buckets)
                 |   HTTP + disk     |        +-----------+
                 +-------------------+
                    |            |
                    v            v
        persistent disk     external OAuth 2.1
        (document corpus)   authorization server (JWKS)
```

The request path itself is stateless — any instance can serve any request,
and the rate-limit buckets live in shared Redis. The one piece of durable
local state is the write-capable document corpus, which is backed by a
persistent disk. Because a disk attaches to a single instance, the reference
deployment runs **one** instance so the corpus stays consistent; scaling the
write corpus horizontally means moving it behind object storage (a roadmap
item) so the request tier can again run many replicas. See `deploy/` for the
container image and the Render and Fly.io blueprints.
