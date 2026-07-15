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
