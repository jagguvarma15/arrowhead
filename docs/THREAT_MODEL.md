# Threat model

This document breaks down the attack surface per tool and states what is
explicitly out of scope for this version.

## Assets and trust boundaries

- **The host environment.** The process runs inside a container with access to
  outbound network and a small jailed directory. The metadata endpoint,
  internal services, and the broader filesystem are assets an attacker would
  want to reach through the tools.
- **The authorization boundary.** Over HTTP, callers are authenticated by an
  external OAuth 2.1 authorization server. The bearer token is the only trusted
  assertion of identity; headers, arguments, and anything else the caller
  controls are untrusted.
- **Log storage.** Audit logs are shipped somewhere. Anything written into
  them is assumed to be readable by operators, so argument values must never
  land there.

The caller (the MCP client, and by extension whatever drives it) is untrusted.
Every tool argument is attacker-controlled input.

## Per-tool attack surface

### `safe_fetch`

- **Inputs:** one URL, plus any `Location` headers on redirects.
- **Attacks considered:** requests to the cloud metadata endpoint (IPv4 and
  IPv6), private/loopback/link-local ranges, non-HTTP schemes, DNS rebinding
  (public record at check time, private at connection time), redirect chains
  that end at an internal address, oversized responses used to exhaust memory,
  and reuse of the caller's token as outbound credentials.
- **Controls:** scheme allowlist, resolve-and-check-every-address, address
  pinning, per-hop re-validation, response size cap, and construction of
  outbound requests without inbound credentials.
- **Residual risk:** a service reachable at a genuinely public address is
  fetchable — this is a general-purpose fetch tool, not an allowlist of
  approved destinations. Deployments that need destination allowlisting should
  add it on top.

### `calculate`

- **Inputs:** one expression string.
- **Attacks considered:** code injection via `eval`-style payloads, shell
  metacharacters, Python dunder traversal (`().__class__…`), and
  resource-exhaustion via very long or deeply structured expressions.
- **Controls:** character allowlist, AST interpreter restricted to numbers and
  basic operators, length and node-count bounds.
- **Residual risk:** none known within arithmetic; the tool intentionally does
  nothing but arithmetic.

### `read_file`

- **Inputs:** one relative path string.
- **Attacks considered:** `../` traversal, absolute paths, symlinks pointing
  outside the jail, null-byte tricks, path disclosure through error messages,
  and oversized files.
- **Controls:** relative-path validation, canonicalization with symlink
  resolution, jail-containment check, path-free error messages, size cap.
- **Residual risk:** any file the operator places inside the jail is readable
  by any authorized caller. The jail's contents are the operator's
  responsibility.

## Cross-cutting

- **Authentication:** enforced over HTTP; audience validation is mandatory and
  tokens are never forwarded. Over stdio (local development against a process
  the operator already owns) auth is skipped.
- **Rate limiting and kill switch:** bound abuse volume and allow rapid
  disabling of a tool without redeploying.
- **Audit and tracing:** provide after-the-fact accountability without leaking
  argument values.

## Explicitly out of scope for this version

- **Multi-tenant, per-caller tool permissioning.** All authorized callers see
  the same set of tools; there is one scope tier (`tools:read`). Fine-grained
  per-tenant policies are not modeled.
- **Write or mutating tools.** Every tool is read-only. There is no
  `tools:write` scope in use.
- **Output/content filtering.** Fetched bodies and file contents are returned
  as-is (size-capped). Scanning returned content for secrets or malware is not
  attempted.
- **TLS termination.** Delegated to the hosting platform or a reverse proxy.
- **Authorization-server security.** Token issuance, client registration, and
  key rotation belong to the external IdP, not to this server.
- **Denial of service beyond per-caller rate limits.** Network-level flood
  protection is the platform's job.
