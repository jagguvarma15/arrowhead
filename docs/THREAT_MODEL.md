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
- **Residual risk:** by default any service at a genuinely public address is
  fetchable, since this is a general-purpose fetch tool. A deployment that
  needs to restrict destinations sets an egress allowlist
  (`ARROWHEAD_EGRESS_ALLOWED_HOSTS`), which confines the fetch and retrieve
  tools to approved hosts and is enforced on every redirect hop. With it unset
  the guard still blocks private ranges but not public destinations.

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

### Document suite (`doc_search`, `doc_read`, `doc_retrieve`, `doc_scan`, `doc_write`)

- **Inputs:** a corpus-relative path or prefix, a search query, content bytes,
  and (for retrieve) a URL. All are attacker-controlled.
- **Attacks considered:** indirect prompt injection via returned content;
  Markdown image/link exfiltration and embedded HTML/script; JSON bombs (deep
  nesting, duplicate keys, huge structures); ANSI/control/UTF-7/homoglyph text
  injection; ReDoS from a user-supplied search pattern; path traversal and
  symlink escape on read, scan, and write; clobbering or partially writing a
  document; writing outside the caller's namespace; leaking a secret's raw
  value through a scan result or log; and, on retrieve, the full SSRF set plus
  decompression bombs.
- **Controls:** the per-format content sanitizers and provenance wrapping; the
  bounded, symlink-safe document store with atomic no-clobber writes and
  quotas; scope-by-verb plus a default-deny per-resource authorization check;
  redaction-only scan findings; a ReDoS-resistant matcher with a timeout; the
  reused SSRF guard and decompressed-size cap on retrieve; and elicitation
  confirmation for destructive overwrites.
- **Residual risk:** the sanitizers are conservative transforms, not full
  renderers; a client that renders returned Markdown must still apply its own
  output-side controls (an image proxy, a content security policy). Search and
  scan read document contents, so a caller with those scopes over a subtree can
  infer the presence of matching or sensitive data within what the policy lets
  it access.

### Data connectors (`sql_query`, `vector_search`)

- **Surface:** arbitrary SQL and vector queries against a configured database.
  The primary risks are write/DDL smuggling, injection through table or column
  names, denial of service through an expensive query, and cross-tenant reads.
- **Mitigations:** a real SQL parser (with bounded nesting so it cannot be made
  to exhaust its stack) admits only a single read-only `SELECT`, rejecting
  stacked statements, writes, DDL, `SET`, row-locking clauses, and a denylist of
  side-effecting, file, network, and administrative functions. Every referenced
  table is authorized; a tableless query is authorized against a dedicated
  resource the default policy does not grant. On Postgres the query runs in a
  read-only transaction under a server-side statement timeout; a read-only role
  is the primary control on every engine. Results are bounded by byte, row, and
  column count. For `vector_search`, the connector requires Postgres, the
  collection is allow-listed, all interpolated identifiers pass a strict guard,
  the embedding is a bound parameter of finite numbers, and the tenant filter is
  the authenticated caller injected server-side.
- **Residual risk:** the parser and function denylist are defense in depth, not a
  sandbox; a misconfigured deployment that grants a writable role or a broad
  authorization policy widens the surface, and the denylist is not exhaustive.
  On non-Postgres engines there is no server-side read-only transaction, so the
  read-only role and the parser carry the weight; on SQLite an expensive query
  cannot be interrupted mid-flight by the in-process deadline, so SQLite is a
  demo backend, not a hardened multi-tenant target. Tenant isolation depends on
  the collection carrying a correct tenant column.

### Resources, prompts, completions, and tasks

- **Surface:** a second path to corpus content (resources), a server-provided
  instruction channel (prompts), a discovery oracle (completions), and
  server-minted handles for background work (tasks).
- **Mitigations:** resource reads run the same per-resource authorization and
  sanitization as `doc_read`; prompts reference resources or tools rather than
  inlining untrusted content and sanitize their arguments; completions are
  filtered by the caller's read authorization, bounded, and wrapped so they pass
  the same rate limit, kill switch, and audit line as a tool call even though the
  low-level path bypasses the middleware chain; tasks are authorized at start,
  owner-scoped so a caller can only poll or cancel its own, and bounded in
  count.
- **Residual risk:** completions confirm which authorized paths exist, the same
  inference a caller with search access already has. The task registry is in
  process, so a task is visible only on the instance that created it.

## Cross-cutting

- **Authentication:** enforced over HTTP; audience validation is mandatory and
  tokens are never forwarded. Over stdio (local development against a process
  the operator already owns) auth is skipped.
- **Authorization:** scopes are split by verb, and the document tools add a
  per-resource, default-deny check on top; a scope alone never grants access to
  a specific document.
- **Rate limiting and kill switch:** bound abuse volume and allow rapid
  disabling of a tool without redeploying. Every tool has a ceiling; a tool
  without an explicit one falls back to a configurable default.
- **Audit and tracing:** provide after-the-fact accountability without leaking
  argument values; authorization denials are recorded distinctly.

## Explicitly out of scope for this version

- **Full multi-tenant isolation.** The per-resource policy demonstrates
  per-subject write namespaces and prefix grants, but there is no tenant
  boundary beyond the subject claim, no per-document ACL store, and no external
  policy engine wired in (the `Authorizer` seam exists for one).
- **Output-side rendering controls.** Returned content is sanitized at the
  server, but a client that renders it must still apply its own image proxy and
  content security policy; the server cannot enforce those.
- **Content classification beyond secrets/PII patterns.** `doc_scan` uses a
  fixed pattern set; it is not a comprehensive DLP or malware scanner.
- **TLS termination.** Delegated to the hosting platform or a reverse proxy.
- **Authorization-server security.** Token issuance, client registration, and
  key rotation belong to the external IdP, not to this server.
- **Tool-definition pinning / rug-pull detection.** The server sets honest
  annotations but does not yet expose a pinned tool-definition hash for clients
  to re-consent against.
- **Denial of service beyond per-caller rate limits.** Network-level flood
  protection is the platform's job. The document quota check walks the corpus on
  each write, which is O(corpus size); the in-memory rate-limit store is
  per-replica, and while the Redis store reads time from the server, an operator
  running the in-memory store across replicas with skewed clocks gets
  per-replica limits.
- **Filesystem races on the read path.** The document store and `read_file`
  resolve a path and then open it; an attacker with write access inside the jail
  could swap a path for a symlink between the two steps (a TOCTOU window). Atomic
  writes are hard-link based, which assumes the filesystem supports hard links.
- **Multi-line and non-ASCII-normalized secrets.** `doc_scan` is line-oriented,
  so a secret split across lines (a wrapped private key) is detected by its
  header only, and its tag is of the NFC-normalized text, not the on-disk bytes.
