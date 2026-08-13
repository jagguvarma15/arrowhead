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

### Repo intelligence (`code_search`, `code_read`, `symbol_map`, `dependency_graph`)

- **Surface:** read-only access to a source tree, which typically holds
  credentials in config files, private URLs in version-control metadata, and
  the shape of an organization's code.
- **Mitigations:** the repo store applies the document store's containment rule
  (resolve, then require the path to stay inside the root) to a separate jail,
  is read-only by construction, prunes `.git` and dependency directories from
  every walk so version-control internals are unreachable, refuses binary files
  by content sniff, and caps per-file and per-walk size. Repository resources
  have their own authorization kinds, so a grant over corpus documents never
  reaches code and vice versa; the default policy grants only read and search on
  the repo. Symbol and dependency results are filtered per file, so they never
  name something in a file the caller could not read directly.
- **Residual risk:** a caller granted broad repo read can infer the presence of
  matching content the same way corpus search allows. Symbol extraction for
  non-Python languages without the tree-sitter extra is a line heuristic and may
  miss or misclassify a definition.

### Assist tools (`code_explain`, `summarize_diff`, `rerank`)

- **Surface:** an outbound request to a model backend carrying code or a diff,
  and model output flowing back into the caller's context.
- **Mitigations:** the completion providers post through the SSRF-guarded,
  redirect-refusing path the embedding client uses; the API key is
  configuration-supplied and never appears in an error. `code_explain` reads
  through the repo jail under the same authorization as `code_read`, so the
  assist path can reach no code the read path could not. A local model endpoint
  is reachable only through the exact-pair internal allowlist. Every input is
  bounded and sanitized, and all model output returns inside the untrusted
  framing, because a model reading attacker-influenced source can be steered by
  it; `rerank` asks only for an ordering and parses it defensively, so a hostile
  answer cannot inject content.
- **Residual risk:** the backend is a third party (unless self-hosted); what it
  does with a prompt is outside this server's control. The tools are only as
  private as the endpoint an operator points them at.

### Sandboxed execution (`run_snippet`, `run_tests`)

- **Surface:** arbitrary code execution, the highest-privilege operation the
  server offers.
- **Mitigations:** off by default and denied by the default policy, so a
  deployment opts in twice (the `ARROWHEAD_EXEC_ENABLED` flag and the `execute`
  grant). The subprocess runner scrubs the environment, bounds CPU, memory, wall
  time, output, and process count, runs an explicit argv with no shell, uses a
  fresh per-call scratch directory, and secret-scans and redacts output.
  `run_tests` copies only the authorized subtree into scratch, so a test that
  writes never touches the real repository.
- **Residual risk (stated plainly):** the subprocess runner does **not** block
  network egress or filesystem reads beyond OS permissions. A snippet can reach
  the network and read world-readable files. A deployment that needs those
  isolated must use the container runner (`--network none`, read-only root) or
  an external sandbox. On macOS, `RLIMIT_AS` memory bounding is best effort.

### Context packer and working sets (`pack_context`, `workingset_*`)

- **Surface:** a single call that assembles many sources into one bundle, and
  a per-caller store of pinned references.
- **Mitigations:** the packer reaches every source through the same internal
  functions the standalone tools use, re-authorizes each pinned item at pack
  time, secret-scans and redacts every snippet before it leaves, wraps each in
  per-snippet untrusted framing with an unforgeable random marker, and caps the
  bundle at the token budget. Working sets are owner-keyed and bounded exactly
  like the task registry; a set another owner holds reads as not found, and
  pinning authorizes each item.
- **Residual risk:** the working set registry is in process, so a set is visible
  only on the instance that created it, the same single-instance limitation the
  task registry documents.

## Cross-cutting

- **Authentication:** enforced over HTTP; audience validation is mandatory and
  tokens are never forwarded. Over stdio (local development against a process
  the operator already owns) auth is skipped.
- **Tool integrity:** the `arrowhead://integrity` digest lets a client pin the
  tool surface it consented to and detect a later change to what a tool
  advertises.
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
- **Network egress and filesystem isolation for sandboxed execution.** The
  default subprocess runner bounds resources but does not confine network or
  filesystem access beyond OS permissions; isolation requires the container
  runner or an external sandbox. This is a documented property of the runner
  choice, not a gap to be closed in the subprocess path.
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
