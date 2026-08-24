# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Migrated the server core onto the official MCP Python SDK (the `mcp` package,
  version 2), replacing the FastMCP framework. One streamable-HTTP endpoint now
  serves the sessionless 2026-07-28 protocol natively and handshake-era clients
  on the same endpoint. The guard chain (tracing, audit, kill switch, rate
  limit, scope check, exception masking) moved from message middleware into
  per-component wrappers, so the import-and-call path runs the identical path as
  an HTTP request; cache hints and argument completion use first-class SDK
  APIs, and destructive-write confirmation uses the SDK's `Resolve`
  elicitation. Bearer tokens are verified in-house with pyjwt against the
  issuer's JWKS or a static key; the `workos` provider derives its issuer and
  JWKS URI from the AuthKit domain.
- Toolset profiles (`ARROWHEAD_PROFILE`: `core`, `docs`, `coding`, `full`)
  select which tool families a deployment exposes, so a connection carries only
  the tools it needs. A tool outside the active profile is unregistered, costs
  no context, and is unknown on call.
- A tool-integrity digest at the `arrowhead://integrity` resource: a sha256 over
  the semantic surface of every enabled tool, so a client can pin the surface it
  consented to and detect a later change.
- Hybrid, code-aware retrieval: `hybrid_query` fuses vector similarity with
  Postgres full-text rank by reciprocal rank fusion; source files chunk along
  their structure; and a re-index re-embeds only chunks whose content hash
  changed, reporting how many were reused. The schema gains `content_hash` and a
  generated `content_tsv` column.
- Repository intelligence over a jailed, read-only source tree: `code_search`,
  `code_read`, `symbol_map` (stdlib parser, an optional tree-sitter extra, or a
  line heuristic), and `dependency_graph`. Repository resources have their own
  authorization kinds, separate from corpus documents.
- Model-backed assist tools over a pluggable completion provider seam
  (`code_explain`, `summarize_diff`, `rerank`): an Anthropic Messages adapter
  and an OpenAI-compatible adapter, both posting through the SSRF-guarded,
  redirect-refusing path. A local model server is reachable only by naming its
  exact `host:port` in `ARROWHEAD_LLM_INTERNAL_HOSTS`, a deliberate exemption
  that leaves the public SSRF posture unchanged.
- Sandboxed execution behind a runner seam (`run_snippet`, `run_tests`): off by
  default and denied by the default policy, so a deployment opts in twice. The
  subprocess runner scrubs the environment and bounds CPU, memory, wall time,
  output, and process count; a container runner adds network and filesystem
  isolation. Output is secret-scanned and redacted before it leaves.
- A guarded context packer (`pack_context`) and owner-scoped working sets
  (`workingset_get`, `workingset_update`): the packer returns a token-budgeted
  bundle of pinned and retrieved snippets, each re-authorized, secret-scanned,
  provenance-stamped, and wrapped as untrusted data.
- Retrieval over the corpus: `doc_index` chunks, embeds, and writes documents
  into a pgvector collection under the caller's tenant, and `vector_query` embeds
  a natural-language query server-side and returns the nearest chunks with their
  source and chunk index as citations. Embeddings come from a pluggable provider
  (a stdlib deterministic default, or an OpenAI-compatible HTTP endpoint reached
  through the SSRF guard and the egress allowlist). Ingestion uses a write
  credential separate from the read-only DSN (`ARROWHEAD_VECTOR_WRITE_DSN`) and a
  dedicated `ingest` action the default policy denies. See
  `deploy/pgvector_schema.sql`, `docs/INTEGRATIONS.md`, and `examples/docs_rag/`.
- Handle-based asynchronous tasks following the 2026-07-28 stateless pattern:
  `scan_corpus_async` starts a background corpus scan and returns a server-minted
  handle, `task_get` polls it, and `task_update` cancels it. A task is owned by
  the caller that started it and is guarded, rate-limited, and kill-switchable
  like every other tool.
- Argument completion now passes the same per-caller rate limit, kill switch,
  and audit line as a tool call, closing the one request path that bypassed the
  middleware chain.
- Wire-level 2026-07-28 support now that the server runs on the official SDK
  version 2: cacheable results carry native `ttl_ms`/`cache_scope` freshness
  hints (private scope), the sessionless leg serves bare enveloped requests, and
  conformance tests pin both the handshake and sessionless legs. This supersedes
  the earlier application-level-only alignment.
- A startup refusal to serve HTTP with authentication disabled unless
  `ARROWHEAD_ALLOW_INSECURE_HTTP` is set, and startup validation of the SQL
  dialect and the egress port allowlist.
- A coding-agent walkthrough (`examples/coding_agent/`) driving the repo,
  assist, exec, and context families through the importable facade.
- PyPI packaging metadata (`project.urls`, keywords, classifiers, license
  expression); CI builds the wheel and smoke-tests its console script, and the
  load test gained a `--modern` sessionless leg.
- The Arrowhead logo (`assets/`) with dark and monochrome cuts, and the README
  rewritten around it.
- `ARROWHEAD_EXEC_COPY_MAX_FILES` bounds the file count of the `run_tests`
  sandbox copy, which previously borrowed the symbol-map limit.
- Direct tests for the ReDoS-guarded search matcher and for the optional
  tree-sitter symbol backend, and a suite-wide fail-on-warning ratchet with
  coverage reported in CI.

### Fixed

- The container runner passed the CPU-seconds budget as Docker's `--cpus` core
  count, which refuses to start on small hosts and grants unbounded CPU time on
  large ones; the budget is now enforced as a CPU-time ulimit inside the
  container alongside a single-core quota.
- Runaway subprocess output is killed the moment it exceeds the byte cap
  instead of buffering in server memory until the wall clock expires.
- The working set registry's eviction could never trigger, so many distinct
  owners grew server memory without bound; the registry is now bounded globally
  as well as per owner.
- `code_explain` now enforces the same repo extension allowlist as `code_read`,
  and `pack_context` authorizes at the tool boundary like every other
  range-scoped tool.
- Disabling the `doc://{+path}` resource template now refuses the concrete
  reads it expands to as well as hiding it from listings.
- `doc_index` reports `files_indexed` as every file it processed; the chunk
  counts carry the rewrite-versus-reuse detail. Its hash lookup and chunk
  writes are batched, so a large corpus no longer pays a round trip per
  document and per chunk.
- Repo authorization denials name the file or path instead of the generic
  resource wording.
- The environment example's commented repo lists mirror the real defaults (the
  previous values silently dropped `.hg`, `.svn`, and `target` from pruning),
  the runtime jail roots (`documents/`, `exec-scratch/`, `repo/`) are
  gitignored, the compose Postgres image is digest-pinned like the other
  images, the compose file wires the repo jail for the coding profile and
  recommends the subprocess runner in-container, and the RAG example now
  starts as written (complete OAuth block, write role including `UPDATE`).

### Changed

- The `Arrowhead.call` facade method now returns an `mcp.types.CallToolResult`
  rather than a FastMCP `ToolResult`; it still raises `ToolError` on a refusal,
  carrying the guard's own message. `http_app` now returns the SDK's
  streamable-HTTP ASGI app.
- The document resource template is `doc://{+path}` (RFC 6570 reserved
  expansion) rather than `doc://{path*}`, which the SDK's URI matcher does not
  accept for multi-segment matching.
- The `fastmcp` dependency is removed; `mcp>=2` and `pyjwt` are direct
  dependencies. A `treesitter` extra adds exact non-Python symbol extraction and
  is never imported in the base install.
- Authorization grants are now kind-aware: outbound fetch is authorized under its
  own `fetch` action, so a policy can deny a caller outbound fetch without
  denying its document reads, and prefix matching is component-bounded so a grant
  on `notes` no longer reaches `notes-private`. A tableless SQL query is denied
  by default.
- The SQL guard bounds parse nesting, rejects row-locking clauses and a denylist
  of side-effecting, file, network, and administrative functions, and its result
  caps are measured in bytes with a per-cell bound. `serverInfo.version` and
  `/health` now report the real package version.
- Hot paths stopped redoing constant work: the `arrowhead://integrity` surface
  is cached per configuration instead of rebuilding a server and every schema
  per read, the authorizer cache is keyed by policy value so the library door
  no longer re-parses the policy JSON on every call, argument completion prunes
  by prefix inside the store walk, the optional tree-sitter import is probed
  once, the embedding endpoint is resolved once per call, pinned items resolve
  in one worker hop with shared stores, and the readiness probe's filesystem
  check moved off the event loop.
- `doc_search` and `code_search` run through one shared search core
  (`tools/search_core.py`), the two pgvector similarity searches merged into
  one query builder, both exec runners share one capped stream collector, audit
  lines emit through one function, the untrusted framing is a single public
  helper, and the SQL dialect alias table is single-sourced in configuration.
  Wire-visible names, descriptions, and schemas are unchanged throughout.
- Removed the unused listing filter and the unused scope-advertisement helper
  (scope discovery stays deliberately unadvertised); `rerank.model_answered`
  now reports whether the model's answer contributed any index instead of a
  constant true.
- The unused `pgvector` package left the `postgres` extra: embeddings travel
  as bound text literals cast in SQL, so only `asyncpg` is needed.
- CI pins every action to a full commit SHA, checks the lockfile, builds and
  scans the container image the deploy blueprints reference, and runs the
  security job on a weekly schedule as well as on pushes and pull requests.
- The README, security document, threat model, and architecture document now
  describe the full served surface: the tasks family, the profile-to-family
  mapping, repo-intelligence and retrieval-tool coverage, the container CPU cap
  as it is actually enforced, and the complete module layout. The README
  regained its command line, scopes, testing, and deployment sections.

### Security

- Fixed an SSRF bypass where an IPv4 address embedded in an IPv6 wrapper (NAT64
  and related forms) could reach the cloud metadata endpoint.
- Fixed a content-sanitizer bypass where a multi-line or oversized HTML tag (a
  zero-click image beacon) survived Markdown stripping.
- The secret-scan redaction tag is now keyed by a random per-process salt, so it
  is no longer brute-forceable back to a low-entropy SSN or email.
- Resource reads are audited by scheme and path shape, never the caller-supplied
  path; additional invisible and filler characters are stripped from text.

## [0.2.0]

### Added

- Liveness (`/health`) and readiness (`/ready`) endpoints, unauthenticated so a
  platform probe reaches them without a token, and graceful shutdown that
  closes the rate-limit backend.
- Durable document corpus on a persistent volume, with the deploy configs
  mounting it and running a single instance so writes stay consistent.
- WorkOS AuthKit as a selectable identity provider alongside the generic
  JWT/JWKS path, and an integration test that exercises the real JWKS
  verification path (key discovery, rotation, and audience validation).
- Production OpenTelemetry export: OTLP trace and metric export configured by
  an endpoint variable, with tool-call and duration metrics, no-op until a
  collector is set.
- CI security gate: dependency audit (pip-audit), filesystem and config
  scanning (trivy), secret scanning (gitleaks), the flake8-bandit ruff rules as
  SAST, and an SBOM. Base image digests are pinned.
- Deployment runbook (`docs/DEPLOY.md`) and a load smoke test
  (`scripts/loadtest.py`).
- Structured tool output: every tool publishes an output schema, so a client
  receives typed, structured results rather than only a text blob.
- Three new MCP primitives, each carrying the same per-resource authorization,
  content sanitization, rate limiting, audit logging, and kill-switch coverage
  as the tools: resources (a `doc://{path}` template and a `docs://index`
  listing), prompts (`summarize_document`, `audit_corpus`), and authorization-
  filtered argument completions.
- The flagship Postgres and pgvector connector: `sql_query` runs a single vetted
  read-only statement over asyncpg in a read-only transaction under a
  server-side statement timeout, and `vector_search` runs a bounded pgvector
  similarity search with server-side tenant isolation derived from the caller.
- A single component contract (`ToolSpec`, `ResourceSpec`, `PromptSpec`) that
  rejects any tool, resource, or prompt registered without a scope and a
  rate-limit setting, and optional icon metadata for the 2025-11-25 spec.
- The importable facade gained `read_resource`, `get_prompt`, and `complete`,
  each routed through the same guarded dispatch as `call`.

### Changed

- Moved to MCP specification 2025-11-25 and FastMCP 3.4.6. As a pre-1.0 release,
  tool return shapes are now typed for structured output; the change is not
  backward compatible with 0.1.0 clients that parsed the previous shapes.

### Security

- The SQL read path authorizes a tableless query against a sentinel resource so
  it cannot skip the per-table check, derives the parse dialect from the DSN so
  no clause is silently dropped, sanitizes column names as well as values, and
  enforces read-only execution with a statement timeout at the database.
- `doc_search` and `doc_scan` apply the path prefix while walking the corpus and
  report truncation honestly, so a match behind the file cap is no longer
  dropped while the result claims to be complete.
- The text sanitizer removes the Unicode Tags block, the variation selectors,
  and the bidi isolates; the Markdown sanitizer defangs reference-style images
  and strips multiline HTML comments.
- The SSRF guard restricts targets to the web ports plus a configurable
  allowlist; `safe_fetch` and `read_file` now consult the authorizer rather than
  relying on scope alone; and the in-memory rate-limit store bounds its buckets.

### Not included

- The experimental async Tasks primitive from the 2025-11-25 spec is not part of
  this release: it requires FastMCP's `tasks` extra and a durable task queue,
  and will follow as its own change.

## [0.1.0]

### Added

- Three hardened built-in tools: `safe_fetch` (SSRF-guarded fetch with address
  pinning), `calculate` (allowlist plus an AST evaluator, no `eval`), and
  `read_file` (path-jailed reader).
- A document suite over a jailed JSON/Markdown/text corpus: `doc_search`,
  `doc_read`, `doc_retrieve`, `doc_scan` (secrets/PII redaction), and
  `doc_write` (atomic, no-clobber, confirmation-gated).
- OAuth 2.1 resource server with mandatory audience validation, scope-by-verb,
  and a default-deny per-resource authorization policy.
- Content-hardening boundary (JSON, Markdown, and text sanitizers plus
  provenance wrapping) for everything returned to a model.
- Rate limiting (per-caller token buckets, Redis-backed), a per-tool kill
  switch, structured audit logging with source-side redaction, and tracing.
- Container image, docker-compose stack, and Render and Fly.io blueprints.
- Security, threat-model, and architecture documentation.

[Unreleased]: https://github.com/jagguvarma15/arrowhead/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jagguvarma15/arrowhead/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jagguvarma15/arrowhead/releases/tag/v0.1.0
