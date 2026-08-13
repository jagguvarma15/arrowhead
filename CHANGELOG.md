# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

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
- Application-level alignment with the 2026-07-28 specification: a valid
  `private` cache scope with `ttlMs` on every cacheable list and read result, a
  deterministic list order, error-detail masking, and a conformance test that
  asserts the negotiated protocol version. The wire-level 2026-07-28 changes are
  deferred until a stable SDK speaks them; see `docs/SECURITY.md`.
- A startup refusal to serve HTTP with authentication disabled unless
  `ARROWHEAD_ALLOW_INSECURE_HTTP` is set, and startup validation of the SQL
  dialect and the egress port allowlist.

### Changed

- Authorization grants are now kind-aware: outbound fetch is authorized under its
  own `fetch` action, so a policy can deny a caller outbound fetch without
  denying its document reads, and prefix matching is component-bounded so a grant
  on `notes` no longer reaches `notes-private`. A tableless SQL query is denied
  by default.
- The SQL guard bounds parse nesting, rejects row-locking clauses and a denylist
  of side-effecting, file, network, and administrative functions, and its result
  caps are measured in bytes with a per-cell bound. `serverInfo.version` and
  `/health` now report the real package version.

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
