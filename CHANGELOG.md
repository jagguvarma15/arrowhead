# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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

[Unreleased]: https://github.com/jagguvarma15/arrowhead/compare/main...HEAD
[0.1.0]: https://github.com/jagguvarma15/arrowhead/releases/tag/v0.1.0
