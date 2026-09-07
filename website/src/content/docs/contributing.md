---
title: Contributing
description: Development setup, the test layers, and the conventions the repo holds itself to.
---

## Development setup

```bash
git clone https://github.com/jagguvarma15/arrowhead.git
cd arrowhead
uv sync --all-extras --dev
uv run pytest tests/ -v
uv run ruff check src/ tests/
```

Python 3.12 or newer. The suite treats every warning as an error, so a new
deprecation fails loudly instead of landing silently. Lint runs the `E`, `F`,
`I`, `UP`, `B`, and `S` rule sets - the `S` set is flake8-bandit, so security
lint is part of ordinary lint.

## The test layers

| Directory | What it covers |
|---|---|
| `tests/unit/` | Each tool and each security module in isolation |
| `tests/security/` | An adversarial corpus of SSRF, injection, and traversal payloads run against every input that could reach a guard |
| `tests/conformance/` | The protocol surface over the HTTP transport, and the golden catalog |
| `tests/integration/` | Postgres and pgvector paths, run when `ARROWHEAD_POSTGRES_TEST_URL` names a live database |

For the integration leg locally:

```bash
docker run -d --name arrowhead-pg -p 5432:5432 -e POSTGRES_PASSWORD=postgres pgvector/pgvector:pg16
ARROWHEAD_POSTGRES_TEST_URL=postgresql+asyncpg://postgres:postgres@localhost/postgres uv run pytest tests/integration/
```

CI provides the same service container, so the integration tests always run on
a pull request.

## The golden catalog and frozen docstrings

`tests/fixtures/tool_list_golden.json` pins the client-visible tool surface:
name, description, input schema, annotations, output-schema presence, and scope
for every tool under the default environment. A tool's docstring is sent to
clients verbatim as its wire description, so changing one is a surface change:
the conformance test fails, the `arrowhead://integrity` digest shifts, and the
fixture must be deliberately regenerated from `arrowhead list-tools --json`
projected to the fixture's shape. Keep docstrings terse, include an `Example:`
line, and mind the token budget - a conformance test fails the build if the
tool list's average cost per tool grows past its ceiling.

## Adding a tool

Declare a `ToolSpec` in `src/arrowhead/tools/catalog.py`. The spec will not
construct without a scope, a rate-limit setting, and a family, and registration
wraps every tool in the same guard chain (span, audit, kill switch, rate limit,
scope check, masked errors) - there is no unguarded registration path. A new
tool ships with unit tests, adversarial tests for any new input surface, and
the regenerated golden fixture.

## Commit convention

Every file changes in its own commit, and the suite stays green at every
commit; the rare deliberate exception (a catalog change whose fixture lands in
the adjacent commit) is disclosed in the pull-request body. Commit subjects are
imperative and plain.

## What CI runs

Every pull request runs four workflows: `test` (lock check, lint, the full
suite against a pgvector service container, a wheel build smoke), `image` (the
production Docker build with a blocking Trivy scan), `security` (pip-audit,
Trivy filesystem and config scans, gitleaks, and an SBOM), and the docs build
(the site builds with a link validator that fails on any broken internal link,
and the reference generator fails on drift between `.env.example` and the
Settings model). A release tag additionally publishes the container image to
GitHub Container Registry.

## The documentation site

The site you are reading builds from three sources: the repository documents
under `docs/`, the site pages under `website/src/content/docs/`, and two
generated reference pages that never exist on disk. To work on it locally:

```bash
uv run python scripts/gen_reference.py
cd website
npm ci
npm run dev
```
