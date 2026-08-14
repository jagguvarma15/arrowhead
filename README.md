<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/arrowhead-dark.svg">
    <img alt="Arrowhead" src="assets/arrowhead.svg" width="88" height="88">
  </picture>
</p>

<h1 align="center">Arrowhead</h1>

<p align="center"><strong>The fast, secure data plane for AI agents.</strong></p>

<p align="center">
  <a href="https://modelcontextprotocol.io"><img alt="Speaks the Model Context Protocol" src="https://img.shields.io/badge/speaks-Model_Context_Protocol-C6693E?style=flat-square&labelColor=1D2024"></a>
  <a href="https://github.com/modelcontextprotocol/python-sdk"><img alt="Built on the official MCP Python SDK v2" src="https://img.shields.io/badge/SDK-mcp_v2-33717E?style=flat-square&labelColor=1D2024"></a>
  <img alt="Serves protocol revision 2026-07-28" src="https://img.shields.io/badge/protocol-2026--07--28-33717E?style=flat-square&labelColor=1D2024">
  <img alt="Reachable over stdio and HTTP" src="https://img.shields.io/badge/interface-stdio_and_HTTP-33717E?style=flat-square&labelColor=1D2024">
  <a href="docs/SECURITY.md"><img alt="Authorization is default-deny" src="https://img.shields.io/badge/authorization-default--deny-2E7D57?style=flat-square&labelColor=1D2024"></a>
  <a href="LICENSE"><img alt="MIT licensed" src="https://img.shields.io/badge/license-MIT-1D2024?style=flat-square&labelColor=1D2024"></a>
</p>

<p align="center">
A hardened <a href="https://modelcontextprotocol.io">Model Context Protocol</a> server and an
importable Python library for exposing your infrastructure &mdash; a document corpus, SQL, a
pgvector store, a source tree, a model backend &mdash; to AI agents, with no unguarded path.
</p>

---

The safe path is the default path. OAuth 2.1 authorization, per-resource authorization, SSRF
and path-traversal defenses, content sanitization and provenance, per-caller rate limiting,
structured audit logging, and token-efficient schemas apply to every tool, resource, and prompt.
Security lives inside each component rather than in a proxy in front of it, so the guarantees
hold whether a call arrives over HTTP or the server is imported and called directly from Python.

It runs on the official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
(the `mcp` package, version 2): one streamable-HTTP endpoint serves the sessionless 2026-07-28
protocol natively while still serving handshake-era clients that send the `initialize` lifecycle.

## Quickstart

```bash
uv sync                               # install
uv run python -m arrowhead.server     # serve over stdio, ready for MCP Inspector
```

Auth is off in stdio mode, so every tool is immediately callable. Try `calculate` with
`2 * (3 + 4)`, or `read_file` with `welcome.txt` (a sample lives in `sandbox/`). To point the
Inspector at it:

```bash
npx @modelcontextprotocol/inspector uv run python -m arrowhead.server
```

For a streamable-HTTP endpoint on `http://localhost:8000/mcp` with a shared rate-limit store:

```bash
docker compose -f deploy/docker-compose.yml up
```

## Use it as a library

`Arrowhead.call` and the HTTP transport route through the same dispatch, so an imported call runs
the identical authorization, sanitization, and middleware path as a call over the wire:

```python
from arrowhead.app import Arrowhead

app = Arrowhead()
with app.as_principal("service:etl", {"docs:read"}):
    result = await app.call("doc_read", {"path": "notes.md"})
    document = await app.read_resource("doc://notes.md")
```

A call with no principal is anonymous, and every scoped component is denied, so the guarded path
is the default whichever door a call comes through.

## What it exposes

A deployment sets `ARROWHEAD_PROFILE` (`core`, `docs`, `coding`, or `full`) so a connection
carries only the tool families it needs; a tool outside the active profile is never registered,
so it costs no context and a call to it is unknown.

| Family | Tools | What it does |
|---|---|---|
| `core` | `safe_fetch`, `calculate`, `read_file` | The general-purpose utilities |
| `docs` | `doc_*`, corpus resource and prompts | The jailed document corpus |
| `data` | `sql_query`, `vector_search`, `vector_query`, `hybrid_query`, `doc_index` | SQL reads and pgvector retrieval, including hybrid vector-plus-full-text fusion and diff-aware re-indexing |
| `repo` | `code_search`, `code_read`, `symbol_map`, `dependency_graph` | Read-only intelligence over a jailed source tree |
| `assist` | `code_explain`, `summarize_diff`, `rerank` | Model-backed helpers over a pluggable completion provider |
| `exec` | `run_snippet`, `run_tests` | Sandboxed execution behind a resource-bounded runner (opt in twice) |
| `context` | `pack_context`, `workingset_get`, `workingset_update` | A token-budgeted, secret-scanned, provenance-stamped context bundle and the working sets that feed it |

Three capabilities go beyond what comparable coding servers offer: the guarded **context packer**
secret-scans and provenance-stamps every snippet before it leaves the server; **hybrid, code-aware
retrieval** fuses vector similarity with Postgres full-text rank and re-embeds only changed chunks;
and a **tool-integrity digest** (`arrowhead://integrity`) lets a client pin the tool surface it
consented to and detect a later change. Alongside tools, Arrowhead exposes resources, resource
templates, prompts, argument completions, and handle-based asynchronous tasks &mdash; each on the
same guarded path.

The data and coding families are opt-in extras and refuse to run until configured:

```bash
uv sync --extra sql --extra postgres    # SQL and pgvector connectors
```

## Built for a hostile surface

A published assessment of MCP servers in the wild found the same flaws again and again: command
injection, server-side request forgery, path traversal, and a large share with no authentication
at all. Each built-in tool is a direct answer to one of those classes:

| Tool | Vulnerability class it closes | How |
|---|---|---|
| `safe_fetch` | Server-side request forgery | Resolves the host, refuses private, loopback, link-local, and cloud-metadata addresses, restricts the port, and pins the vetted IP so DNS rebinding cannot swap it |
| `calculate` | Command / code injection | A strict character allowlist, then an AST interpreter that evaluates only numbers and basic operators. No `eval`, no `exec`, no shell |
| `read_file` | Path traversal | Relative paths only, no parent components, and the fully resolved path (after symlinks) must stay inside one configured jail directory |

Content returned to a caller is treated as untrusted data: sanitized per format and wrapped in
provenance so a client presents it as data rather than instructions. Scopes are split by verb and
a scope is necessary but not sufficient &mdash; every call also passes a server-side per-resource
check, default-deny, whose small JSON grant list can be replaced by an external engine (OPA, Cedar).

## Configuration

Every setting is an environment variable with the `ARROWHEAD_` prefix; see
[`.env.example`](.env.example) for the full list with safe placeholders. Enable auth and set the
OAuth variables before exposing the server anywhere public.

## Documentation

- [`docs/SECURITY.md`](docs/SECURITY.md) &mdash; each mitigation mapped to the vulnerability class it closes
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) &mdash; attack surface per tool and what is out of scope
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) &mdash; request flow from auth through rate limiting to the tool and the audit log
- [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) &mdash; connecting Claude Code, Cursor, and other hosts
- [`docs/DEPLOY.md`](docs/DEPLOY.md) &mdash; runbook for a live reference deployment
- [`examples/`](examples/) &mdash; a runnable RAG walkthrough and a coding-agent walkthrough
- [`CHANGELOG.md`](CHANGELOG.md) &mdash; notable changes

## License

[MIT](LICENSE)
