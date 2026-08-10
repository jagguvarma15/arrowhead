# Arrowhead

**The fast, secure data plane for AI agents.** Arrowhead is a hardened
[Model Context Protocol](https://modelcontextprotocol.io) server and an
installable foundation for exposing infrastructure (a document corpus, SQL, a
pgvector store) to AI agents safely. The safe path is the default path: OAuth
2.1 authorization, per-resource authorization, SSRF and path-traversal defenses,
content sanitization and provenance, per-caller rate limiting, structured audit
logging, and token-efficient schemas apply to every component, and there is no
unguarded path. It targets MCP specification 2025-11-25 and exposes the full
modern surface: tools with structured output, resources and resource templates,
prompts, and argument completions.

Security lives inside each tool, resource, and prompt rather than in a proxy in
front of them, so the guarantees hold whether a call arrives over HTTP or the
server is imported and called directly from Python.

## Why it looks the way it does

A published assessment of MCP servers in the wild found the same handful of
flaws again and again: command injection, server-side request forgery, path
traversal, and a large share with no authentication at all. Each built-in tool
is a direct, working answer to one of those classes:

| Tool | Vulnerability class it closes | How |
|---|---|---|
| `safe_fetch` | Server-side request forgery | Resolves the target host, refuses private, loopback, link-local, and cloud-metadata addresses, restricts the port, and pins the vetted IP so DNS rebinding cannot swap it |
| `calculate` | Command / code injection | A strict character allowlist, then an AST interpreter that evaluates only numbers and basic operators. No `eval`, no `exec`, no shell |
| `read_file` | Path traversal | Relative paths only, no parent components, and the fully resolved path (after symlinks) must stay inside one configured jail directory |

Each carries accurate MCP behavior annotations and a published output schema.
Auth, per-resource authorization, rate limiting, audit logging, and tracing wrap
every call regardless of which tool, resource, or prompt it targets.

## Quickstart

### Local, over stdio (for MCP Inspector)

```bash
uv sync
uv run python -m arrowhead.server
```

In another terminal, point the Inspector at it:

```bash
npx @modelcontextprotocol/inspector uv run python -m arrowhead.server
```

Auth is off in this mode, so every tool is immediately callable. Try
`calculate` with `2 * (3 + 4)`, or `read_file` with `welcome.txt` (a sample
file lives in `sandbox/`).

### Local, over HTTP with Docker

```bash
docker compose -f deploy/docker-compose.yml up
```

This brings up the streamable HTTP endpoint on `http://localhost:8000/mcp`
alongside a Redis instance for shared rate-limit state. Any MCP client that
speaks streamable HTTP can connect.

## Tools

Every argument is validated before it reaches an evaluator, the filesystem, or
the network, and every failure is a controlled error rather than a crash.

- **`safe_fetch(url)`** — fetches a public `http`/`https` URL and returns its
  status, content type, and body. Redirects are followed manually with the
  SSRF guard re-applied on every hop; response size is capped. The caller's
  MCP credentials are never attached to the outbound request.
- **`calculate(expression)`** — evaluates arithmetic with `+ - * / ( )` and
  decimals. `2 * (3 + 4)` returns `14`. `1+1; import os` is refused.
- **`read_file(path)`** — reads a text file by relative path from the
  configured jail root. `../../etc/passwd` is refused; a symlink inside the
  jail that points outside it is refused.

### Document suite

A second group of tools operates over a jailed corpus of JSON, Markdown, and
plain-text documents. Content returned to the caller is treated as untrusted
data: it is sanitized per format (JSON parsed under strict bounds, Markdown
stripped of HTML and image-exfiltration vectors, text stripped of ANSI and
invisible characters) and wrapped in provenance so a client can present it as
data rather than instructions.

| Tool | Scope | Purpose |
|---|---|---|
| `doc_search(query, path_prefix, use_regex)` | `docs:search` | Bounded, read-filtered search; literal by default, regex opt-in behind a ReDoS-resistant engine |
| `doc_read(path)` | `docs:read` | Read one corpus document, format-aware and sanitized |
| `doc_retrieve(url)` | `docs:read` | Fetch an external document, SSRF-guarded and sanitized |
| `doc_scan(path_prefix)` | `docs:scan` | Detect secrets and PII, reporting redacted placeholders, never raw values |
| `doc_write(path, content, overwrite)` | `docs:write` | Create or (with confirmation) overwrite a document via an atomic, no-clobber write |

### Authorization

Scopes are split by verb, and a scope is necessary but not sufficient: every
document call also passes a server-side per-resource check. The default policy
lets any authenticated caller search, read, and scan the corpus, but write only
within its own `<subject>/` namespace, so cross-subject writes are denied. The
policy is a small JSON grant list (`ARROWHEAD_AUTHZ_POLICY`) whose interface is
designed so an external engine (OPA, Cedar) can replace it later. Overwriting an
existing document is destructive and requests human confirmation via MCP
elicitation.

## Data connectors

The flagship connector exposes a Postgres database, including a
[pgvector](https://github.com/pgvector/pgvector) store, behind the same guards.
Both are opt-in extras (`pip install 'arrowhead[sql,postgres]'`) and both refuse
to run until a DSN is configured.

| Tool | Scope | Purpose |
|---|---|---|
| `sql_query(query, params)` | `sql:read` | Runs a single vetted read-only statement. The query is parsed in the database's own dialect, every referenced table (or a sentinel for a tableless query) is authorized, and it runs in a read-only transaction under a server-side statement timeout. Bind values with named parameters |
| `vector_search(collection, embedding, k)` | `vector:search` | A bounded pgvector nearest-neighbour search over an allow-listed collection. The tenant filter is the authenticated caller, never an argument, so one tenant cannot read another's rows |

A read-only database role is the recommended credential; the read-only
transaction and statement timeout are defense in depth behind the parser.

## Resources, prompts, and completions

Beyond tools, Arrowhead exposes the other MCP primitives, each running the same
authorization, sanitization, rate limiting, audit, and kill-switch path:

- **Resources**: the `doc://{path}` template reads one corpus document,
  sanitized for its format, and `docs://index` lists the documents the caller
  is authorized to read.
- **Prompts**: `summarize_document` and `audit_corpus` are reusable
  instructions that reference a resource or a tool rather than inlining
  untrusted content.
- **Completions**: argument completion suggests corpus paths as a caller types,
  filtered by the caller's authorization so it never reveals a path they could
  not read.

## Use it as a library

The server is also an importable foundation. `Arrowhead.call` and the HTTP
transport route through the same dispatch, so an imported call runs the
identical authorization, sanitization, and middleware path as a call over the
wire:

```python
from arrowhead.app import Arrowhead

app = Arrowhead()
with app.as_principal("service:etl", {"docs:read"}):
    result = await app.call("doc_read", {"path": "notes.md"})
    document = await app.read_resource("doc://notes.md")
```

A call with no principal is anonymous, and every scoped component is denied, so
the guarded path is the default whichever door a call comes through.

## Configuration

Every setting is an environment variable with the `ARROWHEAD_` prefix; see
[`.env.example`](.env.example) for the full list with safe placeholders. The
essentials:

| Variable | Purpose | Default |
|---|---|---|
| `ARROWHEAD_TRANSPORT` | `stdio` or `http` | `stdio` |
| `ARROWHEAD_AUTH_ENABLED` | Turn on OAuth 2.1 verification | `false` |
| `ARROWHEAD_OAUTH_ISSUER` / `_AUDIENCE` / `_JWKS_URI` | Authorization server details | - |
| `ARROWHEAD_JAIL_ROOT` | Directory `read_file` may read from | `sandbox` |
| `ARROWHEAD_DOCS_ROOT` | Corpus directory the `doc_*` tools operate on | `documents` |
| `ARROWHEAD_AUTHZ_POLICY` | Per-resource authorization grants (JSON) | safe default |
| `ARROWHEAD_SQL_DSN` | SQLAlchemy async URL for the SQL and pgvector connectors | - |
| `ARROWHEAD_PGVECTOR_COLLECTIONS` | Allow-listed pgvector collections to search | - |
| `ARROWHEAD_EGRESS_ALLOWED_HOSTS` / `_PORTS` | Outbound host and extra-port allowlists | - |
| `ARROWHEAD_REDIS_URL` | Shared rate-limit store across replicas | - |
| `ARROWHEAD_DISABLED_TOOLS` | Kill switch: comma-separated component names | - |

## Testing

```bash
uv run pytest tests/ -v
```

The suite covers unit tests per tool and per security module, protocol
conformance over the HTTP transport, and an adversarial corpus of SSRF,
injection, and traversal payloads. Lint and tests run in CI on every pull
request.

## Documentation

- [`docs/SECURITY.md`](docs/SECURITY.md) — each mitigation mapped to the
  vulnerability class it closes
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — attack surface per tool and
  what is out of scope for this version
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — request flow from auth
  through rate limiting to the tool and the audit log
- [`docs/DEPLOY.md`](docs/DEPLOY.md) — runbook for a live reference deployment
- [`CHANGELOG.md`](CHANGELOG.md) — notable changes

## Deployment

`deploy/` holds a multi-stage, non-root [`Dockerfile`](deploy/Dockerfile), a
local [`docker-compose.yml`](deploy/docker-compose.yml), and blueprints for
[Render](deploy/render.yaml) and [Fly.io](deploy/fly.toml). FastMCP does not
terminate TLS itself; the hosting platform or a reverse proxy in front of the
process must. Set the OAuth variables and enable auth before exposing the
server anywhere public.

[`docs/DEPLOY.md`](docs/DEPLOY.md) is the step-by-step runbook for a live
reference instance on Render with WorkOS AuthKit, including verification,
rollback, and corpus backup. Before going public, sanity-check concurrency and
rate limiting against a local stack:

```bash
docker compose -f deploy/docker-compose.yml up --build -d
uv run python scripts/loadtest.py http://localhost:8000 200
```

## License

[MIT](LICENSE)
