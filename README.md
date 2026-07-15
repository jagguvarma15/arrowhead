# Arrowhead

Arrowhead is a hardened, general-purpose [Model Context Protocol](https://modelcontextprotocol.io)
server. It exists to demonstrate best-practice MCP security in working code
rather than prose: OAuth 2.1 authorization, SSRF and path-traversal defenses,
sandboxed evaluation, per-caller rate limiting, structured audit logging, and
token-efficient tool schemas.

## Why it looks the way it does

A published assessment of MCP servers in the wild found the same handful of
flaws again and again: command injection, server-side request forgery, path
traversal, and a large share with no authentication at all. Arrowhead ships
three tools, and each one is a direct, working answer to one of those classes:

| Tool | Vulnerability class it closes | How |
|---|---|---|
| `safe_fetch` | Server-side request forgery | Resolves the target host, refuses private, loopback, link-local, and cloud-metadata addresses, and pins the vetted IP for the connection so DNS rebinding cannot swap it |
| `calculate` | Command / code injection | A strict character allowlist, then an AST interpreter that evaluates only numbers and basic operators. No `eval`, no `exec`, no shell |
| `read_file` | Path traversal | Relative paths only, no parent components, and the fully resolved path (after symlinks) must stay inside one configured jail directory |

All three are read-only and carry accurate MCP behavior annotations. Auth,
rate limiting, audit logging, and tracing wrap every call regardless of which
tool it targets.

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

Auth is off in this mode, so all three tools are immediately callable. Try
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

## Configuration

Every setting is an environment variable with the `ARROWHEAD_` prefix; see
[`.env.example`](.env.example) for the full list with safe placeholders. The
essentials:

| Variable | Purpose | Default |
|---|---|---|
| `ARROWHEAD_TRANSPORT` | `stdio` or `http` | `stdio` |
| `ARROWHEAD_AUTH_ENABLED` | Turn on OAuth 2.1 verification | `false` |
| `ARROWHEAD_OAUTH_ISSUER` / `_AUDIENCE` / `_JWKS_URI` | Authorization server details | — |
| `ARROWHEAD_JAIL_ROOT` | Directory `read_file` may read from | `sandbox` |
| `ARROWHEAD_REDIS_URL` | Shared rate-limit store across replicas | — |
| `ARROWHEAD_DISABLED_TOOLS` | Kill switch: comma-separated tool names | — |

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

## Deployment

`deploy/` holds a multi-stage, non-root [`Dockerfile`](deploy/Dockerfile), a
local [`docker-compose.yml`](deploy/docker-compose.yml), and blueprints for
[Render](deploy/render.yaml) and [Fly.io](deploy/fly.toml). FastMCP does not
terminate TLS itself; the hosting platform or a reverse proxy in front of the
process must. Set the OAuth variables and enable auth before exposing the
server anywhere public.

## License

[MIT](LICENSE)
