<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/arrowhead-dark.svg">
    <img alt="Arrowhead" src="assets/arrowhead.svg" width="96" height="96">
  </picture>
</p>

# Arrowhead

**The fast, secure data plane for AI agents.**

A hardened [Model Context Protocol](https://modelcontextprotocol.io) server and an
importable Python library for exposing your infrastructure — a document corpus, SQL, a
pgvector store, a source tree, a model backend — to AI agents, with no unguarded path.

The safe path is the default path. OAuth 2.1 authorization, per-resource authorization,
SSRF and path-traversal defenses, content sanitization and provenance, per-caller rate
limiting, structured audit logging, and token-efficient schemas apply to every tool,
resource, and prompt. Security lives inside each component rather than in a proxy in
front of it, so the guarantees hold whether a call arrives over HTTP or the server is
imported and called directly from Python.

## Quickstart

```bash
git clone https://github.com/jagguvarma15/arrowhead.git
cd arrowhead
uv sync
uv run python -m arrowhead.server
```

Auth is off in stdio mode, so every tool is immediately callable. Try `calculate` with
`2 * (3 + 4)`, or point the MCP Inspector at it:

```bash
npx @modelcontextprotocol/inspector uv run python -m arrowhead.server
```

Deployments run the container image published to GitHub Container Registry by each
release tag: `ghcr.io/jagguvarma15/arrowhead`.

## Find your way

<div class="grid cards" markdown>

-   **Getting started**

    ---

    Install from a checkout, pick a profile, make the first guarded call, and see
    where auth begins.

    [Start here](getting-started.md)

-   **Integrations**

    ---

    Connect Claude Desktop, Claude Code, Cursor, VS Code, the Agent SDK, or any MCP
    client.

    [Connect a client](INTEGRATIONS.md)

-   **Tool reference**

    ---

    Every tool with its wire description, scope, rate ceiling, and behavior hints,
    generated from the catalog.

    [Browse the catalog](reference/tools.md)

-   **Configuration**

    ---

    Every environment variable with its real default, section by section.

    [Look up a setting](reference/configuration.md)

-   **Security model**

    ---

    Each mitigation mapped to the vulnerability class it closes, from SSRF to prompt
    injection via tool results.

    [Read the model](SECURITY.md)

-   **Threat model**

    ---

    The attack surface tool by tool, cross-cutting concerns, and what is explicitly
    out of scope.

    [Weigh the risks](THREAT_MODEL.md)

-   **Architecture**

    ---

    The request flow from auth through rate limiting to the tool and the audit log,
    and the module layout.

    [See the shape](ARCHITECTURE.md)

-   **Deployment**

    ---

    The step-by-step runbook for a live instance: platform, auth, verification,
    rollback, and backup.

    [Ship an instance](DEPLOY.md)

</div>

Runnable walkthroughs live in [Examples](examples/docs-rag.md), development setup and
conventions in [Contributing](contributing.md), and common failure modes in the
[FAQ](faq.md).
