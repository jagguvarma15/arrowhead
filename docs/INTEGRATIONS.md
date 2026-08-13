# Connecting a client

Arrowhead speaks the Model Context Protocol over two transports: stdio for local
use and streamable HTTP for a deployed server. Local stdio runs with auth off, so
every tool is immediately callable; a deployed HTTP server verifies an OAuth 2.1
bearer token and enforces per-caller scopes. Pick the transport your client
supports and give it the command or URL below.

The examples run the server from a source checkout with `uv`. Replace
`/path/to/arrowhead` with your checkout, or swap `uv run python -m
arrowhead.server` for `arrowhead serve` once the package is installed on the
client's PATH.

## Claude Desktop

Add an entry to the Claude Desktop configuration file
(`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "arrowhead": {
      "command": "uv",
      "args": ["run", "python", "-m", "arrowhead.server"],
      "cwd": "/path/to/arrowhead"
    }
  }
}
```

Restart Claude Desktop; the Arrowhead tools appear in the tools menu.

## Claude Code

Register the server with the CLI:

```bash
claude mcp add arrowhead -- uv run python -m arrowhead.server
```

For a deployed HTTP server, add it by URL and supply the bearer token:

```bash
claude mcp add --transport http arrowhead https://arrowhead.example/mcp \
  --header "Authorization: Bearer $TOKEN"
```

## Cursor

Create `.cursor/mcp.json` in the project (or the global `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "arrowhead": {
      "command": "uv",
      "args": ["run", "python", "-m", "arrowhead.server"],
      "cwd": "/path/to/arrowhead"
    }
  }
}
```

## VS Code

Create `.vscode/mcp.json` in the workspace:

```json
{
  "servers": {
    "arrowhead": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "python", "-m", "arrowhead.server"],
      "cwd": "/path/to/arrowhead"
    }
  }
}
```

## Claude Agent SDK (Python)

The SDK connects to an MCP server defined in its options. The exact field names
track the SDK version, so check its docs; the shape is:

```python
from claude_agent_sdk import ClaudeAgentOptions, query

options = ClaudeAgentOptions(
    mcp_servers={
        "arrowhead": {
            "type": "stdio",
            "command": "uv",
            "args": ["run", "python", "-m", "arrowhead.server"],
        }
    },
    allowed_tools=[
        "mcp__arrowhead__vector_query",
        "mcp__arrowhead__doc_read",
    ],
)

async for message in query(prompt="Summarize the refund policy", options=options):
    print(message)
```

To reach a deployed server instead, point the entry at the HTTP URL and pass the
bearer token in a header rather than a stdio command.

## Generic MCP client (LangGraph, OpenAI Agents, and others)

Any client that speaks streamable HTTP connects to the `/mcp` endpoint of a
deployed server and authenticates with a bearer token:

```
POST https://arrowhead.example/mcp
Authorization: Bearer <token>
```

A client with no token receives 401 and a pointer to
`/.well-known/oauth-protected-resource/mcp` (RFC 9728), which names the
authorization server to complete an OAuth 2.1 flow against. Arrowhead issues no
tokens itself; it only verifies them. The caller sees only the tools whose scope
its token holds.

## A note on scopes

Over HTTP the token's scopes decide which tools are visible. The retrieval tools
need `vector:search` (for `vector_query`) and `vector:write` (for `doc_index`),
and `doc_index` additionally requires the `ingest` action to be granted in the
per-resource policy, which the default policy denies. See the README for the
full scope list and `docs/SECURITY.md` for the authorization model.
