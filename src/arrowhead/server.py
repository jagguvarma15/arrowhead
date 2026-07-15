"""FastMCP application entrypoint.

Runs over stdio by default for local development and Inspector testing.
"""

from fastmcp import FastMCP

mcp = FastMCP(
    name="arrowhead",
    version="0.1.0",
    instructions=(
        "Hardened general-purpose MCP server. Tools are read-only and "
        "validate all inputs before acting on them."
    ),
)


@mcp.tool(annotations={"readOnlyHint": True})
def ping() -> str:
    """Check that the server is alive. Example: ping() returns "pong"."""
    return "pong"


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
