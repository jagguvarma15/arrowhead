"""FastMCP application entrypoint.

Runs over stdio by default for local development and Inspector testing.
"""

from fastmcp import FastMCP

from arrowhead.tools.registry import register_tools

mcp = FastMCP(
    name="arrowhead",
    version="0.1.0",
    instructions=(
        "Hardened general-purpose MCP server. Tools are read-only and "
        "validate all inputs before acting on them."
    ),
)

register_tools(mcp)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
