"""FastMCP application entrypoint.

Runs over stdio by default for local development and Inspector testing.
Set ARROWHEAD_TRANSPORT=http (with auth enabled) for deployment.
"""

from fastmcp import FastMCP

from arrowhead.auth.oauth import build_auth_provider
from arrowhead.config import get_settings
from arrowhead.tools.registry import register_tools


def create_server() -> FastMCP:
    settings = get_settings()
    mcp = FastMCP(
        name="arrowhead",
        version="0.1.0",
        instructions=(
            "Hardened general-purpose MCP server. Tools are read-only and "
            "validate all inputs before acting on them."
        ),
        auth=build_auth_provider(settings),
    )
    register_tools(mcp)
    return mcp


def main() -> None:
    settings = get_settings()
    mcp = create_server()
    if settings.transport == "http":
        mcp.run(
            transport="http",
            host=settings.host,
            port=settings.port,
            stateless_http=settings.stateless_http,
        )
    else:
        mcp.run()


if __name__ == "__main__":
    main()
