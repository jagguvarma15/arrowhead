"""FastMCP application entrypoint.

Runs over stdio by default for local development and Inspector testing.
Set ARROWHEAD_TRANSPORT=http (with auth enabled) for deployment.
"""

from fastmcp import FastMCP

from arrowhead.auth.oauth import build_auth_provider
from arrowhead.cache import attach_list_cache_hints
from arrowhead.config import get_settings
from arrowhead.observability.audit_log import AuditLogMiddleware
from arrowhead.observability.tracing import TracingMiddleware
from arrowhead.security.kill_switch import KillSwitchMiddleware
from arrowhead.security.rate_limit import build_rate_limit_middleware
from arrowhead.tools.registry import register_tools


def create_server() -> FastMCP:
    settings = get_settings()

    # Outermost first: the span wraps everything, the audit line records
    # every outcome including kill-switch and rate-limit refusals, and
    # only calls that survive both reach a tool.
    middleware = [
        TracingMiddleware(),
        AuditLogMiddleware(),
        KillSwitchMiddleware(settings.disabled_tool_set()),
    ]
    rate_limiter = build_rate_limit_middleware(settings)
    if rate_limiter is not None:
        middleware.append(rate_limiter)

    mcp = FastMCP(
        name="arrowhead",
        version="0.1.0",
        instructions=(
            "Hardened general-purpose MCP server. Tools are read-only and "
            "validate all inputs before acting on them."
        ),
        auth=build_auth_provider(settings),
        middleware=middleware,
    )
    register_tools(mcp)
    attach_list_cache_hints(mcp, settings.tool_list_ttl_ms)
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
