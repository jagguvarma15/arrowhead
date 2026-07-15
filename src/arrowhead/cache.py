"""Cache hints for tools/list responses.

The tool list only changes on deploy, so clients are told they may cache
it: the response _meta carries ttlMs and cacheScope. Scope is "session"
rather than "server" because visibility is per caller: scope checks and
the kill switch can hide tools from one session that another sees.
Between the hint and the schemas staying lean, repeated list polling
costs a client almost nothing.
"""

from mcp.types import ListToolsRequest


def attach_list_cache_hints(mcp, ttl_ms: int, cache_scope: str = "session") -> None:
    """Wrap the low-level tools/list handler to stamp cache hints.

    FastMCP middleware sees the tool sequence, not the result envelope,
    so the _meta has to be added on the underlying request handler.
    """
    handler = mcp._mcp_server.request_handlers[ListToolsRequest]

    async def with_cache_hints(request):
        result = await handler(request)
        inner = result.root
        meta = dict(inner.meta or {})
        meta.setdefault("ttlMs", ttl_ms)
        meta.setdefault("cacheScope", cache_scope)
        inner.meta = meta
        return result

    mcp._mcp_server.request_handlers[ListToolsRequest] = with_cache_hints
