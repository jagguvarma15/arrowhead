"""Cache hints for cacheable MCP list and read results.

A list of tools, resources, prompts, or resource templates, and the content of
a single resource, change only on deploy or on a write, so clients are told
they may cache them: the result _meta carries ttlMs and cacheScope. The scope
is "private" rather than "public" because visibility is per caller. Scope
checks, the per-resource authorization policy, and the kill switch can hide a
tool, resource, or document from one caller that another sees, so a shared
intermediary must not serve one caller's result to another. Between the hint
and the schemas staying lean, repeated polling costs a client almost nothing.

The value "private" is one of the two cache scopes the 2026-07-28 spec defines
for a cacheable result; the earlier "session" scope is meaningless once the
protocol has no sessions. On the stable SDK these keys ride in _meta; a
2026-07-28 SDK surfaces them as CacheableResult fields.
"""

from mcp.types import (
    ListPromptsRequest,
    ListResourcesRequest,
    ListResourceTemplatesRequest,
    ListToolsRequest,
    ReadResourceRequest,
)

CACHE_SCOPE_PRIVATE = "private"

# The list requests the spec marks cacheable. resources/read is stamped
# separately because its freshness follows a write, not a deploy.
_LIST_REQUESTS = (
    ListToolsRequest,
    ListResourcesRequest,
    ListResourceTemplatesRequest,
    ListPromptsRequest,
)


def _wrap(mcp, request_type, ttl_ms: int, cache_scope: str) -> None:
    """Wrap one low-level request handler to stamp cache hints on its result.

    FastMCP middleware sees the handler's return value, not the result
    envelope, so the _meta has to be added on the underlying request handler.
    A handler that is not registered (for example when no resources exist) is
    left alone.
    """
    handlers = mcp._mcp_server.request_handlers
    handler = handlers.get(request_type)
    if handler is None:
        return

    async def with_cache_hints(request):
        result = await handler(request)
        inner = result.root
        meta = dict(inner.meta or {})
        meta.setdefault("ttlMs", ttl_ms)
        meta.setdefault("cacheScope", cache_scope)
        inner.meta = meta
        return result

    handlers[request_type] = with_cache_hints


def attach_list_cache_hints(
    mcp,
    list_ttl_ms: int,
    read_ttl_ms: int,
    cache_scope: str = CACHE_SCOPE_PRIVATE,
) -> None:
    """Stamp ttlMs and cacheScope on every cacheable list and read result."""
    for request_type in _LIST_REQUESTS:
        _wrap(mcp, request_type, list_ttl_ms, cache_scope)
    _wrap(mcp, ReadResourceRequest, read_ttl_ms, cache_scope)
