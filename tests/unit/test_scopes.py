from fastmcp import FastMCP
from fastmcp.server.auth import AuthContext
from fastmcp.server.context import _current_transport

from arrowhead.auth.scopes import TOOL_SCOPES, scope_checks, supported_scopes
from arrowhead.tools.registry import register_tools


async def test_tools_hidden_without_credentials_and_visible_on_stdio():
    mcp = FastMCP("scope-check")
    register_tools(mcp)

    # No transport context means no token: scoped tools must be invisible.
    assert await mcp.list_tools() == []

    # stdio is local development; FastMCP skips component auth there.
    reset = _current_transport.set("stdio")
    try:
        tools = await mcp.list_tools()
    finally:
        _current_transport.reset(reset)
    assert {tool.name for tool in tools} == set(TOOL_SCOPES)


def test_scope_checks_deny_without_token():
    class FakeComponent:
        tags: set = set()

    for name in TOOL_SCOPES:
        (check,) = scope_checks(name)
        assert check(AuthContext(token=None, component=FakeComponent())) is False


def test_supported_scopes_deduplicated():
    assert supported_scopes() == ["tools:read"]
