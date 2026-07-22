"""An in-process caller runs under the same identity and scope checks as a
request, and no caller at all fails closed to anonymous with scoped tools
denied.
"""

import pytest
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_access_token

from arrowhead.auth.identity import caller_identity
from arrowhead.auth.principal import as_principal
from arrowhead.tools.registry import register_tools


def test_identity_is_anonymous_outside_a_principal_block():
    assert caller_identity() == "anonymous"


def test_identity_resolves_to_the_subject_inside_the_block():
    with as_principal("service:etl", {"docs:read"}):
        assert caller_identity() == "service:etl"
    assert caller_identity() == "anonymous"


def test_scopes_are_carried_on_the_token():
    with as_principal("service:etl", {"docs:read", "docs:scan"}):
        token = get_access_token()
        assert token is not None
        assert set(token.scopes) == {"docs:read", "docs:scan"}


def test_blank_scopes_are_dropped():
    with as_principal("service:etl", {"docs:read", ""}):
        assert set(get_access_token().scopes) == {"docs:read"}


def test_a_principal_needs_a_subject():
    with pytest.raises(ValueError):
        with as_principal(""):
            pass


async def test_scoped_tools_are_hidden_without_a_principal():
    mcp = FastMCP("principal-check")
    register_tools(mcp)
    assert await mcp.list_tools() == []


async def test_a_principal_sees_only_the_tools_its_scopes_allow():
    mcp = FastMCP("principal-check")
    register_tools(mcp)
    with as_principal("service:reader", {"docs:read"}):
        visible = {tool.name for tool in await mcp.list_tools()}
    assert visible == {"doc_read", "doc_retrieve"}


async def test_a_broader_principal_sees_more_tools():
    mcp = FastMCP("principal-check")
    register_tools(mcp)
    with as_principal("service:ops", {"tools:read", "docs:write"}):
        visible = {tool.name for tool in await mcp.list_tools()}
    assert visible == {"safe_fetch", "calculate", "read_file", "doc_write"}
