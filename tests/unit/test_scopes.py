from fastmcp import FastMCP
from fastmcp.server.auth import AuthContext
from fastmcp.server.context import _current_transport

from arrowhead.auth.scopes import TOOL_SCOPES, scope_checks, supported_scopes
from arrowhead.tools.catalog import PROMPT_SPECS, RESOURCE_SPECS, TOOL_SPECS
from arrowhead.tools.registry import register_tools

# Derived from the catalog so this stays correct as tools are added: every tool
# the catalog declares is registered and must be visible on stdio.
REGISTERED_TOOLS = {spec.name for spec in TOOL_SPECS}


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
    assert {tool.name for tool in tools} == REGISTERED_TOOLS


def test_every_registered_tool_has_a_scope():
    assert REGISTERED_TOOLS <= set(TOOL_SCOPES)


def test_scope_checks_deny_without_token():
    class FakeComponent:
        tags: set = set()

    for name in TOOL_SCOPES:
        (check,) = scope_checks(name)
        assert check(AuthContext(token=None, component=FakeComponent())) is False


def test_document_verbs_have_distinct_scopes():
    assert TOOL_SCOPES["doc_search"] == "docs:search"
    assert TOOL_SCOPES["doc_read"] == "docs:read"
    assert TOOL_SCOPES["doc_retrieve"] == "docs:read"
    assert TOOL_SCOPES["doc_scan"] == "docs:scan"
    assert TOOL_SCOPES["doc_write"] == "docs:write"


def test_supported_scopes_are_the_catalog_scopes_deduplicated_and_sorted():
    scopes = supported_scopes()
    assert scopes == sorted(set(scopes))
    expected = {spec.scope for spec in TOOL_SPECS}
    expected |= {spec.scope for spec in RESOURCE_SPECS}
    expected |= {spec.scope for spec in PROMPT_SPECS}
    assert set(scopes) == expected
