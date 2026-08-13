import pytest
from mcp.server import MCPServer

from arrowhead.auth.scopes import (
    TOOL_SCOPES,
    has_scope,
    require_scope,
    supported_scopes,
)
from arrowhead.errors import ToolError
from arrowhead.runtime.guards import Guards, visible_tools
from arrowhead.tools.catalog import PROMPT_SPECS, RESOURCE_SPECS, TOOL_SPECS
from arrowhead.tools.registry import register_tools

# Derived from the catalog so this stays correct as tools are added: every tool
# the catalog declares is registered and must be visible without auth.
REGISTERED_TOOLS = {spec.name for spec in TOOL_SPECS}


def _guards(enforce: bool) -> Guards:
    return Guards(
        enforce_scopes=enforce, rate_limiter=None, disabled=frozenset()
    )


async def test_tools_hidden_from_anonymous_only_when_auth_is_enforced():
    mcp = MCPServer("scope-check")
    register_tools(mcp, guards=_guards(True))
    tools = await mcp.list_tools()

    # With auth enforced and no token, every scoped tool is invisible.
    assert visible_tools(tools, _guards(True)) == []

    # Without auth there is no token to check scopes against; everything
    # registers and lists, and the per-resource policy remains the guard.
    assert {
        tool.name for tool in visible_tools(tools, _guards(False))
    } == REGISTERED_TOOLS


def test_every_registered_tool_has_a_scope():
    assert REGISTERED_TOOLS <= set(TOOL_SCOPES)


def test_scope_checks_deny_without_token():
    for name, scope in TOOL_SCOPES.items():
        assert has_scope(scope) is False
        with pytest.raises(ToolError, match=f"Unknown tool: {name}"):
            require_scope(scope, name, "tool")


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
