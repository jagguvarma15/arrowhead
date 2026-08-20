import pytest
from mcp.server import MCPServer

from arrowhead.auth.scopes import TOOL_SCOPES, has_scope, require_scope
from arrowhead.errors import ToolError
from arrowhead.runtime.guards import Guards, visible_tools
from arrowhead.tools.catalog import TOOL_SPECS
from arrowhead.tools.registry import register_tools


def registered_tools() -> set[str]:
    """The tools register_tools actually registers for the current settings:
    every family the active profile exposes, which excludes the exec family
    until it is enabled. Computed per call so it tracks the test's env."""
    from arrowhead.tools.registry import active_families

    families = active_families()
    return {spec.name for spec in TOOL_SPECS if spec.family in families}


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
    } == registered_tools()


def test_every_registered_tool_has_a_scope():
    assert registered_tools() <= set(TOOL_SCOPES)


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
