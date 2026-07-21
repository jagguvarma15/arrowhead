"""Registers the tools declared in the catalog with the server.

The catalog is the single source of each tool's name, implementation, scope,
and annotations, so this module does not restate any of them: it walks the
specs and wires each one.

Scope checks are attached only when auth is enabled. Scopes are an
authorization concept: with no authentication there is no token to check them
against, so on stdio and on unauthenticated local HTTP the tools are registered
without checks and remain callable.
"""

from fastmcp import FastMCP

from arrowhead.auth.scopes import scope_checks
from arrowhead.tools.catalog import TOOL_SPECS


def register_tools(mcp: FastMCP, *, enforce_scopes: bool = True) -> None:
    for spec in TOOL_SPECS:
        mcp.tool(
            spec.load(),
            annotations=dict(spec.annotations),
            auth=scope_checks(spec.name) if enforce_scopes else None,
        )
