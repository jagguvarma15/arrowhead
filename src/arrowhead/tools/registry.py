"""Registers the components declared in the catalog with the server.

The catalog is the single source of each component's name or URI,
implementation, scope, and annotations, so this module does not restate any
of them: it walks the specs and wires each tool, resource, and prompt, then
attaches the argument-completion handler.

Scope checks are attached only when auth is enabled. Scopes are an
authorization concept: with no authentication there is no token to check them
against, so on stdio and on unauthenticated local HTTP the components are
registered without checks and remain callable.
"""

from fastmcp import FastMCP

from arrowhead.auth.scopes import checks_for_scope, scope_checks
from arrowhead.tools.catalog import PROMPT_SPECS, RESOURCE_SPECS, TOOL_SPECS


def register_components(mcp: FastMCP, *, enforce_scopes: bool = True) -> None:
    """Register every tool, resource, and prompt, and the completion handler."""
    register_tools(mcp, enforce_scopes=enforce_scopes)
    register_resources(mcp, enforce_scopes=enforce_scopes)
    register_prompts(mcp, enforce_scopes=enforce_scopes)
    register_completions(mcp)


def register_tools(mcp: FastMCP, *, enforce_scopes: bool = True) -> None:
    for spec in TOOL_SPECS:
        mcp.tool(
            spec.load(),
            annotations=dict(spec.annotations),
            icons=list(spec.icons) or None,
            auth=scope_checks(spec.name) if enforce_scopes else None,
        )


def register_resources(mcp: FastMCP, *, enforce_scopes: bool = True) -> None:
    for spec in RESOURCE_SPECS:
        mcp.resource(
            spec.uri,
            description=spec.description,
            mime_type=spec.mime_type,
            icons=list(spec.icons) or None,
            auth=checks_for_scope(spec.scope) if enforce_scopes else None,
        )(spec.load())


def register_prompts(mcp: FastMCP, *, enforce_scopes: bool = True) -> None:
    for spec in PROMPT_SPECS:
        mcp.prompt(
            spec.load(),
            name=spec.name,
            description=spec.description,
            icons=list(spec.icons) or None,
            auth=checks_for_scope(spec.scope) if enforce_scopes else None,
        )


def register_completions(mcp: FastMCP) -> None:
    """Attach the argument-completion handler to the low-level server."""
    from arrowhead.completions.handlers import complete_argument

    mcp._mcp_server.completion()(complete_argument)
