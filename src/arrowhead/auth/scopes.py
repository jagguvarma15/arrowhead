"""Tool-to-scope mapping.

Every tool names the OAuth scope a caller must hold. Scopes are split by
verb: the document suite separates search, read, scan, and write so a
caller can be granted the narrowest capability it needs. The checks are
enforced on HTTP transports; stdio runs are local development against a
process the operator already owns, and FastMCP skips component auth there.
A tool the caller lacks scopes for is invisible to that caller: it is
filtered from tools/list and tools/call reports it as unknown.

Holding a scope is necessary but not sufficient for the document tools: a
scoped call still passes a per-resource authorization check (see
arrowhead.authz), because the scope grants a capability, not access to a
specific document.
"""

from fastmcp.server.auth import AuthCheck, require_scopes

from arrowhead.tools.catalog import TOOL_SPECS

# Derived from the catalog so a tool's scope is declared in exactly one place.
TOOL_SCOPES: dict[str, str] = {spec.name: spec.scope for spec in TOOL_SPECS}


def scope_checks(tool_name: str) -> list[AuthCheck]:
    """Auth checks to attach to a tool at registration time."""
    return [require_scopes(TOOL_SCOPES[tool_name])]


def supported_scopes() -> list[str]:
    """All scopes this server understands, for resource metadata."""
    return sorted(set(TOOL_SCOPES.values()))
