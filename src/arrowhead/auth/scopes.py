"""Tool-to-scope mapping.

Every tool names the OAuth scope a caller must hold. The checks are
enforced on HTTP transports; stdio runs are local development against a
process the operator already owns, and FastMCP skips component auth there.
A tool the caller lacks scopes for is invisible to that caller: it is
filtered from tools/list and tools/call reports it as unknown.
"""

from fastmcp.server.auth import AuthCheck, require_scopes

TOOL_SCOPES: dict[str, str] = {
    "safe_fetch": "tools:read",
    "calculate": "tools:read",
    "read_file": "tools:read",
}


def scope_checks(tool_name: str) -> list[AuthCheck]:
    """Auth checks to attach to a tool at registration time."""
    return [require_scopes(TOOL_SCOPES[tool_name])]


def supported_scopes() -> list[str]:
    """All scopes this server understands, for resource metadata."""
    return sorted(set(TOOL_SCOPES.values()))
