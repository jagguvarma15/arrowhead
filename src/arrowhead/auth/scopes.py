"""Tool-to-scope mapping and the in-house scope check.

Every tool names the OAuth scope a caller must hold. Scopes are split by
verb: the document suite separates search, read, scan, and write so a
caller can be granted the narrowest capability it needs. The checks are
enforced only when auth is enabled: with no authentication there is no
token to check them against, so stdio and unauthenticated local HTTP run
without them. A tool the caller lacks scopes for is invisible to that
caller: it is filtered from tools/list and calling it reports it as
unknown, so the scope taxonomy never leaks to an under-scoped caller.

Holding a scope is necessary but not sufficient for the document tools: a
scoped call still passes a per-resource authorization check (see
arrowhead.authz), because the scope grants a capability, not access to a
specific document.
"""

from mcp.server.auth.middleware.auth_context import get_access_token

from arrowhead.errors import ToolError
from arrowhead.tools.catalog import TOOL_SPECS

# Derived from the catalog so a tool's scope is declared in exactly one place.
TOOL_SCOPES: dict[str, str] = {spec.name: spec.scope for spec in TOOL_SPECS}


def caller_scopes() -> frozenset[str]:
    """The scopes carried by the current caller's verified token."""
    try:
        token = get_access_token()
    except Exception:
        return frozenset()
    if token is None:
        return frozenset()
    return frozenset(token.scopes or ())


def has_scope(scope: str) -> bool:
    """Whether the current caller's token carries the scope."""
    return scope in caller_scopes()


def require_scope(scope: str, component: str, kind: str = "tool") -> None:
    """Refuse a call whose caller lacks the component's scope.

    The refusal reports the component as unknown, matching its invisibility
    in the listing, so probing calls cannot map the scope taxonomy.
    """
    if not has_scope(scope):
        raise ToolError(f"Unknown {kind}: {component}")
