"""Run an in-process tool call as a verified caller.

Over HTTP the resource server verifies a bearer token and FastMCP exposes it
as the current access token, from which the caller identity, the rate-limit
key, and the per-resource authorization decision all derive. A direct
in-process call has no HTTP request and therefore no such token, so those
controls would treat the caller as anonymous and every scoped tool would be
denied.

as_principal sets the same access token a verified request would, for the
duration of a block, so an imported call runs under the same identity and scope
checks as a request. Leaving it unset is safe by design: the caller is
anonymous, scoped tools are denied, and there is no path that skips the checks.
"""

from collections.abc import Iterable, Iterator
from contextlib import contextmanager

from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken

# The token string is unused for an in-process principal: identity comes from
# the subject and the granted scopes, not from a bearer value to verify.
_IN_PROCESS_TOKEN = "in-process"  # noqa: S105


@contextmanager
def as_principal(subject: str, scopes: Iterable[str] = ()) -> Iterator[None]:
    """Run the enclosed block as the given caller.

    subject identifies the caller for rate limiting and per-resource
    authorization; scopes are the capabilities the caller holds, checked
    against each tool's required scope exactly as a request's token would be.

    Example:
        with as_principal("service:etl", {"docs:read"}):
            await app.call_tool("doc_read", {"path": "notes.md"})
    """
    if not subject:
        raise ValueError("a principal must have a subject")
    token = AccessToken(
        token=_IN_PROCESS_TOKEN,
        client_id=subject,
        subject=subject,
        scopes=sorted({scope for scope in scopes if scope}),
    )
    reset = auth_context_var.set(AuthenticatedUser(token))
    try:
        yield
    finally:
        auth_context_var.reset(reset)
