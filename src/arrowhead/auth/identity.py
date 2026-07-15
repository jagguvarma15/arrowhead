"""Caller identity derived from the validated access token.

Used to key rate limits and audit records. Identity comes only from the
token the resource server already verified, never from anything the
caller can freely assert such as a header or a tool argument.
"""

from fastmcp.server.dependencies import get_access_token

ANONYMOUS = "anonymous"


def caller_identity() -> str:
    """Stable identifier for the current caller, or "anonymous".

    stdio has no auth context and HTTP without auth has no token; both
    report as anonymous and share one rate-limit bucket per tool.
    """
    try:
        token = get_access_token()
    except Exception:
        return ANONYMOUS
    if token is None:
        return ANONYMOUS
    return token.subject or token.client_id or ANONYMOUS
