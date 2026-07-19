"""Human-in-the-loop confirmation for destructive actions.

A destructive document action (overwriting an existing document) requests
confirmation from the caller through MCP elicitation. The exchange happens
inline within the authenticated tool call, so its identity is already the
token's subject; no elicitation state is persisted or keyed on a session,
per the MCP security guidance. If the client cannot elicit, or the caller
declines or cancels, confirmation is not granted and the caller falls back
to passing an explicit overwrite flag.
"""

from fastmcp.server.elicitation import AcceptedElicitation


async def request_confirmation(context, message: str) -> bool:
    """Ask the caller to confirm a destructive action.

    Returns True only on an explicit acceptance. A missing context, a
    client that cannot elicit, a decline, and a cancel all return False.
    """
    if context is None:
        return False
    try:
        result = await context.elicit(message, response_type=None)
    except Exception:
        return False
    return isinstance(result, AcceptedElicitation)
