"""Human-in-the-loop confirmation for destructive actions.

A destructive document action (overwriting an existing document) requests
confirmation from the caller through MCP elicitation. The exchange happens
inline within the authenticated tool call, so its identity is already the
token's subject; no elicitation state is persisted or keyed on a session,
per the MCP security guidance.

The outcome is one of three, which the caller treats differently: an
explicit decline blocks the action, an acceptance permits it, and an
unavailable channel (no context, or a client that cannot elicit) falls
back to the caller's explicit overwrite flag as the opt-in.
"""

from fastmcp.server.elicitation import AcceptedElicitation

CONFIRM_ACCEPTED = "accepted"
CONFIRM_DECLINED = "declined"
CONFIRM_UNAVAILABLE = "unavailable"


async def request_confirmation(context, message: str) -> str:
    """Ask the caller to confirm a destructive action.

    Returns CONFIRM_ACCEPTED on explicit acceptance, CONFIRM_DECLINED on a
    decline or cancel, and CONFIRM_UNAVAILABLE when there is no context or
    the client cannot elicit.
    """
    if context is None:
        return CONFIRM_UNAVAILABLE
    try:
        result = await context.elicit(message, response_type=None)
    except Exception:
        return CONFIRM_UNAVAILABLE
    if isinstance(result, AcceptedElicitation):
        return CONFIRM_ACCEPTED
    return CONFIRM_DECLINED
