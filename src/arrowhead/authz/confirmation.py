"""Human-in-the-loop confirmation for destructive actions.

A destructive document action (overwriting an existing document) requests
confirmation from the caller through MCP elicitation, resolved by the
framework before the tool body runs: on current-protocol connections the
question rides an input-required round trip, on older ones it is asked
inline. The exchange happens within the authenticated tool call, so its
identity is already the token's subject; no elicitation state is
persisted or keyed on a session, per the MCP security guidance.

The resolver asks only when the write would genuinely proceed to an
overwrite: a call that the kill switch, the scope check, input
validation, or the per-resource policy is going to refuse is resolved
without a question, so a refused caller can never put a prompt in front
of a human. A client that never declared the elicitation capability is
resolved without a question too, and the caller's explicit overwrite flag
stands in as the opt-in, exactly as before.
"""

import anyio.to_thread
from mcp.server.elicitation import (
    AcceptedElicitation,
    CancelledElicitation,
    DeclinedElicitation,
    ElicitationResult,
)
from mcp.server.mcpserver import Context, Elicit
from pydantic import BaseModel

from arrowhead.auth.scopes import TOOL_SCOPES, has_scope
from arrowhead.authz.enforce import get_authorizer
from arrowhead.authz.policy import ACTION_WRITE, KIND_DOCUMENT, Resource
from arrowhead.config import get_settings
from arrowhead.security.input_validation import (
    ValidationError,
    validate_document_path,
)
from arrowhead.store.document_store import DocumentStoreError, build_document_store

__all__ = [
    "AcceptedElicitation",
    "CancelledElicitation",
    "ConfirmOverwrite",
    "DeclinedElicitation",
    "ElicitationResult",
    "confirm_overwrite",
    "confirmation_declined",
]


class ConfirmOverwrite(BaseModel):
    """The caller's answer to an overwrite confirmation."""

    confirm: bool


_ACCEPTED = ConfirmOverwrite(confirm=True)


async def confirm_overwrite(
    path: str, overwrite: bool = False, ctx: Context | None = None
) -> ConfirmOverwrite | Elicit[ConfirmOverwrite]:
    """Decide whether the overwrite needs a human answer, and ask only then.

    Every early return resolves as accepted without asking: either no
    confirmation is required (a fresh write, confirmation disabled, a
    client that cannot elicit falls back to the explicit flag), or the
    call is about to be refused by a guard and the answer would never be
    used.
    """
    from arrowhead.auth.identity import caller_identity

    settings = get_settings()
    if not overwrite or not settings.require_write_confirmation:
        return _ACCEPTED
    if "doc_write" in settings.disabled_tool_set():
        return _ACCEPTED
    if settings.auth_enabled and not has_scope(TOOL_SCOPES["doc_write"]):
        return _ACCEPTED
    if not _can_elicit(ctx):
        return _ACCEPTED
    try:
        validate_document_path(
            path, allowed_extensions=settings.doc_allowed_extension_set()
        )
    except ValidationError:
        return _ACCEPTED
    decision = get_authorizer().authorize(
        caller_identity(),
        ACTION_WRITE,
        Resource(kind=KIND_DOCUMENT, identifier=path),
    )
    if not decision.allowed:
        return _ACCEPTED
    store = build_document_store(settings)
    try:
        exists = await anyio.to_thread.run_sync(store.exists, path)
    except DocumentStoreError:
        return _ACCEPTED
    if not exists:
        return _ACCEPTED
    return Elicit(
        f"Overwrite the existing document at '{path}'?", ConfirmOverwrite
    )


def confirmation_declined(outcome: ElicitationResult[ConfirmOverwrite]) -> bool:
    """Whether the resolved confirmation refuses the overwrite."""
    if isinstance(outcome, (DeclinedElicitation, CancelledElicitation)):
        return True
    if isinstance(outcome, AcceptedElicitation):
        answer = outcome.data
        return isinstance(answer, ConfirmOverwrite) and not answer.confirm
    return False


def _can_elicit(ctx: Context | None) -> bool:
    """Whether the connected client declared usable form elicitation.

    An in-process call has no request context and an anonymous stateless
    request may declare nothing; both resolve as unable, and the explicit
    overwrite flag remains the opt-in. A bare elicitation declaration
    counts as form support, matching the SDK's own capability gate.
    """
    if ctx is None:
        return False
    try:
        capabilities = ctx.client_capabilities
    except (ValueError, AttributeError):
        return False
    if capabilities is None or capabilities.elicitation is None:
        return False
    elicitation = capabilities.elicitation
    return elicitation.form is not None or elicitation.url is None
