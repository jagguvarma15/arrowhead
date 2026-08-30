from mcp.server.elicitation import (
    AcceptedElicitation,
    CancelledElicitation,
    DeclinedElicitation,
)
from mcp.server.mcpserver import Elicit
from mcp.types import (
    ClientCapabilities,
    ElicitationCapability,
    FormElicitationCapability,
)

from arrowhead.authz.confirmation import (
    ConfirmOverwrite,
    confirm_overwrite,
    confirmation_declined,
)


class FakeContext:
    """A context exposing only the declared client capabilities."""

    def __init__(self, capabilities):
        self.client_capabilities = capabilities


def eliciting_context():
    return FakeContext(
        ClientCapabilities(
            elicitation=ElicitationCapability(form=FormElicitationCapability())
        )
    )


class TestConfirmationDeclined:
    def test_accepted_confirm_true_is_not_declined(self):
        outcome = AcceptedElicitation(data=ConfirmOverwrite(confirm=True))
        assert confirmation_declined(outcome) is False

    def test_accepted_confirm_false_is_declined(self):
        outcome = AcceptedElicitation(data=ConfirmOverwrite(confirm=False))
        assert confirmation_declined(outcome) is True

    def test_declined_is_declined(self):
        assert confirmation_declined(DeclinedElicitation()) is True

    def test_cancelled_is_declined(self):
        assert confirmation_declined(CancelledElicitation()) is True

    def test_missing_outcome_is_not_declined(self):
        # A direct call with no resolved confirmation falls back to the
        # explicit overwrite flag, exactly like a client that cannot elicit.
        assert confirmation_declined(None) is False


async def test_fresh_write_resolves_without_asking(docs):
    outcome = await confirm_overwrite("a.txt", False, eliciting_context())
    assert isinstance(outcome, ConfirmOverwrite) and outcome.confirm


async def test_missing_context_resolves_without_asking(docs):
    (docs / "a.txt").write_text("existing")
    outcome = await confirm_overwrite("a.txt", True, None)
    assert isinstance(outcome, ConfirmOverwrite) and outcome.confirm


async def test_capability_less_client_resolves_without_asking(docs):
    (docs / "a.txt").write_text("existing")
    outcome = await confirm_overwrite(
        "a.txt", True, FakeContext(ClientCapabilities())
    )
    assert isinstance(outcome, ConfirmOverwrite) and outcome.confirm


async def test_absent_target_resolves_without_asking(docs):
    outcome = await confirm_overwrite("new.txt", True, eliciting_context())
    assert isinstance(outcome, ConfirmOverwrite) and outcome.confirm


async def test_existing_target_with_capable_client_asks(docs):
    (docs / "a.txt").write_text("existing")
    outcome = await confirm_overwrite("a.txt", True, eliciting_context())
    assert isinstance(outcome, Elicit)
    assert "a.txt" in outcome.message
    assert outcome.schema is ConfirmOverwrite


async def test_invalid_path_never_asks(docs):
    outcome = await confirm_overwrite(
        "../../etc/passwd.txt", True, eliciting_context()
    )
    assert isinstance(outcome, ConfirmOverwrite) and outcome.confirm


class PeekingLimiter:
    """Records would_allow calls and answers with a fixed verdict."""

    def __init__(self, allowed):
        self.allowed = allowed
        self.asked = []

    async def would_allow(self, component):
        self.asked.append(component)
        return self.allowed


def bound_context(limiter):
    from arrowhead.authz.confirmation import bind_rate_limiter

    server = ServerStandIn()
    bind_rate_limiter(server, limiter)
    ctx = eliciting_context()
    ctx.mcp_server = server
    return ctx


class ServerStandIn:
    """A weakly referenceable stand-in for the MCPServer instance."""


async def test_over_quota_caller_never_asks(docs):
    # The resolver runs before the guard chain, so it must consult the
    # server's limiter itself: a caller out of doc_write budget is resolved
    # without a prompt and without touching the corpus.
    (docs / "a.txt").write_text("existing")
    limiter = PeekingLimiter(allowed=False)
    outcome = await confirm_overwrite("a.txt", True, bound_context(limiter))
    assert isinstance(outcome, ConfirmOverwrite) and outcome.confirm
    assert limiter.asked == ["doc_write"]


async def test_within_quota_caller_still_asks(docs):
    (docs / "a.txt").write_text("existing")
    limiter = PeekingLimiter(allowed=True)
    outcome = await confirm_overwrite("a.txt", True, bound_context(limiter))
    assert isinstance(outcome, Elicit)
    assert limiter.asked == ["doc_write"]


async def test_unbound_server_resolves_as_before(docs):
    # A context whose server has no bound limiter (rate limiting disabled)
    # keeps the pre-existing behavior: the existing target is confirmed.
    (docs / "a.txt").write_text("existing")
    ctx = eliciting_context()
    ctx.mcp_server = ServerStandIn()
    outcome = await confirm_overwrite("a.txt", True, ctx)
    assert isinstance(outcome, Elicit)


async def test_unauthorized_write_never_asks(docs, monkeypatch):
    from arrowhead.authz.enforce import get_authorizer
    from arrowhead.config import get_settings

    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    get_settings.cache_clear()
    get_authorizer.cache_clear()
    (docs / "someone-else").mkdir()
    (docs / "someone-else" / "theirs.txt").write_text("existing")
    # The default policy confines writes to the caller's namespace, so the
    # denied caller must not put a confirmation prompt in front of a human.
    outcome = await confirm_overwrite(
        "someone-else/theirs.txt", True, eliciting_context()
    )
    assert isinstance(outcome, ConfirmOverwrite) and outcome.confirm
