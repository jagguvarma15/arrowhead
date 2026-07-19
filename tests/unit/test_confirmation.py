from fastmcp.server.elicitation import (
    AcceptedElicitation,
    CancelledElicitation,
    DeclinedElicitation,
)

from arrowhead.authz.confirmation import request_confirmation


class FakeContext:
    def __init__(self, result):
        self._result = result

    async def elicit(self, message, response_type=None):
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


async def test_accepted_confirmation_returns_true():
    ctx = FakeContext(AcceptedElicitation(data=None))
    assert await request_confirmation(ctx, "overwrite?") is True


async def test_declined_returns_false():
    ctx = FakeContext(DeclinedElicitation())
    assert await request_confirmation(ctx, "overwrite?") is False


async def test_cancelled_returns_false():
    ctx = FakeContext(CancelledElicitation())
    assert await request_confirmation(ctx, "overwrite?") is False


async def test_client_without_elicitation_returns_false():
    ctx = FakeContext(RuntimeError("elicitation not supported"))
    assert await request_confirmation(ctx, "overwrite?") is False


async def test_missing_context_returns_false():
    assert await request_confirmation(None, "overwrite?") is False
