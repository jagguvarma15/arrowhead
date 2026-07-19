from fastmcp.server.elicitation import (
    AcceptedElicitation,
    CancelledElicitation,
    DeclinedElicitation,
)

from arrowhead.authz.confirmation import (
    CONFIRM_ACCEPTED,
    CONFIRM_DECLINED,
    CONFIRM_UNAVAILABLE,
    request_confirmation,
)


class FakeContext:
    def __init__(self, result):
        self._result = result

    async def elicit(self, message, response_type=None):
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


async def test_accepted_confirmation():
    ctx = FakeContext(AcceptedElicitation(data=None))
    assert await request_confirmation(ctx, "overwrite?") == CONFIRM_ACCEPTED


async def test_declined_confirmation():
    ctx = FakeContext(DeclinedElicitation())
    assert await request_confirmation(ctx, "overwrite?") == CONFIRM_DECLINED


async def test_cancelled_is_declined():
    ctx = FakeContext(CancelledElicitation())
    assert await request_confirmation(ctx, "overwrite?") == CONFIRM_DECLINED


async def test_client_without_elicitation_is_unavailable():
    ctx = FakeContext(RuntimeError("elicitation not supported"))
    assert await request_confirmation(ctx, "overwrite?") == CONFIRM_UNAVAILABLE


async def test_missing_context_is_unavailable():
    assert await request_confirmation(None, "overwrite?") == CONFIRM_UNAVAILABLE
