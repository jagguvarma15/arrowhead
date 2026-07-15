import fakeredis.aioredis
import pytest
from fastmcp import Client, FastMCP

from arrowhead.security.rate_limit import (
    InMemoryTokenBucketStore,
    RateLimitMiddleware,
    RedisTokenBucketStore,
)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class TestInMemoryStore:
    async def test_capacity_is_consumed(self):
        store = InMemoryTokenBucketStore(clock=Clock())
        results = [await store.acquire("k", 3, 0.0) for _ in range(4)]
        assert results == [True, True, True, False]

    async def test_tokens_refill_over_time(self):
        clock = Clock()
        store = InMemoryTokenBucketStore(clock=clock)
        assert await store.acquire("k", 1, 1.0)
        assert not await store.acquire("k", 1, 1.0)
        clock.now += 1.5
        assert await store.acquire("k", 1, 1.0)

    async def test_keys_are_independent(self):
        store = InMemoryTokenBucketStore(clock=Clock())
        assert await store.acquire("caller-a:fetch", 1, 0.0)
        assert not await store.acquire("caller-a:fetch", 1, 0.0)
        assert await store.acquire("caller-b:fetch", 1, 0.0)
        assert await store.acquire("caller-a:calc", 1, 0.0)


class TestRedisStore:
    async def test_capacity_and_refill(self):
        clock = Clock()
        store = RedisTokenBucketStore(
            fakeredis.aioredis.FakeRedis(), clock=clock
        )
        assert await store.acquire("k", 2, 1.0)
        assert await store.acquire("k", 2, 1.0)
        assert not await store.acquire("k", 2, 1.0)
        clock.now += 1.0
        assert await store.acquire("k", 2, 1.0)


def limited_server(limit: int) -> FastMCP:
    mcp = FastMCP(
        "limited",
        middleware=[
            RateLimitMiddleware(
                InMemoryTokenBucketStore(clock=Clock()), {"echo": limit}
            )
        ],
    )

    @mcp.tool
    def echo(text: str) -> str:
        return text

    @mcp.tool
    def unlimited(text: str) -> str:
        return text

    return mcp


async def test_exceeding_the_limit_is_a_clean_error_not_a_crash():
    async with Client(limited_server(limit=2)) as client:
        for _ in range(2):
            result = await client.call_tool("echo", {"text": "hi"})
            assert result.content[0].text == "hi"

        result = await client.call_tool(
            "echo", {"text": "hi"}, raise_on_error=False
        )
        assert result.is_error
        assert "rate limit exceeded for echo" in result.content[0].text

        # The server keeps serving: tools without a ceiling are unaffected.
        result = await client.call_tool("unlimited", {"text": "still up"})
        assert result.content[0].text == "still up"


async def test_callers_get_separate_buckets(monkeypatch):
    mcp = limited_server(limit=1)
    identities = iter(["alice", "bob"])
    monkeypatch.setattr(
        "arrowhead.security.rate_limit.caller_identity",
        lambda: next(identities),
    )
    async with Client(mcp) as client:
        first = await client.call_tool("echo", {"text": "a"})
        assert first.content[0].text == "a"
        second = await client.call_tool("echo", {"text": "b"})
        assert second.content[0].text == "b"


async def test_spamming_calculate_on_the_real_server(
    monkeypatch, stdio_transport
):
    monkeypatch.setenv("ARROWHEAD_CALCULATE_PER_MINUTE", "3")
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    from arrowhead.server import create_server

    async with Client(create_server()) as client:
        for _ in range(3):
            result = await client.call_tool(
                "calculate", {"expression": "1 + 1"}
            )
            assert result.data == 2.0
        result = await client.call_tool(
            "calculate", {"expression": "1 + 1"}, raise_on_error=False
        )
        assert result.is_error
        assert "rate limit" in result.content[0].text
