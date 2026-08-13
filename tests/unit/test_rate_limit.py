import fakeredis.aioredis
from mcp import Client
from mcp.server import MCPServer

from arrowhead.runtime.guards import Guards, guard_tool
from arrowhead.security.rate_limit import (
    InMemoryTokenBucketStore,
    RateLimiter,
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

    async def test_buckets_are_bounded(self):
        store = InMemoryTokenBucketStore(clock=Clock(), max_entries=100)
        for i in range(5000):
            await store.acquire(f"caller-{i}:fetch", 60, 1.0)
        assert len(store._buckets) == 100
        assert "caller-4999:fetch" in store._buckets
        assert "caller-0:fetch" not in store._buckets

    async def test_eviction_retains_a_throttled_bucket(self):
        store = InMemoryTokenBucketStore(clock=Clock(), max_entries=3)
        # Drain the victim so its bucket is throttled (no tokens, no refill).
        assert await store.acquire("victim", 1, 0.0)
        assert not await store.acquire("victim", 1, 0.0)
        # Flood with fresh, unpenalized buckets past the cap.
        for i in range(10):
            await store.acquire(f"flood{i}", 60, 0.0)
        # The throttled bucket is kept; an unpenalized flood bucket was evicted
        # instead, so the victim cannot reset its own throttle.
        assert "victim" in store._buckets
        assert not await store.acquire("victim", 1, 0.0)


class TestRedisStore:
    async def test_capacity_is_consumed(self):
        # The script reads time from the Redis server, so refill over time is
        # covered by the in-memory store's injectable clock; here we confirm the
        # capacity is consumed and then refused.
        store = RedisTokenBucketStore(fakeredis.aioredis.FakeRedis())
        assert await store.acquire("k", 2, 1.0)
        assert await store.acquire("k", 2, 1.0)
        assert not await store.acquire("k", 2, 1.0)

    async def test_is_healthy_and_aclose(self):
        client = fakeredis.aioredis.FakeRedis()
        store = RedisTokenBucketStore(client)
        assert await store.is_healthy() is True
        await store.aclose()


class TestLimiterLifecycle:
    class RecordingStore:
        def __init__(self):
            self.closed = False

        async def acquire(self, key, capacity, refill_per_second):
            return True

        async def is_healthy(self):
            return True

        async def aclose(self):
            self.closed = True

    async def test_backend_healthy_and_aclose_delegate(self):
        store = self.RecordingStore()
        limiter = RateLimiter(store, {})
        assert await limiter.backend_healthy() is True
        await limiter.aclose()
        assert store.closed is True

    async def test_in_memory_backend_is_healthy_and_closes_cleanly(self):
        store = InMemoryTokenBucketStore(clock=Clock())
        assert await store.is_healthy() is True
        await store.aclose()

    async def test_explicit_zero_blocks_but_an_absent_component_falls_through(self):
        store = InMemoryTokenBucketStore(clock=Clock())
        limiter = RateLimiter(store, {"blocked": 0}, default_per_minute=0)
        # an explicit ceiling of 0 means no calls
        assert await limiter.allow("blocked") is False
        # a component with no ceiling and no default is unlimited, not blocked
        assert await limiter.allow("absent") is True

    async def test_allow_consumes_a_configured_ceiling(self):
        store = InMemoryTokenBucketStore(clock=Clock())
        limiter = RateLimiter(store, {"c": 1})
        assert await limiter.allow("c") is True
        assert await limiter.allow("c") is False


def _spec(name, fn):
    class Spec:
        scope = "tools:read"

        def load(self):
            return fn

    spec = Spec()
    spec.name = name
    return spec


def _register(mcp: MCPServer, guards: Guards, name: str) -> None:
    def tool(text: str) -> str:
        return text

    tool.__name__ = name
    mcp.add_tool(guard_tool(_spec(name, tool), guards), name=name)


def limited_server(limit: int, *, default: int = 0) -> MCPServer:
    limiter = RateLimiter(
        InMemoryTokenBucketStore(clock=Clock()),
        {"echo": limit},
        default_per_minute=default,
    )
    guards = Guards(
        enforce_scopes=False, rate_limiter=limiter, disabled=frozenset()
    )
    mcp = MCPServer("limited")
    _register(mcp, guards, "echo")
    _register(mcp, guards, "unlimited")
    return mcp


async def test_exceeding_the_limit_is_a_clean_error_not_a_crash():
    async with Client(limited_server(limit=2)) as client:
        for _ in range(2):
            result = await client.call_tool("echo", {"text": "hi"})
            assert result.content[0].text == "hi"

        result = await client.call_tool("echo", {"text": "hi"})
        assert result.is_error
        assert "rate limit exceeded for echo" in result.content[0].text

        # The server keeps serving: tools without a ceiling are unaffected.
        result = await client.call_tool("unlimited", {"text": "still up"})
        assert result.content[0].text == "still up"


async def test_unlisted_tool_falls_back_to_default_ceiling():
    limiter = RateLimiter(
        InMemoryTokenBucketStore(clock=Clock()),
        {"echo": 5},
        default_per_minute=1,
    )
    guards = Guards(
        enforce_scopes=False, rate_limiter=limiter, disabled=frozenset()
    )
    mcp = MCPServer("defaulted")
    _register(mcp, guards, "only")

    async with Client(mcp) as client:
        first = await client.call_tool("only", {"text": "a"})
        assert first.content[0].text == "a"
        second = await client.call_tool("only", {"text": "b"})
        assert second.is_error
        assert "rate limit exceeded for only" in second.content[0].text


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


async def test_spamming_calculate_on_the_real_server(monkeypatch):
    monkeypatch.setenv("ARROWHEAD_CALCULATE_PER_MINUTE", "3")
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    from arrowhead.server import create_server

    async with Client(create_server()) as client:
        for _ in range(3):
            result = await client.call_tool(
                "calculate", {"expression": "1 + 1"}
            )
            assert result.structured_content == {"result": 2.0}
        result = await client.call_tool("calculate", {"expression": "1 + 1"})
        assert result.is_error
        assert "rate limit" in result.content[0].text
