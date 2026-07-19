"""Per-caller token-bucket rate limiting with per-tool ceilings.

Each (caller, tool) pair gets its own bucket. Ceilings differ by cost:
safe_fetch is network-bound and gets a low ceiling, calculate is cheap
and gets a high one. Exceeding a limit returns a clear tool error the
caller can back off from; it never crashes the request.

The bucket state lives in Redis when ARROWHEAD_REDIS_URL is set, so
limits hold across replicas of the stateless server. Without Redis an
in-process store is used and limits are per replica.
"""

import time
from typing import Protocol

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from arrowhead.auth.identity import caller_identity
from arrowhead.config import Settings


class RateLimitExceededError(ToolError):
    """Refused because the caller exhausted this tool's rate limit."""


class TokenBucketStore(Protocol):
    async def acquire(
        self, key: str, capacity: float, refill_per_second: float
    ) -> bool: ...

    async def is_healthy(self) -> bool: ...

    async def aclose(self) -> None: ...


class InMemoryTokenBucketStore:
    """Token buckets in process memory. Limits apply per replica."""

    def __init__(self, clock=time.monotonic) -> None:
        self._clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}

    async def acquire(
        self, key: str, capacity: float, refill_per_second: float
    ) -> bool:
        now = self._clock()
        tokens, updated = self._buckets.get(key, (capacity, now))
        tokens = min(capacity, tokens + (now - updated) * refill_per_second)
        allowed = tokens >= 1
        if allowed:
            tokens -= 1
        self._buckets[key] = (tokens, now)
        return allowed

    async def is_healthy(self) -> bool:
        return True

    async def aclose(self) -> None:
        return None


_TOKEN_BUCKET_LUA = """
local capacity = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local tokens = tonumber(redis.call('HGET', KEYS[1], 'tokens') or capacity)
local updated = tonumber(redis.call('HGET', KEYS[1], 'ts') or now)
tokens = math.min(capacity, tokens + (now - updated) * refill)
local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end
redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', KEYS[1], math.max(60, math.ceil(capacity / refill)))
return allowed
"""


class RedisTokenBucketStore:
    """Token buckets in Redis, shared by every replica.

    The refill math runs atomically inside a Lua script, so concurrent
    requests across replicas cannot double-spend a token.
    """

    def __init__(self, client, clock=time.time) -> None:
        self._client = client
        self._script = client.register_script(_TOKEN_BUCKET_LUA)
        self._clock = clock

    async def acquire(
        self, key: str, capacity: float, refill_per_second: float
    ) -> bool:
        allowed = await self._script(
            keys=[f"arrowhead:ratelimit:{key}"],
            args=[capacity, refill_per_second, self._clock()],
        )
        return bool(allowed)

    async def is_healthy(self) -> bool:
        try:
            return bool(await self._client.ping())
        except Exception:
            return False

    async def aclose(self) -> None:
        await self._client.aclose()


class RateLimitMiddleware(Middleware):
    def __init__(
        self,
        store: TokenBucketStore,
        limits_per_minute: dict[str, int],
        *,
        default_per_minute: int = 0,
    ) -> None:
        self._store = store
        self._limits = limits_per_minute
        self._default = default_per_minute

    async def on_call_tool(
        self, context: MiddlewareContext, call_next: CallNext
    ):
        tool_name = context.message.name
        # A tool without an explicit ceiling falls back to the default, so
        # a newly added tool is never accidentally left unlimited.
        limit = self._limits.get(tool_name, self._default)
        if limit is not None and limit > 0:
            key = f"{caller_identity()}:{tool_name}"
            allowed = await self._store.acquire(
                key, capacity=float(limit), refill_per_second=limit / 60.0
            )
            if not allowed:
                raise RateLimitExceededError(
                    f"rate limit exceeded for {tool_name}: "
                    f"{limit} calls per minute; retry shortly"
                )
        return await call_next(context)

    async def backend_healthy(self) -> bool:
        """Whether the bucket store is reachable, for readiness checks."""
        return await self._store.is_healthy()

    async def aclose(self) -> None:
        """Release the bucket store's resources on shutdown."""
        await self._store.aclose()


def build_rate_limit_middleware(settings: Settings) -> RateLimitMiddleware | None:
    if not settings.rate_limit_enabled:
        return None
    if settings.redis_url:
        import redis.asyncio as redis_asyncio

        store: TokenBucketStore = RedisTokenBucketStore(
            redis_asyncio.from_url(settings.redis_url)
        )
    else:
        store = InMemoryTokenBucketStore()
    return RateLimitMiddleware(
        store,
        settings.rate_limits_per_minute(),
        default_per_minute=settings.default_tool_per_minute,
    )
