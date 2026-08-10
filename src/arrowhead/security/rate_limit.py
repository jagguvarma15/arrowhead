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
from collections import OrderedDict
from typing import Protocol

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from arrowhead.auth.identity import caller_identity
from arrowhead.config import Settings

# Cap on the number of distinct (caller, tool) buckets the in-memory store
# retains, so a stream of unique caller identities cannot grow it without
# bound. When the cap is reached an unpenalized bucket (one that still has a
# token to spend) is evicted in preference to a rate-limited one, so a flood of
# new keys cannot evict and thereby reset a caller's own throttled bucket.
_DEFAULT_MAX_ENTRIES = 100_000
# How many of the oldest buckets to scan for an unpenalized eviction victim
# before falling back to dropping the oldest, keeping eviction near-constant.
_EVICTION_SCAN = 64


class RateLimitExceededError(ToolError):
    """Refused because the caller exhausted this tool's rate limit."""


class TokenBucketStore(Protocol):
    async def acquire(
        self, key: str, capacity: float, refill_per_second: float
    ) -> bool: ...

    async def is_healthy(self) -> bool: ...

    async def aclose(self) -> None: ...


class InMemoryTokenBucketStore:
    """Token buckets in process memory. Limits apply per replica.

    Buckets are held in an LRU bounded by max_entries so a flood of distinct
    caller identities cannot grow the store without bound. When the cap is
    reached the store drops an unpenalized bucket (one still holding a token)
    rather than a throttled one, so a caller cannot flood new keys to evict and
    reset their own drained bucket.
    """

    def __init__(
        self, clock=time.monotonic, *, max_entries=_DEFAULT_MAX_ENTRIES
    ) -> None:
        self._clock = clock
        self._max_entries = max_entries
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

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
        self._buckets.move_to_end(key)
        while len(self._buckets) > self._max_entries:
            self._evict_one()
        return allowed

    def _evict_one(self) -> None:
        # Prefer to drop a bucket that still has a token to spend: recreating it
        # is identical to its current state. A drained bucket is retained so an
        # attacker cannot reset their own throttle by aging it out of the LRU.
        victim = None
        for index, (bucket_key, (tokens, _updated)) in enumerate(
            self._buckets.items()
        ):
            if tokens >= 1:
                victim = bucket_key
                break
            if index + 1 >= _EVICTION_SCAN:
                break
        if victim is not None:
            del self._buckets[victim]
        else:
            # Every scanned bucket is throttled; drop the oldest to keep the
            # bound.
            self._buckets.popitem(last=False)

    async def is_healthy(self) -> bool:
        return True

    async def aclose(self) -> None:
        return None


_BUCKET_LUA_SCRIPT = """
local capacity = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
local tokens = tonumber(redis.call('HGET', KEYS[1], 'tokens') or capacity)
local updated = tonumber(redis.call('HGET', KEYS[1], 'ts') or now)
local elapsed = now - updated
if elapsed < 0 then elapsed = 0 end
tokens = math.min(capacity, tokens + elapsed * refill)
if tokens < 0 then tokens = 0 end
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

    The refill math runs atomically inside a Lua script that reads the time
    from the Redis server itself, so a replica whose wall clock is skewed
    cannot mint tokens by sending an inflated timestamp or drain a shared
    bucket by sending a lagging one. A negative elapsed interval is clamped to
    zero and stored tokens never go below zero.
    """

    def __init__(self, client) -> None:
        self._client = client
        self._script = client.register_script(_BUCKET_LUA_SCRIPT)

    async def acquire(
        self, key: str, capacity: float, refill_per_second: float
    ) -> bool:
        allowed = await self._script(
            keys=[f"arrowhead:ratelimit:{key}"],
            args=[capacity, refill_per_second],
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
        await self._enforce(context.message.name)
        return await call_next(context)

    async def on_read_resource(
        self, context: MiddlewareContext, call_next: CallNext
    ):
        # Resource reads share one per-caller bucket, keyed by the operation
        # class rather than the resource URI, so an unbounded set of URIs
        # cannot create an unbounded set of buckets.
        await self._enforce("resource:read")
        return await call_next(context)

    async def on_get_prompt(
        self, context: MiddlewareContext, call_next: CallNext
    ):
        await self._enforce("prompt:get")
        return await call_next(context)

    async def allow(self, component: str) -> bool:
        """Whether a call to component is permitted now, without raising.

        Used by request paths outside the middleware chain (argument
        completion) so they share the same per-caller ceilings.
        """
        return await self._check(component)

    async def _check(self, component: str) -> bool:
        # An explicit ceiling of zero or less means no calls, not unlimited. A
        # component with no explicit ceiling falls back to the default; a
        # non-positive default means none is configured, so it is left
        # unlimited rather than blocked, keeping a newly added component
        # working until a ceiling is set for it.
        if component in self._limits:
            limit = self._limits[component]
            if limit <= 0:
                return False
        else:
            limit = self._default
            if limit <= 0:
                return True
        key = f"{caller_identity()}:{component}"
        return await self._store.acquire(
            key, capacity=float(limit), refill_per_second=limit / 60.0
        )

    async def _enforce(self, component: str) -> None:
        if not await self._check(component):
            limit = self._limits.get(component, self._default)
            raise RateLimitExceededError(
                f"rate limit exceeded for {component}: "
                f"{max(limit, 0)} calls per minute; retry shortly"
            )

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
    limits = settings.rate_limits_per_minute()
    # The non-tool components rate-limit under their own operation-class keys.
    limits["resource:read"] = settings.resource_read_per_minute
    limits["prompt:get"] = settings.prompt_get_per_minute
    limits["completion"] = settings.completion_per_minute
    return RateLimitMiddleware(
        store,
        limits,
        default_per_minute=settings.default_tool_per_minute,
    )
