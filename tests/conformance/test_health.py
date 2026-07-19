"""Liveness and readiness endpoints.

These must be reachable without a token even when auth is enabled, so a
platform probe can check the instance without credentials.
"""

import httpx
from fastmcp import FastMCP

from arrowhead import __version__
from arrowhead.health import register_health_routes


async def asgi_client(app):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://probe"
    )


async def test_health_is_unauthenticated_and_reports_version(docs):
    from arrowhead.server import create_server

    app = create_server().http_app(json_response=True, stateless_http=True)
    async with app.router.lifespan_context(app):
        async with await asgi_client(app) as client:
            response = await client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__


async def test_health_reachable_with_auth_enabled_and_no_token(auth_client):
    async with auth_client() as client:
        response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


async def test_ready_reports_checks(docs):
    from arrowhead.server import create_server

    app = create_server().http_app(json_response=True, stateless_http=True)
    async with app.router.lifespan_context(app):
        async with await asgi_client(app) as client:
            response = await client.get("/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["checks"]["corpus_writable"] is True


async def test_lifespan_closes_rate_limit_backend(docs, monkeypatch):
    import fakeredis.aioredis

    closed = {"value": False}
    client = fakeredis.aioredis.FakeRedis()
    original_aclose = client.aclose

    async def spy_aclose(*args, **kwargs):
        closed["value"] = True
        return await original_aclose(*args, **kwargs)

    monkeypatch.setattr(client, "aclose", spy_aclose)
    monkeypatch.setattr("redis.asyncio.from_url", lambda *a, **k: client)
    monkeypatch.setenv("ARROWHEAD_REDIS_URL", "redis://fake:6379/0")
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    from arrowhead.server import create_server

    app = create_server().http_app(json_response=True, stateless_http=True)
    async with app.router.lifespan_context(app):
        pass
    assert closed["value"] is True


async def test_ready_returns_503_when_a_dependency_is_down():
    class UnhealthyLimiter:
        async def backend_healthy(self):
            return False

    mcp = FastMCP("ready-probe")
    register_health_routes(mcp, UnhealthyLimiter())
    app = mcp.http_app(json_response=True, stateless_http=True)
    async with app.router.lifespan_context(app):
        async with await asgi_client(app) as client:
            response = await client.get("/ready")
    assert response.status_code == 503
    assert response.json()["status"] == "not ready"
    assert response.json()["checks"]["rate_limit_backend"] is False
