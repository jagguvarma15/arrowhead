"""Unauthenticated liveness and readiness endpoints.

These routes are registered as custom HTTP routes, which sit outside the
MCP auth middleware, so a platform probe reaches them without a token.
/health is a pure liveness signal; /ready reports whether the corpus is
writable and each configured backend (the rate limiter's store, the SQL
connector) is reachable, and returns 503 when a dependency is unavailable
so a load balancer can hold traffic until the instance is ready. A check
for an unconfigured backend is omitted rather than reported as failed,
and the embedding endpoint is deliberately never probed here: readiness
runs unauthenticated, and it must not be usable to drive traffic at a
metered external service.
"""

import os

import anyio
from starlette.requests import Request
from starlette.responses import JSONResponse

from arrowhead import __version__
from arrowhead.config import Settings, get_settings


def register_health_routes(mcp, rate_limiter) -> None:
    @mcp.custom_route("/health", methods=["GET"], include_in_schema=False)
    async def health(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "version": __version__})

    @mcp.custom_route("/ready", methods=["GET"], include_in_schema=False)
    async def ready(request: Request) -> JSONResponse:
        settings = get_settings()
        # The writability probe touches the filesystem, so it runs in a
        # worker thread rather than on the event loop of an endpoint any
        # unauthenticated prober can hit.
        checks = {
            "corpus_writable": await anyio.to_thread.run_sync(
                _corpus_writable, settings
            )
        }
        if rate_limiter is not None:
            checks["rate_limit_backend"] = await rate_limiter.backend_healthy()
        if settings.sql_dsn:
            from arrowhead.connectors.sql import backend_healthy

            checks["sql_backend"] = await backend_healthy(settings)
        ready = all(checks.values())
        return JSONResponse(
            {"status": "ready" if ready else "not ready", "checks": checks},
            status_code=200 if ready else 503,
        )


def _corpus_writable(settings: Settings) -> bool:
    root = settings.docs_root
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    return os.access(root, os.W_OK)
