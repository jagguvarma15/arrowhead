"""Unauthenticated liveness and readiness endpoints.

These routes are registered as custom HTTP routes, which sit outside the
MCP auth middleware, so a platform probe reaches them without a token.
/health is a pure liveness signal; /ready reports whether the corpus is
writable and the rate-limit backend, if configured, is reachable, and
returns 503 when a dependency is unavailable so a load balancer can hold
traffic until the instance is ready.
"""

import os

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
        checks = {"corpus_writable": _corpus_writable(get_settings())}
        if rate_limiter is not None:
            checks["rate_limit_backend"] = await rate_limiter.backend_healthy()
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
