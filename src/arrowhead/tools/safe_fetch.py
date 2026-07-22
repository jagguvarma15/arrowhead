"""URL fetch tool guarded against SSRF.

Every request target, including each redirect hop, is vetted by the SSRF
guard and the connection goes to the pinned address the guard approved.
The original hostname travels in the Host header and, for HTTPS, as the
TLS server name, so certificate verification still checks the real host.
Response bodies are capped in size. The caller's MCP credentials are never
attached to outbound requests.
"""

from urllib.parse import urljoin

import httpx
from fastmcp.exceptions import ToolError

from arrowhead.config import get_settings
from arrowhead.security.input_validation import ValidationError, validate_url
from arrowhead.security.ssrf_guard import BlockedURLError, resolve_pinned


class FetchTooLargeError(Exception):
    """The response body exceeded the configured size cap."""


async def safe_fetch(url: str) -> dict:
    """Fetch a public http or https URL and return its status, content
    type, and body text. Private, loopback, link-local, and cloud metadata
    addresses are refused. Example: safe_fetch(url="https://example.com/").
    """
    try:
        return await fetch_url(url)
    except (ValidationError, BlockedURLError, FetchTooLargeError) as exc:
        raise ToolError(str(exc)) from exc
    except httpx.HTTPError as exc:
        raise ToolError(f"fetch failed: {type(exc).__name__}") from exc


async def fetch_url(
    url: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    getaddrinfo=None,
) -> dict:
    """Fetch with per-hop SSRF vetting and address pinning.

    transport and getaddrinfo exist so tests can substitute a mock
    transport and resolver; production callers pass only the URL.
    """
    settings = get_settings()
    validate_url(url)
    allowed_hosts = settings.egress_allowed_hosts_set()

    async with httpx.AsyncClient(
        transport=transport,
        timeout=settings.fetch_timeout_seconds,
        follow_redirects=False,
    ) as client:
        current = url
        for _ in range(settings.fetch_max_redirects + 1):
            target = await resolve_pinned(
                current, getaddrinfo=getaddrinfo, allowed_hosts=allowed_hosts
            )
            extensions = {}
            if target.scheme == "https":
                extensions["sni_hostname"] = target.host
            request = client.build_request(
                "GET",
                target.request_url,
                headers={"Host": target.host_header},
                extensions=extensions,
            )
            response = await client.send(request, stream=True)
            try:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise BlockedURLError("redirect without a location")
                    current = urljoin(current, location)
                    continue
                body = await _read_capped(
                    response, settings.fetch_max_response_bytes
                )
            finally:
                await response.aclose()
            return {
                "status": response.status_code,
                "content_type": response.headers.get("content-type"),
                "body": body.decode("utf-8", errors="replace"),
            }
    raise BlockedURLError("too many redirects")


async def _read_capped(response: httpx.Response, limit: int) -> bytes:
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > limit:
            raise FetchTooLargeError(f"response exceeds {limit} bytes")
    return bytes(body)
