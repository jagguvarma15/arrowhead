import httpx
import pytest
from fastmcp.exceptions import ToolError

from arrowhead.security.ssrf_guard import BlockedURLError
from arrowhead.tools.safe_fetch import FetchTooLargeError, fetch_url, safe_fetch

PUBLIC_IP = "93.184.216.34"


async def test_cloud_metadata_fetch_rejected():
    with pytest.raises(BlockedURLError):
        await fetch_url("http://169.254.169.254/latest/meta-data/")


async def test_tool_reports_blocked_url_as_tool_error():
    with pytest.raises(ToolError):
        await safe_fetch("http://127.0.0.1:8080/internal")


async def test_public_url_fetch_succeeds(make_resolver):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == PUBLIC_IP
        assert request.headers["host"] == "example.com"
        return httpx.Response(200, text="hello", headers={"content-type": "text/plain"})

    result = await fetch_url(
        "http://example.com/",
        transport=httpx.MockTransport(handler),
        getaddrinfo=make_resolver(PUBLIC_IP),
    )
    assert result["status"] == 200
    assert result["body"] == "hello"
    assert result["content_type"] == "text/plain"


async def test_redirect_to_private_address_rejected(make_resolver):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302, headers={"location": "http://169.254.169.254/latest/meta-data/"}
        )

    with pytest.raises(BlockedURLError):
        await fetch_url(
            "http://example.com/",
            transport=httpx.MockTransport(handler),
            getaddrinfo=make_resolver(PUBLIC_IP),
        )


async def test_redirect_loop_capped(make_resolver):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://example.com/again"})

    with pytest.raises(BlockedURLError, match="too many redirects"):
        await fetch_url(
            "http://example.com/",
            transport=httpx.MockTransport(handler),
            getaddrinfo=make_resolver(PUBLIC_IP),
        )


async def test_oversized_response_rejected(make_resolver, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_FETCH_MAX_RESPONSE_BYTES", "16")
    from arrowhead.config import get_settings

    get_settings.cache_clear()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="x" * 64)

    with pytest.raises(FetchTooLargeError):
        await fetch_url(
            "http://example.com/",
            transport=httpx.MockTransport(handler),
            getaddrinfo=make_resolver(PUBLIC_IP),
        )


async def test_invalid_url_rejected():
    with pytest.raises(ToolError):
        await safe_fetch("")
