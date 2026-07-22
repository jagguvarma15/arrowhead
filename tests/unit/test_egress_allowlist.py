"""The egress allowlist confines the fetch tools to approved hosts.

When no allowlist is configured any public host is reachable (the SSRF guard
still blocks private ranges); when one is set, only listed hosts pass, on the
first request and on every redirect hop.
"""

import pytest

from arrowhead.security.ssrf_guard import BlockedURLError, resolve_pinned


async def test_no_allowlist_allows_any_public_host(make_resolver):
    target = await resolve_pinned(
        "https://api.example.com/", getaddrinfo=make_resolver("93.184.216.34")
    )
    assert target.host == "api.example.com"


async def test_a_listed_host_is_permitted(make_resolver):
    target = await resolve_pinned(
        "https://api.example.com/v1",
        getaddrinfo=make_resolver("93.184.216.34"),
        allowed_hosts=frozenset({"api.example.com"}),
    )
    assert target.host == "api.example.com"


async def test_a_host_not_on_the_list_is_refused(make_resolver):
    with pytest.raises(BlockedURLError):
        await resolve_pinned(
            "https://evil.example.com/",
            getaddrinfo=make_resolver("93.184.216.34"),
            allowed_hosts=frozenset({"api.example.com"}),
        )


async def test_matching_is_case_insensitive(make_resolver):
    # A mixed-case URL host matches a lowercase allowlist entry.
    target = await resolve_pinned(
        "https://API.Example.COM/",
        getaddrinfo=make_resolver("93.184.216.34"),
        allowed_hosts=frozenset({"api.example.com"}),
    )
    assert target.host == "api.example.com"


async def test_a_public_ip_literal_is_refused_when_a_list_is_set():
    with pytest.raises(BlockedURLError):
        await resolve_pinned(
            "https://93.184.216.34/",
            allowed_hosts=frozenset({"api.example.com"}),
        )


async def test_fetch_url_enforces_the_configured_allowlist(
    monkeypatch, make_resolver
):
    monkeypatch.setenv("ARROWHEAD_EGRESS_ALLOWED_HOSTS", "api.example.com")
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    from arrowhead.tools.safe_fetch import fetch_url

    with pytest.raises(BlockedURLError):
        await fetch_url(
            "https://evil.example.com/",
            getaddrinfo=make_resolver("93.184.216.34"),
        )


async def test_a_redirect_off_the_allowlist_is_refused(monkeypatch):
    monkeypatch.setenv("ARROWHEAD_EGRESS_ALLOWED_HOSTS", "api.example.com")
    from arrowhead.config import get_settings

    get_settings.cache_clear()

    import httpx

    from arrowhead.tools.safe_fetch import fetch_url

    async def handler(request: httpx.Request) -> httpx.Response:
        # The first hop is allowed and redirects to a host that is not.
        return httpx.Response(302, headers={"location": "https://evil.example.com/"})

    transport = httpx.MockTransport(handler)

    async def resolver(host, port, **kwargs):
        import socket

        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    with pytest.raises(BlockedURLError):
        await fetch_url(
            "https://api.example.com/start",
            transport=transport,
            getaddrinfo=resolver,
        )
