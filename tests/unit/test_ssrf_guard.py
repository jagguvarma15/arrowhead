import ipaddress
import socket

import pytest

from arrowhead.security.ssrf_guard import (
    BlockedURLError,
    is_blocked_address,
    resolve_pinned,
)


async def test_cloud_metadata_address_rejected():
    with pytest.raises(BlockedURLError):
        await resolve_pinned("http://169.254.169.254/latest/meta-data/")


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://10.0.0.8/admin",
        "http://172.16.4.2:8080/",
        "http://192.168.1.1/",
        "http://169.254.10.10/",
        "http://[::1]/",
        "http://[fc00::1]/",
        "http://[fe80::1]/",
        "http://0.0.0.0/",
    ],
)
async def test_private_and_reserved_literals_rejected(url):
    with pytest.raises(BlockedURLError):
        await resolve_pinned(url)


@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "ftp://example.com/", "gopher://x/"]
)
async def test_non_http_schemes_rejected(url):
    with pytest.raises(BlockedURLError):
        await resolve_pinned(url)


async def test_hostname_resolving_to_private_address_rejected(make_resolver):
    with pytest.raises(BlockedURLError):
        await resolve_pinned(
            "http://internal.example.com/", getaddrinfo=make_resolver("10.1.2.3")
        )


async def test_mixed_public_and_private_records_rejected(make_resolver):
    resolver = make_resolver("93.184.216.34", "10.1.2.3")
    with pytest.raises(BlockedURLError):
        await resolve_pinned("http://evil.example.com/", getaddrinfo=resolver)


async def test_ipv4_mapped_ipv6_loopback_rejected(make_resolver):
    resolver = make_resolver("::ffff:127.0.0.1")
    with pytest.raises(BlockedURLError):
        await resolve_pinned("http://mapped.example.com/", getaddrinfo=resolver)


async def test_unresolvable_host_rejected():
    async def failing(host, port, **kwargs):
        raise socket.gaierror("no such host")

    with pytest.raises(BlockedURLError):
        await resolve_pinned("http://nope.invalid/", getaddrinfo=failing)


async def test_public_host_is_pinned(make_resolver):
    target = await resolve_pinned(
        "https://example.com/page?q=1", getaddrinfo=make_resolver("93.184.216.34")
    )
    assert target.address == ipaddress.ip_address("93.184.216.34")
    assert target.request_url == "https://93.184.216.34:443/page?q=1"
    assert target.host_header == "example.com"


def test_blocklist_classification():
    assert is_blocked_address(ipaddress.ip_address("169.254.169.254"))
    assert is_blocked_address(ipaddress.ip_address("100.64.0.1"))
    assert is_blocked_address(ipaddress.ip_address("224.0.0.1"))
    assert not is_blocked_address(ipaddress.ip_address("93.184.216.34"))
    assert not is_blocked_address(
        ipaddress.ip_address("2606:2800:220:1:248:1893:25c8:1946")
    )
