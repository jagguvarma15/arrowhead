"""SSRF guard: resolve a URL's host and refuse non-public addresses.

The guard resolves the hostname once, rejects the URL if any resolved
address is private, loopback, link-local, or otherwise not globally
routable (which covers the cloud metadata address 169.254.169.254), and
pins the address it approved. Callers must connect to the pinned address
rather than re-resolving, otherwise a DNS rebinding attacker can pass the
check with a public record and serve a private one for the connection.
"""

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

import anyio

ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": 80, "https": 443}

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class BlockedURLError(Exception):
    """The URL must not be fetched."""


def is_blocked_address(address: IPAddress) -> bool:
    """Return True unless the address is globally routable unicast."""
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    return not address.is_global or address.is_multicast


@dataclass(frozen=True)
class PinnedTarget:
    """A vetted URL bound to the specific address that was checked."""

    scheme: str
    host: str
    port: int
    address: IPAddress
    path: str
    query: str

    @property
    def request_url(self) -> str:
        """URL that connects to the pinned address, not the hostname."""
        literal = str(self.address)
        if self.address.version == 6:
            literal = f"[{literal}]"
        url = f"{self.scheme}://{literal}:{self.port}{self.path or '/'}"
        if self.query:
            url = f"{url}?{self.query}"
        return url

    @property
    def host_header(self) -> str:
        """Host header value carrying the original hostname."""
        if self.port == DEFAULT_PORTS[self.scheme]:
            return self.host
        return f"{self.host}:{self.port}"


async def resolve_pinned(
    url: str,
    *,
    getaddrinfo=None,
    allowed_hosts: frozenset[str] | None = None,
) -> PinnedTarget:
    """Vet a URL and pin the address the caller must connect to.

    Raises BlockedURLError for disallowed schemes, unresolvable hosts, and
    any host whose resolution includes a non-public address. Every resolved
    address must pass, since an attacker can mix public and private records.

    When allowed_hosts is a non-empty set of lowercased hostnames, the URL's
    host must be one of them; every other host is refused even if it resolves
    to a public address. This is the destination allowlist shared by every
    URL-addressed caller.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise BlockedURLError("only http and https URLs are allowed")
    host = parts.hostname
    if not host:
        raise BlockedURLError("URL has no host")
    if allowed_hosts and host.lower() not in allowed_hosts:
        raise BlockedURLError("host is not in the egress allowlist")
    port = parts.port if parts.port is not None else DEFAULT_PORTS[scheme]

    addresses = await _resolve(host, port, getaddrinfo)
    for address in addresses:
        if is_blocked_address(address):
            raise BlockedURLError("host resolves to a blocked address")

    return PinnedTarget(
        scheme=scheme,
        host=host,
        port=port,
        address=addresses[0],
        path=parts.path,
        query=parts.query,
    )


async def _resolve(host: str, port: int, getaddrinfo) -> list[IPAddress]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass

    if getaddrinfo is None:
        getaddrinfo = anyio.getaddrinfo
    try:
        infos = await getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise BlockedURLError("host does not resolve") from exc

    addresses = []
    for info in infos:
        raw = info[4][0]
        # getaddrinfo may append a zone id (fe80::1%en0); keep it, the
        # ipaddress module accepts zoned IPv6 and such addresses are
        # link-local and blocked anyway.
        addresses.append(ipaddress.ip_address(raw))
    if not addresses:
        raise BlockedURLError("host does not resolve")
    return addresses
