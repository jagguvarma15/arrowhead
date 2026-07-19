import socket
import time
from contextlib import asynccontextmanager

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from arrowhead.config import get_settings

ISSUER = "https://idp.test"
AUDIENCE = "https://arrowhead.test"


@pytest.fixture(autouse=True)
def fresh_settings():
    """Settings and settings-derived caches must not leak between tests."""
    from arrowhead.authz.enforce import get_authorizer

    get_settings.cache_clear()
    get_authorizer.cache_clear()
    yield
    get_settings.cache_clear()
    get_authorizer.cache_clear()


@pytest.fixture
def jail(tmp_path, monkeypatch):
    """Point the read_file jail at a temporary directory."""
    monkeypatch.setenv("ARROWHEAD_JAIL_ROOT", str(tmp_path))
    get_settings.cache_clear()
    return tmp_path


@pytest.fixture
def docs(tmp_path, monkeypatch):
    """Point the document corpus at a temporary directory."""
    monkeypatch.setenv("ARROWHEAD_DOCS_ROOT", str(tmp_path))
    get_settings.cache_clear()
    return tmp_path


@pytest.fixture
def stdio_transport():
    """Mark the current context as stdio so scoped tools are visible.

    In-memory test clients have no transport; FastMCP then enforces
    component auth and hides every scoped tool from an anonymous caller.
    """
    from fastmcp.server.context import _current_transport

    token = _current_transport.set("stdio")
    yield
    _current_transport.reset(token)


@pytest.fixture
def make_resolver():
    """Factory for getaddrinfo stand-ins returning fixed addresses."""

    def factory(*ips: str):
        async def getaddrinfo(host, port, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))
                for ip in ips
            ]

        return getaddrinfo

    return factory


@pytest.fixture(scope="session")
def keypair():
    """RSA keypair standing in for the external authorization server."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


@pytest.fixture
def issue_token(keypair):
    private_pem, _ = keypair

    def issue(audience=AUDIENCE, scope="tools:read", issuer=ISSUER, ttl=600):
        now = int(time.time())
        claims = {
            "iss": issuer,
            "aud": audience,
            "sub": "user-1",
            "iat": now,
            "exp": now + ttl,
            "scope": scope,
        }
        return jwt.encode(claims, private_pem, algorithm="RS256")

    return issue


@pytest.fixture
def auth_client(keypair, monkeypatch):
    """Context-manager factory for an HTTP client against an authed app.

    The ASGI lifespan must be entered and exited inside the test's own
    task, so this returns a factory instead of yielding a live client.
    """
    _, public_pem = keypair
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    monkeypatch.setenv("ARROWHEAD_OAUTH_ISSUER", ISSUER)
    monkeypatch.setenv("ARROWHEAD_OAUTH_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("ARROWHEAD_OAUTH_PUBLIC_KEY", public_pem)
    monkeypatch.setenv("ARROWHEAD_SERVER_PUBLIC_URL", "http://arrowhead.test")
    get_settings.cache_clear()

    from arrowhead.server import create_server

    @asynccontextmanager
    async def open_client():
        app = create_server().http_app(json_response=True, stateless_http=True)
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://arrowhead.test"
            ) as http:
                yield http

    return open_client
