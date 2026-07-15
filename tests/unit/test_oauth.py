import time
from contextlib import asynccontextmanager

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from arrowhead.auth.oauth import build_auth_provider
from arrowhead.config import Settings, get_settings

ISSUER = "https://idp.test"
AUDIENCE = "https://arrowhead.test"

CALL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "calculate", "arguments": {"expression": "2 * (3 + 4)"}},
}
HEADERS = {"Accept": "application/json, text/event-stream"}


@pytest.fixture(scope="module")
def keypair():
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

    def issue(audience=AUDIENCE, scope="tools:read", issuer=ISSUER):
        now = int(time.time())
        claims = {
            "iss": issuer,
            "aud": audience,
            "sub": "user-1",
            "iat": now,
            "exp": now + 600,
            "scope": scope,
        }
        return jwt.encode(claims, private_pem, algorithm="RS256")

    return issue


@pytest.fixture
def auth_client(keypair, monkeypatch):
    """Context-manager factory for an HTTP client against an authed app.

    The lifespan must be entered and exited inside the test's own task,
    so this returns a factory instead of yielding a live client.
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


async def test_request_without_token_is_401(auth_client):
    async with auth_client() as client:
        response = await client.post("/mcp", json=CALL, headers=HEADERS)
        assert response.status_code == 401


async def test_wrong_audience_is_401_even_with_valid_signature(
    auth_client, issue_token
):
    token = issue_token(audience="https://other-service.test")
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json=CALL,
            headers={**HEADERS, "Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 401


async def test_garbage_token_is_401(auth_client):
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json=CALL,
            headers={**HEADERS, "Authorization": "Bearer not-a-jwt"},
        )
        assert response.status_code == 401


async def test_token_without_required_scope_cannot_see_tool(
    auth_client, issue_token
):
    token = issue_token(scope="something:else")
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json=CALL,
            headers={**HEADERS, "Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        result = response.json()["result"]
        assert result["isError"] is True
        assert "Unknown tool" in result["content"][0]["text"]


async def test_valid_scoped_token_executes_tool(auth_client, issue_token):
    token = issue_token()
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json=CALL,
            headers={**HEADERS, "Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        result = response.json()["result"]
        assert result["isError"] is False
        assert result["structuredContent"]["result"] == 14.0


async def test_protected_resource_metadata_is_served(auth_client):
    async with auth_client() as client:
        response = await client.get("/.well-known/oauth-protected-resource/mcp")
        assert response.status_code == 200
        metadata = response.json()
        assert metadata["resource"] == "http://arrowhead.test/mcp"
        assert metadata["authorization_servers"] == [f"{ISSUER}/"]
        assert "tools:read" in metadata["scopes_supported"]


def test_auth_disabled_returns_no_provider():
    assert build_auth_provider(Settings(auth_enabled=False)) is None


def test_incomplete_auth_config_is_rejected():
    with pytest.raises(ValueError, match="ARROWHEAD_OAUTH_AUDIENCE"):
        build_auth_provider(
            Settings(
                auth_enabled=True,
                oauth_issuer=ISSUER,
                oauth_jwks_uri="https://idp.test/jwks",
                server_public_url="http://arrowhead.test",
            )
        )
