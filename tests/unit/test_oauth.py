import pytest

from arrowhead.auth.oauth import build_auth
from arrowhead.auth.verifier import JWKSTokenVerifier
from arrowhead.config import Settings

ISSUER = "https://idp.test"

CALL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "calculate", "arguments": {"expression": "2 * (3 + 4)"}},
}
HEADERS = {"Accept": "application/json, text/event-stream"}


def _kid_token(kid="key-1"):
    import jwt

    # A 32-byte key keeps jwt from emitting the short-key warning the suite
    # promotes to an error; the signature is never verified here anyway.
    return jwt.encode(
        {"sub": "u"}, "k" * 32, algorithm="HS256", headers={"kid": kid}
    )


def _outage_verifier():
    import httpx

    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(503)

    verifier = JWKSTokenVerifier(
        issuer=ISSUER,
        audience="https://arrowhead.test",
        jwks_uri="https://idp.test/jwks",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        cache_ttl_seconds=300.0,
    )
    return verifier, calls


async def test_failed_jwks_refresh_is_bounded_per_window():
    # An issuer outage must not turn a stream of tokens into a stream of JWKS
    # fetches: the window advances even when the refresh fails.
    verifier, calls = _outage_verifier()
    token = _kid_token()
    for _ in range(5):
        assert await verifier.verify_token(token) is None
    assert calls["n"] <= 2


async def test_concurrent_jwks_refresh_is_single_flight():
    import asyncio

    verifier, calls = _outage_verifier()
    token = _kid_token()
    results = await asyncio.gather(
        *[verifier.verify_token(token) for _ in range(8)]
    )
    assert all(result is None for result in results)
    assert calls["n"] <= 2


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
        # The scope taxonomy is deliberately not advertised: an
        # unauthenticated probe learns nothing about the verbs this server
        # understands, matching the unknown-tool refusal for scoped calls.
        assert not metadata.get("scopes_supported")


def test_auth_disabled_returns_no_provider():
    assert build_auth(Settings(auth_enabled=False)) is None


def test_incomplete_auth_config_is_rejected():
    with pytest.raises(ValueError, match="ARROWHEAD_OAUTH_AUDIENCE"):
        build_auth(
            Settings(
                auth_enabled=True,
                oauth_issuer=ISSUER,
                oauth_jwks_uri="https://idp.test/jwks",
                server_public_url="http://arrowhead.test",
            )
        )


def test_workos_settings_become_a_jwks_verifier():
    verifier, auth_settings = build_auth(
        Settings(
            auth_enabled=True,
            oauth_provider="workos",
            oauth_authkit_domain="https://arrowhead.authkit.app",
            server_public_url="https://arrowhead.example.com",
        )
    )
    assert isinstance(verifier, JWKSTokenVerifier)
    assert verifier._issuer == "https://arrowhead.authkit.app"
    assert verifier._jwks_uri == "https://arrowhead.authkit.app/oauth2/jwks"
    assert str(auth_settings.issuer_url).rstrip("/") == (
        "https://arrowhead.authkit.app"
    )
    assert (
        str(auth_settings.resource_server_url)
        == "https://arrowhead.example.com/mcp"
    )


def test_incomplete_workos_config_is_rejected():
    with pytest.raises(ValueError, match="ARROWHEAD_OAUTH_AUTHKIT_DOMAIN"):
        build_auth(
            Settings(
                auth_enabled=True,
                oauth_provider="workos",
                server_public_url="https://arrowhead.example.com",
            )
        )
