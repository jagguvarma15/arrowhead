import pytest

from arrowhead.auth.oauth import build_auth_provider
from arrowhead.config import Settings

ISSUER = "https://idp.test"

CALL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "calculate", "arguments": {"expression": "2 * (3 + 4)"}},
}
HEADERS = {"Accept": "application/json, text/event-stream"}


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
