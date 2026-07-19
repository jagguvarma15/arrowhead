"""Real JWKS verification path.

The other auth tests inject a static public key. These exercise the
production path where the verifier fetches a JWKS document from the issuer
and validates a token against it, using an injected HTTP client so the
JWKS is served in-process. This covers key discovery, key rotation (an
unknown key id is rejected), and that audience validation still holds when
the signature comes from a JWKS.
"""

import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastmcp import FastMCP

from arrowhead.auth.oauth import build_auth_provider
from arrowhead.config import get_settings
from arrowhead.tools.registry import register_tools

ISSUER = "https://idp.test"
AUDIENCE = "https://arrowhead.test"
JWKS_URI = "https://idp.test/jwks"
HEADERS = {"Accept": "application/json, text/event-stream"}

CALCULATE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "calculate", "arguments": {"expression": "2 + 3"}},
}


def jwk_for(public_pem: str, kid: str) -> dict:
    public_key = load_pem_public_key(public_pem.encode())
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return jwk


def jwks_client(public_pem: str, kid: str) -> httpx.AsyncClient:
    document = {"keys": [jwk_for(public_pem, kid)]}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/jwks":
            return httpx.Response(200, json=document)
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def sign(private_pem: str, kid: str, *, scope="tools:read", audience=AUDIENCE):
    now = int(time.time())
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": audience,
            "sub": "user-1",
            "iat": now,
            "exp": now + 600,
            "scope": scope,
        },
        private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )


@pytest.fixture
def jwks_app(keypair, monkeypatch):
    """Build the arrowhead app verifying against an in-process JWKS."""
    private_pem, public_pem = keypair
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    monkeypatch.setenv("ARROWHEAD_OAUTH_ISSUER", ISSUER)
    monkeypatch.setenv("ARROWHEAD_OAUTH_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("ARROWHEAD_OAUTH_JWKS_URI", JWKS_URI)
    monkeypatch.setenv("ARROWHEAD_SERVER_PUBLIC_URL", "http://arrowhead.test")
    get_settings.cache_clear()

    def build(served_kid: str):
        provider = build_auth_provider(
            get_settings(), http_client=jwks_client(public_pem, served_kid)
        )
        mcp = FastMCP("jwks-test", auth=provider)
        register_tools(mcp, enforce_scopes=True)
        return mcp.http_app(json_response=True, stateless_http=True)

    return build


async def drive(app, request, headers):
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://arrowhead.test"
        ) as client:
            return await client.post("/mcp", json=request, headers=headers)


async def test_no_token_is_401_with_discovery_metadata(jwks_app):
    app = jwks_app("key-1")
    response = await drive(app, CALCULATE, HEADERS)
    assert response.status_code == 401
    assert "resource_metadata" in response.headers.get("WWW-Authenticate", "")


async def test_jwks_verified_token_runs_tool(jwks_app, keypair):
    private_pem, _ = keypair
    app = jwks_app("key-1")
    token = sign(private_pem, "key-1")
    response = await drive(
        app, CALCULATE, {**HEADERS, "Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["result"]["structuredContent"]["result"] == 5.0


async def test_unknown_key_id_is_rejected(jwks_app, keypair):
    private_pem, _ = keypair
    # The JWKS serves key-2, but the token is signed under key-1: rotation
    # away from a retired key must reject tokens that still name it.
    app = jwks_app("key-2")
    token = sign(private_pem, "key-1")
    response = await drive(
        app, CALCULATE, {**HEADERS, "Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401


async def test_wrong_audience_rejected_even_via_jwks(jwks_app, keypair):
    private_pem, _ = keypair
    app = jwks_app("key-1")
    token = sign(private_pem, "key-1", audience="https://other-service.test")
    response = await drive(
        app, CALCULATE, {**HEADERS, "Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401
