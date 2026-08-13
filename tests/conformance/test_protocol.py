"""Protocol correctness over the deployed transport.

Exercises the streamable HTTP endpoint end to end, through auth, with
raw JSON-RPC payloads. One endpoint serves both protocol eras: a
handshake-era client runs the initialize lifecycle, and a current-protocol
client sends bare requests carrying the reserved _meta envelope. Both
legs are pinned here.
"""

import pytest
from mcp_types.version import LATEST_HANDSHAKE_VERSION, LATEST_MODERN_VERSION

HEADERS = {"Accept": "application/json, text/event-stream"}

# The reserved keys a sessionless request carries in place of a handshake.
MODERN_ENVELOPE = {
    "io.modelcontextprotocol/protocolVersion": LATEST_MODERN_VERSION,
    "io.modelcontextprotocol/clientCapabilities": {},
}


@pytest.fixture
def bearer(issue_token):
    return {**HEADERS, "Authorization": f"Bearer {issue_token()}"}


def rpc(method, params=None, id=1):
    message = {"jsonrpc": "2.0", "id": id, "method": method}
    if params is not None:
        message["params"] = params
    return message


def modern(method, params, id=1):
    return rpc(method, {**params, "_meta": MODERN_ENVELOPE}, id=id)


async def test_initialize_lifecycle(auth_client, bearer):
    from arrowhead import __version__

    request = rpc(
        "initialize",
        {
            "protocolVersion": LATEST_MODERN_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "conformance", "version": "0"},
        },
        id=7,
    )
    async with auth_client() as client:
        response = await client.post("/mcp", json=request, headers=bearer)
    assert response.status_code == 200
    body = response.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 7
    result = body["result"]
    # The initialize lifecycle is the handshake era's; a client asking for
    # the sessionless revision through it is negotiated down to the latest
    # handshake version, and reaches the modern leg by sending bare
    # requests instead.
    assert result["protocolVersion"] == LATEST_HANDSHAKE_VERSION
    assert result["serverInfo"]["name"] == "arrowhead"
    # serverInfo carries the real package version, not a stale constant.
    assert result["serverInfo"]["version"] == __version__
    assert "tools" in result["capabilities"]


async def test_request_ids_are_echoed_verbatim(auth_client, bearer):
    request = rpc(
        "tools/call",
        {"name": "calculate", "arguments": {"expression": "1 + 1"}},
        id="abc-123",
    )
    async with auth_client() as client:
        response = await client.post("/mcp", json=request, headers=bearer)
    assert response.json()["id"] == "abc-123"


async def test_unknown_method_returns_jsonrpc_error(auth_client, bearer):
    async with auth_client() as client:
        response = await client.post(
            "/mcp", json=rpc("bogus/method", {}, id=8), headers=bearer
        )
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == 8
    assert body["error"]["code"] in (-32601, -32602)
    assert "result" not in body


async def test_request_without_method_is_invalid(auth_client, bearer):
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 9, "params": {}},
            headers=bearer,
        )
    assert response.status_code == 400
    assert "error" in response.json()


async def test_malformed_json_is_a_parse_error(auth_client, bearer):
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            content=b"{not json",
            headers={**bearer, "Content-Type": "application/json"},
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == -32700


async def test_unknown_tool_is_a_tool_level_error(auth_client, bearer):
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json=rpc("tools/call", {"name": "nope", "arguments": {}}, id=10),
            headers=bearer,
        )
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["isError"] is True


async def test_missing_required_argument_is_reported(auth_client, bearer):
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json=rpc("tools/call", {"name": "calculate", "arguments": {}}, id=11),
            headers=bearer,
        )
    result = response.json()["result"]
    assert result["isError"] is True
    assert "expression" in result["content"][0]["text"]


async def test_wrongly_typed_argument_is_reported(auth_client, bearer):
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json=rpc(
                "tools/call",
                {"name": "calculate", "arguments": {"expression": 42}},
                id=12,
            ),
            headers=bearer,
        )
    result = response.json()["result"]
    assert result["isError"] is True
    assert "string" in result["content"][0]["text"]


async def test_notifications_are_accepted_without_a_response(
    auth_client, bearer
):
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=bearer,
        )
    assert response.status_code == 202
    assert response.content == b""


async def test_stateless_requests_need_no_session_handshake(
    auth_client, bearer
):
    """Any replica can serve any request: a bare tools/call with no prior
    initialize on this connection must succeed on the handshake leg."""
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json=rpc(
                "tools/call",
                {"name": "calculate", "arguments": {"expression": "2 + 3"}},
                id=13,
            ),
            headers=bearer,
        )
    assert response.status_code == 200
    assert response.json()["result"]["structuredContent"]["result"] == 5.0


async def test_modern_leg_serves_bare_enveloped_requests(auth_client, bearer):
    """A sessionless client sends no initialize at all: the reserved _meta
    envelope names the revision and capabilities on every request."""
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json=modern(
                "tools/call",
                {"name": "calculate", "arguments": {"expression": "2 + 3"}},
                id="modern-1",
            ),
            headers=bearer,
        )
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "modern-1"
    assert body["result"]["structuredContent"]["result"] == 5.0


async def test_modern_leg_requires_the_envelope(auth_client, bearer):
    """Declaring the modern revision without the envelope is an invalid
    request, not a silent downgrade."""
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json=rpc(
                "tools/call",
                {"name": "calculate", "arguments": {"expression": "2 + 3"}},
                id=14,
            ),
            headers={
                **bearer,
                "MCP-Protocol-Version": LATEST_MODERN_VERSION,
            },
        )
    body = response.json()
    assert body["error"]["code"] == -32602
    assert "_meta" in body["error"]["message"]


async def test_modern_listing_is_scope_filtered_like_the_legacy_leg(
    auth_client, issue_token
):
    """Both eras see the same visibility rules: a caller holding only
    tools:read lists only the unscoped utility tools."""
    token = issue_token(scope="tools:read")
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json=modern("tools/list", {}, id=15),
            headers={**HEADERS, "Authorization": f"Bearer {token}"},
        )
    names = {
        tool["name"] for tool in response.json()["result"]["tools"]
    }
    assert names == {"safe_fetch", "calculate", "read_file"}
