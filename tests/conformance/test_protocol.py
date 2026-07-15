"""Protocol correctness over the deployed transport.

Exercises the streamable HTTP endpoint end to end, through auth, with
raw JSON-RPC payloads: lifecycle, id echoing, error envelopes, and
notification handling.
"""

import pytest

HEADERS = {"Accept": "application/json, text/event-stream"}


@pytest.fixture
def bearer(issue_token):
    return {**HEADERS, "Authorization": f"Bearer {issue_token()}"}


def rpc(method, params=None, id=1):
    message = {"jsonrpc": "2.0", "id": id, "method": method}
    if params is not None:
        message["params"] = params
    return message


async def test_initialize_lifecycle(auth_client, bearer):
    request = rpc(
        "initialize",
        {
            "protocolVersion": "2025-06-18",
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
    assert result["protocolVersion"]
    assert result["serverInfo"]["name"] == "arrowhead"
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
    initialize on this connection must succeed."""
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
