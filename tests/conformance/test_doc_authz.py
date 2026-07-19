"""Document-tool authorization over the HTTP transport.

Drives the streamable endpoint with tokens carrying different scopes to
confirm scope-by-verb is enforced: a tool the caller lacks the scope for
is invisible (reported as unknown), and the correctly scoped call runs.
"""

import pytest

HEADERS = {"Accept": "application/json, text/event-stream"}


def call(name, arguments, id=1):
    return {
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


@pytest.fixture
def permissive_docs(tmp_path, monkeypatch):
    """A corpus with an all-permissive resource policy, so these tests
    isolate scope enforcement from per-resource authorization."""
    monkeypatch.setenv("ARROWHEAD_DOCS_ROOT", str(tmp_path))
    monkeypatch.setenv(
        "ARROWHEAD_AUTHZ_POLICY",
        '{"grants": [{"subject": "*", '
        '"actions": ["read", "write", "search", "scan"], "prefix": ""}]}',
    )
    from arrowhead.authz.enforce import get_authorizer
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    get_authorizer.cache_clear()
    return tmp_path


def bearer(issue_token, scope):
    return {**HEADERS, "Authorization": f"Bearer {issue_token(scope=scope)}"}


async def test_write_hidden_without_write_scope(
    auth_client, issue_token, permissive_docs
):
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json=call("doc_write", {"path": "a.txt", "content": "x"}),
            headers=bearer(issue_token, "docs:read"),
        )
    result = response.json()["result"]
    assert result["isError"] is True
    assert "Unknown tool" in result["content"][0]["text"]


async def test_write_scope_permits_write(
    auth_client, issue_token, permissive_docs
):
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json=call("doc_write", {"path": "a.txt", "content": "hello"}),
            headers=bearer(issue_token, "docs:write"),
        )
    result = response.json()["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["created"] is True


async def test_read_scope_permits_read(
    auth_client, issue_token, permissive_docs
):
    (permissive_docs / "a.txt").write_text("content here")
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json=call("doc_read", {"path": "a.txt"}),
            headers=bearer(issue_token, "docs:read"),
        )
    result = response.json()["result"]
    assert result["isError"] is False
    assert "content here" in result["structuredContent"]["content"]


async def test_search_scope_cannot_write(
    auth_client, issue_token, permissive_docs
):
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json=call("doc_write", {"path": "a.txt", "content": "x"}),
            headers=bearer(issue_token, "docs:search"),
        )
    result = response.json()["result"]
    assert result["isError"] is True
    assert "Unknown tool" in result["content"][0]["text"]
