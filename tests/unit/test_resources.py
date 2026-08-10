import json

import pytest
from fastmcp.exceptions import ToolError

from arrowhead.authz.enforce import get_authorizer
from arrowhead.config import get_settings
from arrowhead.resources.documents import corpus_index, read_document_resource


async def test_reads_and_sanitizes_a_document(docs):
    (docs / "a.md").write_text("keep\x1b[31mred\x1b[0m ![x](http://evil/?s=1)")
    out = await read_document_resource("a.md")
    assert "\x1b" not in out
    assert "evil" not in out
    assert out.startswith("keepred")


async def test_json_document_is_canonicalized(docs):
    (docs / "d.json").write_text('{"b": 2, "a": 1}')
    out = await read_document_resource("d.json")
    assert json.loads(out) == {"a": 1, "b": 2}


async def test_index_lists_documents(docs):
    (docs / "a.txt").write_text("hi")
    (docs / "sub").mkdir()
    (docs / "sub" / "b.json").write_text("{}")
    index = json.loads(await corpus_index())
    uris = {d["uri"] for d in index["documents"]}
    assert uris == {"doc://a.txt", "doc://sub/b.json"}
    assert index["count"] == 2


async def test_traversal_rejected(docs):
    with pytest.raises(ToolError):
        await read_document_resource("../../etc/passwd")


async def test_unauthorized_document_denied(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    monkeypatch.setenv(
        "ARROWHEAD_AUTHZ_POLICY",
        '{"grants": [{"subject": "*", "actions": ["read", "search"], '
        '"prefix": "ok/"}]}',
    )
    get_settings.cache_clear()
    get_authorizer.cache_clear()
    (docs / "ok").mkdir()
    (docs / "ok" / "f.txt").write_text("allowed")
    (docs / "secret.txt").write_text("denied")
    assert await read_document_resource("ok/f.txt") == "allowed"
    with pytest.raises(ToolError):
        await read_document_resource("secret.txt")


async def test_index_is_authorization_filtered(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    monkeypatch.setenv(
        "ARROWHEAD_AUTHZ_POLICY",
        '{"grants": [{"subject": "*", "actions": ["read", "search"], '
        '"prefix": "ok/"}]}',
    )
    get_settings.cache_clear()
    get_authorizer.cache_clear()
    (docs / "ok").mkdir()
    (docs / "ok" / "f.txt").write_text("allowed")
    (docs / "secret.txt").write_text("denied")
    index = json.loads(await corpus_index())
    assert {d["uri"] for d in index["documents"]} == {"doc://ok/f.txt"}
