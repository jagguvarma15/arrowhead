import json

import pytest
from fastmcp.exceptions import ToolError

from arrowhead.authz.enforce import get_authorizer
from arrowhead.config import get_settings
from arrowhead.tools.doc_scan import doc_scan


async def test_scan_reports_redacted_findings(docs):
    (docs / "config.json").write_text('{"api_key": "AKIAIOSFODNN7EXAMPLE"}')
    result = await doc_scan()
    assert result["finding_count"] >= 1
    assert result["files_scanned"] == 1
    assert all(f["match"].startswith("[REDACTED:") for f in result["findings"])


async def test_scan_never_returns_raw_value(docs):
    secret = "AKIAIOSFODNN7EXAMPLE"
    (docs / "leak.txt").write_text(f"aws key {secret}")
    result = await doc_scan()
    assert secret not in json.dumps(result)


async def test_scan_respects_path_prefix(docs):
    (docs / "public").mkdir()
    (docs / "public" / "a.txt").write_text("alice@example.com")
    (docs / "other.txt").write_text("bob@example.com")
    result = await doc_scan("public/")
    paths = {f["path"] for f in result["findings"]}
    assert paths == {"public/a.txt"}


async def test_scan_skips_oversized_files(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_SCAN_PER_FILE_MAX_BYTES", "8")
    get_settings.cache_clear()
    (docs / "big.txt").write_text("alice@example.com is here and this is long")
    result = await doc_scan()
    assert result["files_scanned"] == 0


async def test_scan_bounds_findings(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_SCAN_MAX_FINDINGS", "3")
    get_settings.cache_clear()
    (docs / "many.txt").write_text("\n".join("a@b.com" for _ in range(20)))
    result = await doc_scan()
    assert result["finding_count"] == 3
    assert result["truncated"] is True


async def test_scan_traversal_prefix_rejected(docs):
    with pytest.raises(ToolError):
        await doc_scan("../../etc")


async def test_scan_filters_unauthorized_documents(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    monkeypatch.setenv(
        "ARROWHEAD_AUTHZ_POLICY",
        '{"grants": [{"subject": "*", "actions": ["scan"], "prefix": "public/"}]}',
    )
    get_settings.cache_clear()
    get_authorizer.cache_clear()
    (docs / "public").mkdir()
    (docs / "public" / "a.txt").write_text("alice@example.com")
    (docs / "secret.txt").write_text("bob@example.com")
    result = await doc_scan()
    paths = {f["path"] for f in result["findings"]}
    assert paths == {"public/a.txt"}
