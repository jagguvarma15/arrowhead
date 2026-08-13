"""The repo tools end to end through their guard-facing behavior."""

import pytest

from arrowhead.config import get_settings
from arrowhead.errors import ToolError
from arrowhead.tools.code_read import code_read
from arrowhead.tools.code_search import code_search
from arrowhead.tools.dependency_graph import dependency_graph
from arrowhead.tools.symbol_map import symbol_map


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_REPO_ROOT", str(tmp_path))
    get_settings.cache_clear()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "import json\n\n\ndef serve():\n    return json.dumps({})\n"
    )
    (tmp_path / "README.md").write_text("Run serve() to start.\n")
    return tmp_path


async def test_code_search_finds_and_frames_matches(repo):
    result = await code_search("serve")
    assert result["match_count"] >= 2
    paths = {match["path"] for match in result["matches"]}
    assert {"src/app.py", "README.md"} <= paths
    assert "untrusted" in result["notice"]


async def test_code_search_rejects_bad_input(repo):
    with pytest.raises(ToolError):
        await code_search("")
    with pytest.raises(ToolError):
        await code_search("serve", path_prefix="../outside")
    with pytest.raises(ToolError, match="regex"):
        await code_search("serve", use_regex=True)


async def test_code_read_slices_lines_with_provenance(repo):
    result = await code_read("src/app.py", start_line=4, end_line=5)
    assert "def serve():" in result["content"]
    assert "import json" not in result["content"]
    assert result["metadata"]["source"] == "src/app.py:4-5"


async def test_code_read_refuses_bad_ranges_and_paths(repo):
    with pytest.raises(ToolError):
        await code_read("src/app.py", start_line=0)
    with pytest.raises(ToolError):
        await code_read("src/app.py", start_line=5, end_line=2)
    with pytest.raises(ToolError):
        await code_read("../etc/passwd")
    with pytest.raises(ToolError, match="extension"):
        await code_read("binary.exe")


async def test_symbol_map_lists_definitions(repo):
    result = await symbol_map("src/")
    names = {symbol["name"] for symbol in result["symbols"]}
    assert "serve" in names
    assert result["file_count"] == 1
    assert result["truncated"] is False


async def test_dependency_graph_reports_edges(repo):
    result = await dependency_graph()
    pairs = {(edge["source"], edge["target"]) for edge in result["edges"]}
    assert ("src.app", "json") in pairs
    assert result["edge_count"] == len(result["edges"])


async def test_repo_grants_are_separate_from_document_grants(repo, monkeypatch):
    """A policy granting only document access denies the repo tools."""
    from arrowhead.authz.enforce import get_authorizer

    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    monkeypatch.setenv(
        "ARROWHEAD_AUTHZ_POLICY",
        '{"grants": [{"subject": "*", "actions": ["read", "search"], '
        '"prefix": "", "kinds": ["document", "prefix"]}]}',
    )
    get_settings.cache_clear()
    get_authorizer.cache_clear()
    with pytest.raises(ToolError, match="not authorized"):
        await code_read("src/app.py")
    with pytest.raises(ToolError, match="not authorized"):
        await code_search("serve")
    get_authorizer.cache_clear()
