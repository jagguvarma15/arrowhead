"""The context packer: budget, ordering, redaction, provenance, and safety."""

import hashlib

import pytest

from arrowhead.config import get_settings
from arrowhead.errors import ToolError
from arrowhead.tools.pack_context import pack_context
from arrowhead.tools.workingset import workingset_update


@pytest.fixture
def corpus(tmp_path, monkeypatch):
    docs = tmp_path / "docs"
    repo = tmp_path / "repo"
    docs.mkdir()
    repo.mkdir()
    (docs / "refunds.md").write_text(
        "Refunds are issued within five business days of approval."
    )
    (repo / "config.py").write_text(
        "aws_key = 'AKIAIOSFODNN7EXAMPLE'\nTIMEOUT = 30\n"
    )
    monkeypatch.setenv("ARROWHEAD_DOCS_ROOT", str(docs))
    monkeypatch.setenv("ARROWHEAD_REPO_ROOT", str(repo))
    get_settings.cache_clear()
    return docs, repo


async def test_retrieved_snippets_are_framed_and_stamped(corpus):
    result = await pack_context("refunds")
    assert result["snippets"]
    snippet = result["snippets"][0]
    lines = snippet["content"].splitlines()
    assert lines[0].startswith("<<UNTRUSTED-")
    assert lines[-1].startswith("<<END-UNTRUSTED-")
    assert snippet["source"] == "refunds.md"
    assert snippet["kind"] == "retrieved:doc"
    assert "untrusted" in result["notice"]


async def test_pinned_items_come_first(corpus):
    await workingset_update(
        "ws", "pin", items=[{"kind": "repo_file", "identifier": "config.py"}]
    )
    result = await pack_context("refunds", working_set="ws")
    assert result["snippets"][0]["kind"].startswith("pinned:")


async def test_planted_secret_is_redacted(corpus):
    await workingset_update(
        "ws", "pin", items=[{"kind": "repo_file", "identifier": "config.py"}]
    )
    result = await pack_context("refunds", working_set="ws")
    combined = "\n".join(s["content"] for s in result["snippets"])
    assert "AKIAIOSFODNN7EXAMPLE" not in combined
    assert "[REDACTED:AWS_ACCESS_KEY" in combined
    assert result["redactions"] >= 1


async def test_provenance_hash_matches_the_redacted_content(corpus):
    await workingset_update(
        "ws", "pin", items=[{"kind": "repo_file", "identifier": "config.py"}]
    )
    result = await pack_context("refunds", working_set="ws")
    pinned = next(s for s in result["snippets"] if s["kind"].startswith("pinned"))
    inner = pinned["content"].split("\n", 1)[1].rsplit("\n", 1)[0]
    assert pinned["sha256"] == hashlib.sha256(inner.encode("utf-8")).hexdigest()


async def test_budget_is_never_exceeded(corpus, monkeypatch):
    # A tiny budget packs at most what fits and flags truncation.
    result = await pack_context("refunds", token_budget=2)
    assert result["token_estimate"] <= 2
    assert result["truncated"] is True


async def test_unauthorized_pinned_item_is_skipped_not_leaked(
    corpus, monkeypatch
):
    from arrowhead.authz.enforce import get_authorizer

    # Pin the repo file while unauthenticated (allow-all), then turn auth on
    # with a policy that denies repo reads: the pack must skip it silently.
    await workingset_update(
        "ws", "pin", items=[{"kind": "repo_file", "identifier": "config.py"}]
    )
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    monkeypatch.setenv(
        "ARROWHEAD_AUTHZ_POLICY",
        '{"grants": [{"subject": "*", "actions": ["read", "search"], '
        '"prefix": "", "kinds": ["document", "prefix"]}]}',
    )
    get_settings.cache_clear()
    get_authorizer.cache_clear()
    result = await pack_context("refunds", working_set="ws")
    combined = "\n".join(s["content"] for s in result["snippets"])
    assert "AKIAIOSFODNN7EXAMPLE" not in combined
    assert not any(s["kind"].startswith("pinned") for s in result["snippets"])
    get_authorizer.cache_clear()


async def test_bad_query_is_refused(corpus):
    with pytest.raises(ToolError):
        await pack_context("")
    with pytest.raises(ToolError):
        await pack_context("refunds", token_budget=0)
