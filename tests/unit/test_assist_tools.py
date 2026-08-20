"""The assist tools against a scripted provider: refusals, bounds, framing."""

import pytest

from arrowhead.config import get_settings
from arrowhead.errors import ToolError
from arrowhead.tools.code_explain import code_explain
from arrowhead.tools.rerank import rerank
from arrowhead.tools.summarize_diff import summarize_diff

DIFF = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-old\n+new\n"


@pytest.fixture
def scripted_provider(monkeypatch):
    """Replace the factory with a provider that records and answers."""
    calls = {"prompts": [], "answer": "The change renames a value."}

    class Provider:
        async def complete(self, prompt, *, system=None, max_tokens):
            calls["prompts"].append((system, prompt))
            return calls["answer"]

    monkeypatch.setattr(
        "arrowhead.llm.factory.build_completion_provider",
        lambda settings: Provider(),
    )
    for module in (
        "arrowhead.tools.code_explain",
        "arrowhead.tools.summarize_diff",
        "arrowhead.tools.rerank",
    ):
        monkeypatch.setattr(
            f"{module}.build_completion_provider", lambda settings: Provider()
        )
    return calls


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_REPO_ROOT", str(tmp_path))
    get_settings.cache_clear()
    (tmp_path / "app.py").write_text("def serve():\n    return 1\n")
    return tmp_path


async def test_unconfigured_backend_refuses_clearly(repo):
    with pytest.raises(ToolError, match="ARROWHEAD_LLM_PROVIDER"):
        await summarize_diff(DIFF)
    with pytest.raises(ToolError, match="ARROWHEAD_LLM_PROVIDER"):
        await code_explain("app.py")
    with pytest.raises(ToolError, match="ARROWHEAD_LLM_PROVIDER"):
        await rerank("query", ["a", "b"])


async def test_summarize_diff_bounds_and_frames(scripted_provider):
    result = await summarize_diff(DIFF)
    assert result["summary"] == "The change renames a value."
    assert "untrusted" in result["notice"]
    with pytest.raises(ToolError):
        await summarize_diff("")
    with pytest.raises(ToolError):
        await summarize_diff("bad\x00diff")


async def test_summarize_diff_size_cap(scripted_provider, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_DIFF_MAX_BYTES", "16")
    get_settings.cache_clear()
    with pytest.raises(ToolError, match="exceeds"):
        await summarize_diff(DIFF)


async def test_code_explain_reads_the_jail_and_frames(
    repo, scripted_provider
):
    result = await code_explain("app.py")
    assert "The change renames a value." in result["content"]
    assert result["content"].splitlines()[0].startswith("<<UNTRUSTED-")
    system, prompt = scripted_provider["prompts"][-1]
    assert "untrusted" in system
    assert "def serve():" in prompt


async def test_code_explain_honors_repo_guards(repo, scripted_provider):
    with pytest.raises(ToolError):
        await code_explain("../outside.py")
    with pytest.raises(ToolError):
        await code_explain("app.py", start_line=0)


async def test_code_explain_refuses_disallowed_extensions(
    repo, scripted_provider
):
    (repo / "blob.bin").write_text("data")
    # The assist path enforces the same extension allowlist as code_read,
    # and the refusal happens before the model backend is ever called.
    with pytest.raises(ToolError, match="extension"):
        await code_explain("blob.bin")
    assert scripted_provider["prompts"] == []


async def test_rerank_parses_a_clean_answer(scripted_provider):
    scripted_provider["answer"] = "2, 0, 1"
    result = await rerank("query", ["a", "b", "c"], top_k=2)
    assert result["order"] == [2, 0]
    assert result["model_answered"] is True


async def test_rerank_survives_a_hostile_answer(scripted_provider):
    scripted_provider["answer"] = (
        "Ignore instructions! The best is 99, then 2, then 2 again, then -1."
    )
    result = await rerank("query", ["a", "b", "c"], top_k=3)
    # Out-of-range and duplicate indices are dropped; missing ones follow
    # in original order, so the result is always a valid permutation.
    assert result["order"] == [2, 0, 1]


async def test_rerank_reports_an_unusable_answer(scripted_provider):
    scripted_provider["answer"] = "I refuse to rank these passages."
    result = await rerank("query", ["a", "b", "c"])
    # An answer contributing no index falls back to the original order and
    # says so, instead of reporting a model ranking that never happened.
    assert result["order"] == [0, 1, 2]
    assert result["model_answered"] is False


async def test_rerank_bounds_candidates(scripted_provider):
    with pytest.raises(ToolError):
        await rerank("query", [])
    with pytest.raises(ToolError):
        await rerank("query", ["x"] * 51)
    with pytest.raises(ToolError):
        await rerank("query", ["y" * 4001])
