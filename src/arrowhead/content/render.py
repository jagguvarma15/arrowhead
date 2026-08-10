"""Render a corpus document to sanitized text for its format.

One rendering path shared by the doc_read tool and the document resource, so
a document is sanitized identically however it is reached: JSON is parsed
under strict bounds and re-serialized canonically, Markdown has HTML and
exfiltration vectors removed, and plain text has escapes and invisible
characters stripped. The caller decides how to frame the result (a tool
wraps it in provenance; a resource returns it as data).
"""

import json
from pathlib import PurePosixPath

from arrowhead.content.json_safe import parse_json
from arrowhead.content.markdown_safe import sanitize_markdown
from arrowhead.content.text_safe import decode_text, sanitize_text


def render_document(path: str, data: bytes, settings) -> tuple[str, str]:
    """Return (sanitized_content, format) for a document's bytes.

    Raises JSONSafetyError or TextSafetyError when the content cannot be
    decoded or bounded safely, exactly as the callers expect.
    """
    suffix = PurePosixPath(path).suffix.lower()
    if suffix == ".json":
        parsed = parse_json(
            decode_text(data),
            max_bytes=settings.content_max_bytes,
            max_depth=settings.json_max_depth,
            max_elements=settings.json_max_elements,
        )
        return json.dumps(parsed, ensure_ascii=False, sort_keys=True, indent=2), "json"
    if suffix == ".md":
        return sanitize_markdown(sanitize_text(data)), "md"
    return sanitize_text(data), "txt"
