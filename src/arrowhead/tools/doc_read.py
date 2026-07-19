"""Read a document from the corpus, format-aware and hardened.

Validates the path, authorizes the read against the per-resource policy,
then reads the document from the jailed store and returns it sanitized for
its format and wrapped in provenance so the caller treats it as untrusted
data. JSON is parsed under strict bounds and re-serialized canonically;
Markdown has HTML and exfiltration vectors removed; plain text has escapes
and invisible characters stripped.
"""

import json
from datetime import UTC, datetime
from pathlib import PurePosixPath

import anyio
from fastmcp.exceptions import ToolError

from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import ACTION_READ, Resource
from arrowhead.config import get_settings
from arrowhead.content.json_safe import JSONSafetyError, parse_json
from arrowhead.content.markdown_safe import sanitize_markdown
from arrowhead.content.provenance import wrap_content
from arrowhead.content.text_safe import TextSafetyError, decode_text, sanitize_text
from arrowhead.security.input_validation import ValidationError, validate_document_path
from arrowhead.store.document_store import DocumentStoreError, build_document_store


async def doc_read(path: str) -> dict:
    """Read a JSON, Markdown, or text document from the corpus by relative
    path. Returns sanitized content wrapped with provenance. Example:
    doc_read(path="notes/todo.md").
    """
    settings = get_settings()
    try:
        validate_document_path(
            path, allowed_extensions=settings.doc_allowed_extension_set()
        )
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc

    authorize_action(ACTION_READ, Resource(kind="document", identifier=path))

    store = build_document_store(settings)
    try:
        data = await anyio.to_thread.run_sync(store.read_bytes, path)
        content, content_format = _render(path, data, settings)
    except DocumentStoreError as exc:
        raise ToolError(str(exc)) from exc
    except (JSONSafetyError, TextSafetyError) as exc:
        raise ToolError(str(exc)) from exc

    return wrap_content(
        content,
        source=path,
        content_format=content_format,
        retrieved_at=datetime.now(UTC).isoformat(),
    )


def _render(path: str, data: bytes, settings) -> tuple[str, str]:
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
