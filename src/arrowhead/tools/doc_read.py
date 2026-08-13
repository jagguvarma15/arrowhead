"""Read a document from the corpus, format-aware and hardened.

Validates the path, authorizes the read against the per-resource policy,
then reads the document from the jailed store and returns it sanitized for
its format and wrapped in provenance so the caller treats it as untrusted
data. JSON is parsed under strict bounds and re-serialized canonically;
Markdown has HTML and exfiltration vectors removed; plain text has escapes
and invisible characters stripped.
"""

import anyio

from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import ACTION_READ, KIND_DOCUMENT, Resource
from arrowhead.config import get_settings
from arrowhead.content.json_safe import JSONSafetyError
from arrowhead.content.provenance import ProvenancedResult, wrap_content
from arrowhead.content.render import render_document
from arrowhead.content.text_safe import TextSafetyError
from arrowhead.errors import ToolError
from arrowhead.security.input_validation import ValidationError, validate_document_path
from arrowhead.store.document_store import DocumentStoreError, build_document_store


async def doc_read(path: str) -> ProvenancedResult:
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

    authorize_action(ACTION_READ, Resource(kind=KIND_DOCUMENT, identifier=path))

    store = build_document_store(settings)
    try:
        data = await anyio.to_thread.run_sync(store.read_bytes, path)
        content, content_format = render_document(path, data, settings)
    except DocumentStoreError as exc:
        raise ToolError(str(exc)) from exc
    except (JSONSafetyError, TextSafetyError) as exc:
        raise ToolError(str(exc)) from exc

    return wrap_content(
        content,
        source=path,
        content_format=content_format,
    )
