"""Document corpus resources.

Two resources expose the same corpus the doc_* tools operate on:

    doc://{path}   one document, read and sanitized for its format
    docs://index   the list of documents the caller is authorized to read

Both authorize per resource before returning anything, and the document read
runs through the shared renderer, so the content is sanitized identically to a
doc_read tool call. A resource read is untrusted data by definition, so no
provenance envelope is added; the sanitizers are what make it safe to hand to
a model.
"""

import json

import anyio
from fastmcp.exceptions import ToolError

from arrowhead.authz.enforce import authorize_action, get_authorizer
from arrowhead.authz.policy import (
    ACTION_READ,
    ACTION_SEARCH,
    KIND_DOCUMENT,
    KIND_PREFIX,
    Resource,
)
from arrowhead.config import get_settings
from arrowhead.content.json_safe import JSONSafetyError
from arrowhead.content.render import render_document
from arrowhead.content.text_safe import TextSafetyError
from arrowhead.security.input_validation import ValidationError, validate_document_path
from arrowhead.store.document_store import DocumentStoreError, build_document_store


async def read_document_resource(path: str) -> str:
    """Read one corpus document as sanitized text, authorized per document."""
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
        content, _ = render_document(path, data, settings)
    except DocumentStoreError as exc:
        raise ToolError(str(exc)) from exc
    except (JSONSafetyError, TextSafetyError) as exc:
        raise ToolError(str(exc)) from exc
    return content


async def corpus_index() -> str:
    """Return, as JSON, the documents the caller is authorized to read."""
    settings = get_settings()
    subject = authorize_action(
        ACTION_SEARCH, Resource(kind=KIND_PREFIX, identifier="")
    )
    return await anyio.to_thread.run_sync(_build_index, subject, settings)


def _build_index(subject, settings) -> str:
    store = build_document_store(settings)
    authorizer = get_authorizer()
    listing = store.list(
        extensions=settings.doc_allowed_extension_set(),
        max_files=settings.search_max_files,
    )
    entries = [
        {"uri": f"doc://{info.path}", "size": info.size, "extension": info.extension}
        for info in listing.items
        if authorizer.authorize(
            subject, ACTION_READ, Resource(kind=KIND_DOCUMENT, identifier=info.path)
        ).allowed
    ]
    return json.dumps(
        {"documents": entries, "count": len(entries), "truncated": listing.truncated},
        ensure_ascii=False,
        sort_keys=True,
    )
