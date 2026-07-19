"""Write a document to the corpus: jailed, atomic, and confirmed.

Validates the path and content, validates the content parses as its
format, then authorizes the write against the per-resource policy. A new
document is written with a no-clobber atomic move. Overwriting an existing
document is destructive: it requires an explicit overwrite flag and, when
the client supports it, human confirmation via elicitation. The store
writes to a temporary file and moves it into place, so a reader never sees
a partial document.
"""

import json
from pathlib import PurePosixPath

import anyio
from fastmcp import Context
from fastmcp.exceptions import ToolError

from arrowhead.authz.confirmation import CONFIRM_DECLINED, request_confirmation
from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import ACTION_WRITE, KIND_DOCUMENT, Resource
from arrowhead.config import get_settings
from arrowhead.content.json_safe import JSONSafetyError, parse_json
from arrowhead.security.input_validation import (
    ValidationError,
    validate_document_path,
    validate_write_content,
)
from arrowhead.store.document_store import DocumentStoreError, build_document_store


async def doc_write(
    path: str,
    content: str,
    overwrite: bool = False,
    ctx: Context | None = None,
) -> dict:
    """Write a JSON, Markdown, or text document to the corpus. Creates a new
    document; set overwrite to replace an existing one, which asks for
    confirmation. Example: doc_write(path="notes/todo.md", content="# Todo").
    """
    settings = get_settings()
    try:
        validate_document_path(
            path, allowed_extensions=settings.doc_allowed_extension_set()
        )
        validate_write_content(content, max_bytes=settings.doc_write_max_bytes)
        data = _encode_for_format(path, content, settings)
    except (ValidationError, JSONSafetyError) as exc:
        raise ToolError(str(exc)) from exc

    authorize_action(ACTION_WRITE, Resource(kind=KIND_DOCUMENT, identifier=path))

    store = build_document_store(settings)
    try:
        exists = await anyio.to_thread.run_sync(store.exists, path)
    except DocumentStoreError as exc:
        raise ToolError(str(exc)) from exc

    if exists:
        if not overwrite:
            raise ToolError(
                "document already exists; pass overwrite=true to replace it"
            )
        if settings.require_write_confirmation:
            outcome = await request_confirmation(
                ctx, f"Overwrite the existing document at '{path}'?"
            )
            if outcome == CONFIRM_DECLINED:
                raise ToolError("overwrite was declined")

    try:
        info = await anyio.to_thread.run_sync(
            _write, store, path, data, overwrite
        )
    except DocumentStoreError as exc:
        raise ToolError(str(exc)) from exc

    return {
        "path": info.path,
        "size": info.size,
        "extension": info.extension,
        "created": not exists,
    }


def _write(store, path, data, overwrite):
    return store.write_atomic(path, data, overwrite=overwrite)


def _encode_for_format(path: str, content: str, settings) -> bytes:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix == ".json":
        parsed = parse_json(
            content,
            max_bytes=settings.doc_write_max_bytes,
            max_depth=settings.json_max_depth,
            max_elements=settings.json_max_elements,
        )
        canonical = json.dumps(
            parsed, ensure_ascii=False, sort_keys=True, indent=2
        )
        return canonical.encode("utf-8")
    return content.encode("utf-8")
