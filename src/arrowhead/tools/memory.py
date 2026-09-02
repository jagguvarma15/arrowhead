"""Owner-scoped agent memory tools.

Memories are records an agent curates across calls: preferences, facts,
notes. Every tool resolves the owner from the verified caller identity
via the authorization step, never from an argument, and the backend keys
all storage by that owner, so no caller can reach another's memories.
Namespaces group memories within an owner (per user, per project); ids
are server-minted. Recall results are sanitized, bounded, and labeled
with the recall the backend actually performed.
"""

import json
from typing import TypedDict

from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import (
    ACTION_READ,
    ACTION_SEARCH,
    ACTION_WRITE,
    KIND_MEMORY,
    KIND_MEMORY_PREFIX,
    Resource,
)
from arrowhead.config import Settings, get_settings
from arrowhead.content.provenance import UNTRUSTED_NOTICE
from arrowhead.content.text_safe import sanitize_text
from arrowhead.errors import ToolError
from arrowhead.memory.base import MemoryBackendError, MemoryEntryNotFoundError
from arrowhead.memory.factory import build_memory_backend
from arrowhead.security.input_validation import (
    ValidationError,
    validate_memory_id,
    validate_namespace,
    validate_search_query,
    validate_write_content,
)


class MemoryStoreResult(TypedDict):
    """The stored entry's id and what the upsert did."""

    id: str
    status: str


class MemorySearchMatch(TypedDict):
    """One recalled memory: a sanitized snippet and its relevance score."""

    id: str
    snippet: str
    score: float
    metadata: dict


class MemorySearchResult(TypedDict):
    """Recall results, labeled with the search the backend performed."""

    notice: str
    recall: str
    results: list[MemorySearchMatch]


class MemoryListEntry(TypedDict):
    """One memory's metadata, without its content."""

    id: str
    size: int
    created_at: str
    updated_at: str
    metadata: dict


class MemoryListResult(TypedDict):
    """The namespace's entries, most recently updated first."""

    namespace: str
    entries: list[MemoryListEntry]


class MemoryDeleteResult(TypedDict):
    """Confirmation of one deleted memory."""

    id: str
    deleted: bool


async def memory_store(
    namespace: str,
    content: str,
    metadata: dict | None = None,
    id: str | None = None,
) -> MemoryStoreResult:
    """Store a memory in a namespace you own and return its id. Identical
    content returns the existing id unchanged; pass id to update an entry
    in place. Example: memory_store(namespace="prefs", content="prefers
    metric units").
    """
    settings = get_settings()
    try:
        validate_namespace(namespace)
        if id is not None:
            validate_memory_id(id)
        if not isinstance(content, str) or not content.strip():
            raise ValidationError("content must be a non-empty string")
        validate_write_content(
            content, max_bytes=settings.memory_max_content_bytes
        )
        meta = _validated_metadata(metadata, settings)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc

    identifier = f"{namespace}/{id}" if id else namespace
    owner = authorize_action(
        ACTION_WRITE, Resource(kind=KIND_MEMORY, identifier=identifier)
    )
    backend = _backend(settings)
    try:
        entry_id, status = await backend.store(
            owner, namespace, content, meta, id
        )
    except MemoryBackendError as exc:
        raise ToolError(str(exc)) from exc
    return {"id": entry_id, "status": status}


async def memory_search(
    namespace: str, query: str, k: int = 5
) -> MemorySearchResult:
    """Recall the memories in a namespace you own most relevant to a query.
    Recall is keyword on the file backend and semantic when an embedding
    provider is configured. Example: memory_search(namespace="prefs",
    query="units", k=5).
    """
    settings = get_settings()
    try:
        validate_namespace(namespace)
        validate_search_query(
            query, max_length=settings.search_query_max_length
        )
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc
    bounded = _bounded_k(k, settings)

    owner = authorize_action(
        ACTION_SEARCH, Resource(kind=KIND_MEMORY_PREFIX, identifier=namespace)
    )
    backend = _backend(settings)
    try:
        hits = await backend.search(owner, namespace, query, bounded)
    except MemoryBackendError as exc:
        raise ToolError(str(exc)) from exc
    limit = settings.search_snippet_max_chars
    return {
        "notice": UNTRUSTED_NOTICE,
        "recall": backend.recall,
        "results": [
            {
                "id": hit.id,
                "snippet": sanitize_text(hit.content)[:limit],
                "score": hit.score,
                "metadata": hit.metadata,
            }
            for hit in hits
        ],
    }


async def memory_list(namespace: str) -> MemoryListResult:
    """List the ids and metadata of the memories in a namespace you own.
    Example: memory_list(namespace="prefs").
    """
    settings = get_settings()
    try:
        validate_namespace(namespace)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc

    owner = authorize_action(
        ACTION_READ, Resource(kind=KIND_MEMORY_PREFIX, identifier=namespace)
    )
    backend = _backend(settings)
    try:
        summaries = await backend.list(owner, namespace)
    except MemoryBackendError as exc:
        raise ToolError(str(exc)) from exc
    return {
        "namespace": namespace,
        "entries": [
            {
                "id": summary.id,
                "size": summary.size,
                "created_at": summary.created_at,
                "updated_at": summary.updated_at,
                "metadata": summary.metadata,
            }
            for summary in summaries
        ],
    }


async def memory_delete(namespace: str, id: str) -> MemoryDeleteResult:
    """Delete one memory you own by namespace and id. An id you do not own
    is reported as not found. Example: memory_delete(namespace="prefs",
    id="3f2a...").
    """
    settings = get_settings()
    try:
        validate_namespace(namespace)
        validate_memory_id(id)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc

    owner = authorize_action(
        ACTION_WRITE, Resource(kind=KIND_MEMORY, identifier=f"{namespace}/{id}")
    )
    backend = _backend(settings)
    try:
        await backend.delete(owner, namespace, id)
    except MemoryEntryNotFoundError as exc:
        raise ToolError(str(exc)) from exc
    except MemoryBackendError as exc:
        raise ToolError(str(exc)) from exc
    return {"id": id, "deleted": True}


def _backend(settings: Settings):
    try:
        return build_memory_backend(settings)
    except MemoryBackendError as exc:
        raise ToolError(str(exc)) from exc


def _bounded_k(k, settings: Settings) -> int:
    try:
        bounded = int(k)
    except (TypeError, ValueError) as exc:
        raise ToolError("k must be an integer") from exc
    return max(1, min(bounded, settings.memory_max_k))


def _validated_metadata(metadata: dict | None, settings: Settings) -> dict:
    if metadata is None:
        return {}
    if not isinstance(metadata, dict):
        raise ValidationError("metadata must be an object")
    try:
        encoded = json.dumps(metadata, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValidationError("metadata must be JSON-serializable") from exc
    if len(encoded.encode("utf-8")) > settings.memory_max_metadata_bytes:
        raise ValidationError(
            f"metadata exceeds {settings.memory_max_metadata_bytes} bytes"
        )
    return metadata
