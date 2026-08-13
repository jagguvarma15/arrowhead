"""Index corpus documents into a pgvector collection for retrieval.

doc_index reads the jailed corpus, chunks and embeds each authorized document,
and writes the chunks under the caller's tenant so vector_query can retrieve
them with citations. Writing needs a credential separate from the read-only
sql_dsn (ARROWHEAD_VECTOR_WRITE_DSN), kept least privilege; ingestion is
authorized under a dedicated ingest action the default policy denies, and the
tenant is the authenticated caller, never an argument. Re-indexing a document
replaces its existing chunks so a shrunk document leaves no stale rows. File,
chunk, and per-chunk-size caps bound how much one call may index.
"""

import hashlib
from typing import TypedDict

import anyio
from fastmcp.exceptions import ToolError

from arrowhead.authz.enforce import authorize_action, get_authorizer
from arrowhead.authz.policy import (
    ACTION_INGEST,
    ACTION_READ,
    KIND_DOCUMENT,
    KIND_TABLE,
    Resource,
)
from arrowhead.config import get_settings
from arrowhead.connectors.pgvector import (
    _safe_identifier,
    _validate_collection,
    _validate_embedding,
)
from arrowhead.connectors.sql import (
    _TIMEOUT_GRACE_SECONDS,
    SqlConnectorError,
    _connector_errors,
    _dialect_from_dsn,
    _get_engine,
    _import_sqlalchemy,
)
from arrowhead.content.chunking import chunk_text
from arrowhead.content.json_safe import JSONSafetyError
from arrowhead.content.render import render_document
from arrowhead.content.text_safe import TextSafetyError
from arrowhead.embeddings.base import EmbeddingError
from arrowhead.embeddings.factory import build_embedding_provider
from arrowhead.security.input_validation import (
    ValidationError,
    validate_relative_path,
)
from arrowhead.store.document_store import DocumentStoreError, build_document_store


class IndexResult(TypedDict):
    """The outcome of indexing corpus documents into a vector collection."""

    collection: str
    files_indexed: int
    chunks_written: int
    truncated: bool


async def doc_index(collection: str, path_prefix: str = "") -> IndexResult:
    """Index corpus documents into a pgvector collection so vector_query can
    retrieve them. Each document under the path prefix is chunked, embedded, and
    written under the caller's tenant; a re-index replaces a document's existing
    chunks. Example: doc_index(collection="doc_chunks", path_prefix="handbook/").
    """
    settings = get_settings()
    if not settings.vector_write_dsn:
        raise ToolError("the vector write connector is not configured")
    if _dialect_from_dsn(settings.vector_write_dsn) != "postgres":
        raise ToolError("vector indexing requires a PostgreSQL database")
    if path_prefix:
        try:
            validate_relative_path(path_prefix)
        except ValidationError as exc:
            raise ToolError(str(exc)) from exc
    collection = _validate_collection(collection, settings)

    # The tenant is the authenticated caller, never an argument, and ingestion
    # is denied unless a deployment explicitly grants the ingest action.
    tenant = authorize_action(
        ACTION_INGEST, Resource(kind=KIND_TABLE, identifier=collection.lower())
    )

    gathered, truncated = await anyio.to_thread.run_sync(
        _gather_chunks, path_prefix, tenant, settings
    )
    flat = [
        (source, index, content)
        for source, chunks in gathered.items()
        for index, content in chunks
    ]
    if not flat:
        return {
            "collection": collection,
            "files_indexed": 0,
            "chunks_written": 0,
            "truncated": truncated,
        }
    if len(flat) > settings.embedding_max_texts:
        raise ToolError("too many chunks to embed in one call")

    prepared = await _embed(flat, settings)
    try:
        written = await _write_chunks(collection, tenant, prepared, settings)
    except SqlConnectorError as exc:
        raise ToolError(str(exc)) from exc
    return {
        "collection": collection,
        "files_indexed": len(prepared),
        "chunks_written": written,
        "truncated": truncated,
    }


def _gather_chunks(path_prefix, tenant, settings):
    """List, read, render, and chunk the authorized corpus documents.

    Runs in a worker thread. Returns a mapping of source path to its
    (chunk_index, content) pairs, and whether the file or chunk caps truncated
    the result.
    """
    store = build_document_store(settings)
    authorizer = get_authorizer()
    listing = store.list(
        extensions=settings.doc_allowed_extension_set(),
        max_files=settings.vector_index_max_files,
        path_prefix=path_prefix,
    )
    truncated = listing.truncated
    gathered: dict[str, list[tuple[int, str]]] = {}
    total_chunks = 0
    for info in listing.items:
        if not authorizer.authorize(
            tenant, ACTION_READ, Resource(kind=KIND_DOCUMENT, identifier=info.path)
        ).allowed:
            continue
        if total_chunks >= settings.vector_index_max_chunks:
            truncated = True
            break
        try:
            data = store.read_bytes(info.path)
            content, _format = render_document(info.path, data, settings)
        except (DocumentStoreError, JSONSafetyError, TextSafetyError):
            continue
        remaining = settings.vector_index_max_chunks - total_chunks
        chunks = chunk_text(
            content,
            max_chars=settings.vector_index_chunk_max_chars,
            overlap=settings.vector_index_chunk_overlap,
            max_chunks=remaining,
        )
        if not chunks:
            continue
        gathered[info.path] = list(enumerate(chunks))
        total_chunks += len(chunks)
    return gathered, truncated


async def _embed(flat, settings):
    """Embed the chunk texts and attach a vector literal to each chunk."""
    provider = build_embedding_provider(settings)
    texts = [content for _source, _index, content in flat]
    try:
        vectors = await provider.embed(texts)
    except EmbeddingError as exc:
        raise ToolError(f"could not embed documents: {exc}") from exc
    if len(vectors) != len(texts):
        raise ToolError("the embedding provider returned the wrong count")
    prepared: dict[str, list[tuple[int, str, str]]] = {}
    for (source, index, content), vector in zip(flat, vectors, strict=True):
        literal = _validate_embedding(vector, settings)
        prepared.setdefault(source, []).append((index, content, literal))
    return prepared


def _chunk_id(tenant: str, source: str, chunk_index: int) -> str:
    raw = f"{tenant}\x00{source}\x00{chunk_index}".encode()
    return hashlib.sha256(raw).hexdigest()


async def _write_chunks(collection, tenant, prepared, settings):
    """Replace each source's chunks under the caller's tenant, in one
    transaction, through the write credential."""
    text = _import_sqlalchemy()
    id_col = _safe_identifier(settings.pgvector_id_column)
    tenant_col = _safe_identifier(settings.pgvector_tenant_column)
    source_col = _safe_identifier(settings.pgvector_source_column)
    chunk_col = _safe_identifier(settings.pgvector_chunk_index_column)
    content_col = _safe_identifier(settings.pgvector_content_column)
    embedding_col = _safe_identifier(settings.pgvector_embedding_column)
    delete_sql = (
        f"DELETE FROM {collection} "  # noqa: S608
        f"WHERE {tenant_col} = :tenant AND {source_col} = :source"
    )
    insert_sql = (
        f"INSERT INTO {collection} "  # noqa: S608
        f"({id_col}, {tenant_col}, {source_col}, {chunk_col}, "
        f"{content_col}, {embedding_col}) "
        "VALUES (:id, :tenant, :source, :chunk_index, :content, "
        "(:embedding)::vector)"
    )
    timeout_ms = max(1, int(settings.vector_index_timeout_seconds * 1000))
    grace = settings.vector_index_timeout_seconds + _TIMEOUT_GRACE_SECONDS
    written = 0
    with _connector_errors():
        engine = _get_engine(settings.vector_write_dsn)
        with anyio.fail_after(grace):
            async with engine.connect() as conn:
                async with conn.begin():
                    await conn.execute(
                        text(f"SET LOCAL statement_timeout = {timeout_ms}")
                    )
                    for source, chunks in prepared.items():
                        await conn.execute(
                            text(delete_sql),
                            {"tenant": tenant, "source": source},
                        )
                        for chunk_index, content, literal in chunks:
                            await conn.execute(
                                text(insert_sql),
                                {
                                    "id": _chunk_id(tenant, source, chunk_index),
                                    "tenant": tenant,
                                    "source": source,
                                    "chunk_index": chunk_index,
                                    "content": content,
                                    "embedding": literal,
                                },
                            )
                            written += 1
    return written
