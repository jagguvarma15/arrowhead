"""Hybrid retrieval: vector similarity fused with full-text rank.

A vector search finds what a query means; a full-text search finds what
it literally says. Each branch misses what the other catches (an exact
identifier or error code embeds poorly; a paraphrase never matches
lexically), so hybrid_query runs both against the same allow-listed
collection and fuses them with reciprocal rank fusion, which needs no
score calibration between the two systems.

Every guarantee of the vector tools holds unchanged: the collection must
be allow-listed, the tenant filter is derived from the authenticated
caller rather than an argument, authorization runs before the query is
embedded so an unauthorized caller cannot trigger an outbound embedding
request, the full-text configuration and every caller value are bound
parameters, results are capped and sanitized, and the payload is wrapped
as untrusted data with per-row citations.
"""

import anyio

from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import ACTION_QUERY, KIND_TABLE, Resource
from arrowhead.config import get_settings
from arrowhead.connectors.pgvector import (
    _bounded_k,
    _embed_query,
    _safe_identifier,
    _validate_collection,
)
from arrowhead.connectors.sql import (
    _TIMEOUT_GRACE_SECONDS,
    SqlConnectorError,
    _collect,
    _connector_errors,
    _dialect_from_dsn,
    _get_engine,
    _import_sqlalchemy,
    _session_guards,
    _wrap_rows,
)
from arrowhead.content.provenance import ProvenancedResult
from arrowhead.errors import ToolError


async def hybrid_query(
    collection: str, query: str, k: int = 10
) -> ProvenancedResult:
    """Retrieve corpus chunks by fused vector and keyword relevance, scoped
    to the caller's tenant. The query is embedded server-side and also run
    as a full-text search; the two rankings merge by reciprocal rank
    fusion, so exact identifiers and paraphrases both surface. Example:
    hybrid_query(collection="doc_chunks", query="refund window", k=5).
    """
    settings = get_settings()
    if not settings.sql_dsn:
        raise ToolError("the vector connector is not configured")
    dialect = settings.sql_dialect or _dialect_from_dsn(settings.sql_dsn)
    if dialect != "postgres":
        raise ToolError("hybrid search requires a PostgreSQL database")
    if not isinstance(query, str) or not query.strip():
        raise ToolError("query must be a non-empty string")
    collection = _validate_collection(collection, settings)
    k = _bounded_k(k, settings)

    # Authorize before embedding so an unauthorized caller cannot trigger an
    # outbound embedding request. The tenant is the caller, never an argument.
    tenant = authorize_action(
        ACTION_QUERY, Resource(kind=KIND_TABLE, identifier=collection.lower())
    )
    literal = await _embed_query(query, settings)

    try:
        rows, columns, truncated = await _fused_search(
            collection, literal, query.strip(), k, tenant, settings
        )
    except SqlConnectorError as exc:
        raise ToolError(str(exc)) from exc

    return _wrap_rows(rows, columns, truncated, source=f"pgvector:{collection}")


async def _fused_search(collection, literal, query, k, tenant, settings):
    text = _import_sqlalchemy()

    # Every interpolated name is either allow-listed (the collection) or
    # comes from configuration, and each passes the strict identifier
    # guard; the caller-supplied inputs (embedding, query text, tenant, k)
    # and the text-search configuration are bound parameters. The S608
    # construction warning is therefore a false positive.
    id_col = _safe_identifier(settings.pgvector_id_column)
    source_col = _safe_identifier(settings.pgvector_source_column)
    chunk_col = _safe_identifier(settings.pgvector_chunk_index_column)
    content_col = _safe_identifier(settings.pgvector_content_column)
    tenant_col = _safe_identifier(settings.pgvector_tenant_column)
    embedding_col = _safe_identifier(settings.pgvector_embedding_column)
    tsv_col = _safe_identifier(settings.pgvector_tsvector_column)
    pool = k * max(1, settings.hybrid_candidate_multiplier)
    sql = (
        "WITH knn AS ("  # noqa: S608
        f"SELECT {id_col}, {source_col}, {chunk_col}, {content_col}, "
        f"ROW_NUMBER() OVER (ORDER BY {embedding_col} <=> (:q)::vector) "
        "AS rank "
        f"FROM {collection} WHERE {tenant_col} = :tenant "
        f"ORDER BY {embedding_col} <=> (:q)::vector LIMIT :pool"
        "), fts AS ("
        f"SELECT {id_col}, {source_col}, {chunk_col}, {content_col}, "
        "ROW_NUMBER() OVER (ORDER BY "
        f"ts_rank({tsv_col}, plainto_tsquery(CAST(:lang AS regconfig), "
        ":query)) DESC) AS rank "
        f"FROM {collection} WHERE {tenant_col} = :tenant "
        f"AND {tsv_col} @@ plainto_tsquery(CAST(:lang AS regconfig), :query) "
        "LIMIT :pool"
        ") "
        f"SELECT COALESCE(knn.{id_col}, fts.{id_col}) AS {id_col}, "
        f"COALESCE(knn.{source_col}, fts.{source_col}) AS {source_col}, "
        f"COALESCE(knn.{chunk_col}, fts.{chunk_col}) AS {chunk_col}, "
        f"COALESCE(knn.{content_col}, fts.{content_col}) AS {content_col}, "
        "(COALESCE(1.0 / (:rrf_k + knn.rank), 0) + "
        "COALESCE(1.0 / (:rrf_k + fts.rank), 0)) AS score "
        f"FROM knn FULL OUTER JOIN fts ON knn.{id_col} = fts.{id_col} "
        "ORDER BY score DESC "
        "LIMIT :k"
    )
    bind = {
        "q": literal,
        "query": query,
        "lang": settings.fts_language,
        "tenant": tenant,
        "pool": pool,
        "rrf_k": settings.hybrid_rrf_k,
        "k": k,
    }

    guards = _session_guards("postgres", settings)
    with _connector_errors():
        engine = _get_engine(settings.sql_dsn)
        with anyio.fail_after(
            settings.sql_timeout_seconds + _TIMEOUT_GRACE_SECONDS
        ):
            async with engine.connect() as conn:
                async with conn.begin():
                    for statement in guards:
                        await conn.execute(text(statement))
                    result = await conn.stream(text(sql), bind)
                    # Reuse the SQL connector's row collector so the byte,
                    # row, column, and per-cell caps stay identical here.
                    return await _collect(result, settings)
