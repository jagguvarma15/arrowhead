"""pgvector similarity search with server-side tenant isolation.

vector_search runs a bounded nearest-neighbour query against a pgvector
collection. The collection must be one a deployment allow-listed, so the table
name is never taken raw from the caller, and the tenant filter is derived from
the authenticated caller rather than from an argument, so one tenant can never
read another's rows even by asking. The query embedding is bound as a
parameter, results are capped, string cells are sanitized, and the payload is
wrapped as untrusted data.

The connection pool, the dialect-derived read-only transaction, and the
server-side statement timeout are shared with the SQL connector, so a vector
search runs under the same read-only, time-bounded guarantees as a SQL read.
"""

import math
import re

import anyio
from fastmcp.exceptions import ToolError

from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import ACTION_QUERY, KIND_TABLE, Resource
from arrowhead.config import get_settings
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

# A schema-qualified SQL identifier: the only shape a table or column name may
# take before it is interpolated into a query. Values still come from the
# allowlist or from configuration, never raw from the caller.
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?")


async def vector_search(
    collection: str, embedding: list[float], k: int = 10
) -> ProvenancedResult:
    """Find the nearest rows in a pgvector collection to a query embedding,
    scoped to the caller's tenant. Only an allow-listed collection may be
    searched, the tenant is the caller, and results are capped. Example:
    vector_search(collection="documents", embedding=[0.1, 0.2, ...], k=5).
    """
    settings = get_settings()
    if not settings.sql_dsn:
        raise ToolError("the vector connector is not configured")
    # The read-only transaction and statement timeout this connector runs are
    # Postgres-specific; refuse a non-Postgres DSN with a clear message rather
    # than emitting a Postgres SET to another engine at runtime.
    dialect = settings.sql_dialect or _dialect_from_dsn(settings.sql_dsn)
    if dialect != "postgres":
        raise ToolError("vector search requires a PostgreSQL database")
    collection = _validate_collection(collection, settings)
    literal = _validate_embedding(embedding, settings)
    k = _bounded_k(k, settings)

    # The tenant is the authenticated caller, never an argument, so the WHERE
    # clause cannot be widened to another tenant's rows. The table is authorized
    # under the same lowercased identity the SQL connector uses, so a policy
    # that denies a table through sql_query also denies it here.
    tenant = authorize_action(
        ACTION_QUERY, Resource(kind=KIND_TABLE, identifier=collection.lower())
    )

    try:
        rows, columns, truncated = await _search(
            collection, literal, k, tenant, settings
        )
    except SqlConnectorError as exc:
        raise ToolError(str(exc)) from exc

    return _wrap_rows(rows, columns, truncated, source=f"pgvector:{collection}")


def _validate_collection(collection: str, settings) -> str:
    allowed = settings.pgvector_collection_set()
    if not allowed:
        raise ToolError("no vector collections are configured")
    if collection not in allowed:
        raise ToolError("unknown vector collection")
    return _safe_identifier(collection)


def _validate_embedding(embedding, settings) -> str:
    if not isinstance(embedding, list) or not embedding:
        raise ToolError("embedding must be a non-empty list of numbers")
    if len(embedding) > settings.pgvector_max_dimensions:
        raise ToolError(
            f"embedding exceeds {settings.pgvector_max_dimensions} dimensions"
        )
    floats: list[float] = []
    for value in embedding:
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ToolError("embedding values must be numbers")
        try:
            number = float(value)
        except OverflowError as exc:
            raise ToolError("embedding value is out of range") from exc
        if not math.isfinite(number):
            raise ToolError("embedding values must be finite numbers")
        floats.append(number)
    return "[" + ",".join(repr(v) for v in floats) + "]"


def _bounded_k(k, settings) -> int:
    try:
        k = int(k)
    except (TypeError, ValueError) as exc:
        raise ToolError("k must be an integer") from exc
    return max(1, min(k, settings.pgvector_max_k))


def _safe_identifier(name: str) -> str:
    if not _IDENTIFIER.fullmatch(name):
        raise ToolError("invalid identifier")
    return name


async def _search(collection, literal, k, tenant, settings):
    text = _import_sqlalchemy()

    # Every interpolated name is either allow-listed (the collection) or comes
    # from configuration, and each passes the strict identifier guard, so the
    # only caller-supplied inputs (the embedding, tenant, and k) are bound
    # parameters. The S608 construction warning is therefore a false positive.
    id_col = _safe_identifier(settings.pgvector_id_column)
    content_col = _safe_identifier(settings.pgvector_content_column)
    tenant_col = _safe_identifier(settings.pgvector_tenant_column)
    embedding_col = _safe_identifier(settings.pgvector_embedding_column)
    query = (
        f"SELECT {id_col}, {content_col}, "  # noqa: S608
        f"{embedding_col} <=> (:q)::vector AS distance "
        f"FROM {collection} "
        f"WHERE {tenant_col} = :tenant "
        f"ORDER BY {embedding_col} <=> (:q)::vector "
        "LIMIT :k"
    )
    bind = {"q": literal, "tenant": tenant, "k": k}

    guards = _session_guards("postgres", settings)
    with _connector_errors():
        # The engine build is inside the wrapped block so a driver-load error
        # (which leaks the backend name) becomes a clean connector error.
        engine = _get_engine(settings.sql_dsn)
        with anyio.fail_after(settings.sql_timeout_seconds + _TIMEOUT_GRACE_SECONDS):
            async with engine.connect() as conn:
                async with conn.begin():
                    for statement in guards:
                        await conn.execute(text(statement))
                    result = await conn.stream(text(query), bind)
                    # Reuse the SQL connector's row collector so the byte,
                    # row, column, and per-cell caps stay identical here.
                    return await _collect(result, settings)
