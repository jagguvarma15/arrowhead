"""Postgres memory backend.

Selected when memory_dsn is configured. Records live in two fixed tables
(deploy/memory_schema.sql); every identifier in the SQL below is a
constant, so the only runtime inputs are bound parameters. With an
embedding provider each memory is embedded on write and recall is
semantic nearest-neighbour over pgvector; without one, recall is Postgres
full-text keyword matching, and the honest recall label says so.

Dedup rides the UNIQUE (owner, namespace, content_hash) constraint, so
two concurrent writers of the same content converge on one row.
"""

import hashlib
import json
import secrets
from contextlib import asynccontextmanager

import anyio

from arrowhead.config import Settings
from arrowhead.connectors.pgvector import _validate_embedding
from arrowhead.connectors.sql import (
    _TIMEOUT_GRACE_SECONDS,
    SqlConnectorError,
    _dialect_from_dsn,
    _get_engine,
    _import_sqlalchemy,
)
from arrowhead.embeddings.base import EmbeddingError, EmbeddingProvider
from arrowhead.memory.base import (
    MemoryBackendError,
    MemoryEntryNotFoundError,
    MemoryHit,
    MemorySummary,
)

_MEMORY_TABLE = "arrowhead_memory"
_KV_TABLE = "arrowhead_memory_kv"


class PostgresMemoryBackend:
    """Owner-scoped memories and scratchpad values in fixed Postgres tables."""

    def __init__(
        self, settings: Settings, embedder: EmbeddingProvider | None = None
    ) -> None:
        if _dialect_from_dsn(settings.memory_dsn) != "postgres":
            raise MemoryBackendError(
                "memory_dsn must be a PostgreSQL DSN"
            )
        self._settings = settings
        self._embedder = embedder

    @property
    def recall(self) -> str:
        return "semantic" if self._embedder is not None else "keyword"

    # ---- memories -----------------------------------------------------

    async def store(
        self,
        owner: str,
        namespace: str,
        content: str,
        metadata: dict,
        entry_id: str | None,
    ) -> tuple[str, str]:
        embedding = await self._embed(content)
        metadata_json = json.dumps(metadata, ensure_ascii=False, sort_keys=True)
        digest = _hash(content)
        settings = self._settings
        async with self._transaction() as (conn, text):
            row = (
                await conn.execute(
                    text(
                        f"SELECT id FROM {_MEMORY_TABLE} WHERE owner = :o "  # noqa: S608
                        "AND namespace = :n AND content_hash = :h"
                    ),
                    {"o": owner, "n": namespace, "h": digest},
                )
            ).first()
            if row is not None:
                return str(row[0]), "unchanged"

            if entry_id is not None:
                result = await conn.execute(
                    text(
                        f"UPDATE {_MEMORY_TABLE} SET content = :c, "  # noqa: S608
                        "metadata = CAST(:m AS jsonb), content_hash = :h, "
                        "embedding = CAST(:e AS vector), updated_at = now() "
                        "WHERE owner = :o AND namespace = :n AND id = :i "
                        "RETURNING id"
                    ),
                    {
                        "c": content,
                        "m": metadata_json,
                        "h": digest,
                        "e": embedding,
                        "o": owner,
                        "n": namespace,
                        "i": entry_id,
                    },
                )
                if result.first() is None:
                    raise MemoryEntryNotFoundError("memory not found")
                return entry_id, "updated"

            counts = (
                await conn.execute(
                    text(
                        "SELECT count(*) FILTER (WHERE namespace = :n), "  # noqa: S608
                        "count(DISTINCT namespace) "
                        f"FROM {_MEMORY_TABLE} WHERE owner = :o"
                    ),
                    {"o": owner, "n": namespace},
                )
            ).first()
            in_namespace, namespaces = (counts[0], counts[1]) if counts else (0, 0)
            if in_namespace >= settings.memory_max_entries_per_namespace:
                raise MemoryBackendError(
                    "namespace is full; delete an entry before storing another"
                )
            if (
                in_namespace == 0
                and namespaces >= settings.memory_max_namespaces
            ):
                raise MemoryBackendError(
                    "namespace limit reached for this caller"
                )

            minted = secrets.token_hex(16)
            inserted = (
                await conn.execute(
                    text(
                        f"INSERT INTO {_MEMORY_TABLE} "  # noqa: S608
                        "(owner, namespace, id, content, metadata, "
                        "content_hash, embedding) VALUES (:o, :n, :i, :c, "
                        "CAST(:m AS jsonb), :h, CAST(:e AS vector)) "
                        "ON CONFLICT (owner, namespace, content_hash) "
                        "DO NOTHING RETURNING id"
                    ),
                    {
                        "o": owner,
                        "n": namespace,
                        "i": minted,
                        "c": content,
                        "m": metadata_json,
                        "h": digest,
                        "e": embedding,
                    },
                )
            ).first()
            if inserted is None:
                # A concurrent writer landed the same content first.
                row = (
                    await conn.execute(
                        text(
                            f"SELECT id FROM {_MEMORY_TABLE} "  # noqa: S608
                            "WHERE owner = :o AND namespace = :n "
                            "AND content_hash = :h"
                        ),
                        {"o": owner, "n": namespace, "h": digest},
                    )
                ).first()
                return (str(row[0]) if row else minted), "unchanged"
            return minted, "created"

    async def search(
        self, owner: str, namespace: str, query: str, k: int
    ) -> list[MemoryHit]:
        if self._embedder is not None:
            literal = await self._embed(query)
            sql = (
                "SELECT id, content, CAST(metadata AS text), "  # noqa: S608
                "1.0 / (1.0 + (embedding <=> CAST(:q AS vector))) AS score "
                f"FROM {_MEMORY_TABLE} WHERE owner = :o AND namespace = :n "
                "AND embedding IS NOT NULL "
                "ORDER BY embedding <=> CAST(:q AS vector) LIMIT :k"
            )
            bind = {"q": literal, "o": owner, "n": namespace, "k": k}
        else:
            sql = (
                "SELECT id, content, CAST(metadata AS text), "  # noqa: S608
                "ts_rank(to_tsvector(CAST(:lang AS regconfig), content), "
                "plainto_tsquery(CAST(:lang AS regconfig), :q)) AS score "
                f"FROM {_MEMORY_TABLE} WHERE owner = :o AND namespace = :n "
                "AND to_tsvector(CAST(:lang AS regconfig), content) "
                "@@ plainto_tsquery(CAST(:lang AS regconfig), :q) "
                "ORDER BY score DESC LIMIT :k"
            )
            bind = {
                "lang": self._settings.fts_language,
                "q": query,
                "o": owner,
                "n": namespace,
                "k": k,
            }
        async with self._transaction() as (conn, text):
            rows = (await conn.execute(text(sql), bind)).all()
        return [
            MemoryHit(
                id=str(row[0]),
                content=str(row[1]),
                score=float(row[3]),
                metadata=_metadata(row[2]),
            )
            for row in rows
        ]

    async def list(self, owner: str, namespace: str) -> list[MemorySummary]:
        sql = (
            "SELECT id, octet_length(content), CAST(metadata AS text), "  # noqa: S608
            "created_at, updated_at "
            f"FROM {_MEMORY_TABLE} WHERE owner = :o AND namespace = :n "
            "ORDER BY updated_at DESC"
        )
        async with self._transaction() as (conn, text):
            rows = (
                await conn.execute(text(sql), {"o": owner, "n": namespace})
            ).all()
        return [
            MemorySummary(
                id=str(row[0]),
                size=int(row[1]),
                created_at=row[3].isoformat(),
                updated_at=row[4].isoformat(),
                metadata=_metadata(row[2]),
            )
            for row in rows
        ]

    async def delete(self, owner: str, namespace: str, entry_id: str) -> None:
        sql = (
            f"DELETE FROM {_MEMORY_TABLE} WHERE owner = :o "  # noqa: S608
            "AND namespace = :n AND id = :i RETURNING id"
        )
        async with self._transaction() as (conn, text):
            row = (
                await conn.execute(
                    text(sql), {"o": owner, "n": namespace, "i": entry_id}
                )
            ).first()
        if row is None:
            raise MemoryEntryNotFoundError("memory not found")

    # ---- scratchpad ---------------------------------------------------

    async def kv_set(
        self, owner: str, key: str, value: str, ttl_seconds: int | None
    ) -> str | None:
        async with self._transaction() as (conn, text):
            exists = (
                await conn.execute(
                    text(
                        f"SELECT 1 FROM {_KV_TABLE} "  # noqa: S608
                        "WHERE owner = :o AND key = :k"
                    ),
                    {"o": owner, "k": key},
                )
            ).first()
            if exists is None:
                count = (
                    await conn.execute(
                        text(
                            f"SELECT count(*) FROM {_KV_TABLE} "  # noqa: S608
                            "WHERE owner = :o"
                        ),
                        {"o": owner},
                    )
                ).first()
                if count and count[0] >= self._settings.kv_max_keys:
                    raise MemoryBackendError(
                        "key limit reached for this caller; delete a key first"
                    )
            row = (
                await conn.execute(
                    text(
                        f"INSERT INTO {_KV_TABLE} (owner, key, value, "  # noqa: S608
                        "expires_at) VALUES (:o, :k, :v, now() + "
                        "make_interval(secs => CAST(:ttl AS double precision))) "
                        "ON CONFLICT (owner, key) DO UPDATE SET "
                        "value = excluded.value, "
                        "expires_at = excluded.expires_at "
                        "RETURNING expires_at"
                    ),
                    {"o": owner, "k": key, "v": value, "ttl": ttl_seconds},
                )
            ).first()
        expires = row[0] if row else None
        return expires.isoformat() if expires is not None else None

    async def kv_get(self, owner: str, key: str) -> tuple[str, str | None]:
        async with self._transaction() as (conn, text):
            # Lazy expiry: an expired record is removed on read.
            await conn.execute(
                text(
                    f"DELETE FROM {_KV_TABLE} WHERE owner = :o "  # noqa: S608
                    "AND key = :k AND expires_at IS NOT NULL "
                    "AND expires_at <= now()"
                ),
                {"o": owner, "k": key},
            )
            row = (
                await conn.execute(
                    text(
                        f"SELECT value, expires_at FROM {_KV_TABLE} "  # noqa: S608
                        "WHERE owner = :o AND key = :k"
                    ),
                    {"o": owner, "k": key},
                )
            ).first()
        if row is None:
            raise MemoryEntryNotFoundError("key not found")
        expires = row[1]
        return str(row[0]), (
            expires.isoformat() if expires is not None else None
        )

    async def kv_delete(self, owner: str, key: str) -> None:
        async with self._transaction() as (conn, text):
            row = (
                await conn.execute(
                    text(
                        f"DELETE FROM {_KV_TABLE} WHERE owner = :o "  # noqa: S608
                        "AND key = :k RETURNING key"
                    ),
                    {"o": owner, "k": key},
                )
            ).first()
        if row is None:
            raise MemoryEntryNotFoundError("key not found")

    # ---- shared -------------------------------------------------------

    def _transaction(self):
        """One bounded transaction: engine, deadline, clean error surface.

        Mirrors the SQL connector's error translation, but memory errors
        raised by the body (a not-found, a cap refusal) pass through
        untouched rather than being masked into a generic query failure.
        """
        settings = self._settings

        @asynccontextmanager
        async def run():
            try:
                text = _import_sqlalchemy()
                engine = _get_engine(settings.memory_dsn)
                with anyio.fail_after(
                    settings.sql_timeout_seconds + _TIMEOUT_GRACE_SECONDS
                ):
                    async with engine.connect() as conn:
                        async with conn.begin():
                            yield conn, text
            except MemoryBackendError:
                raise
            except SqlConnectorError as exc:
                raise MemoryBackendError(str(exc)) from exc
            except TimeoutError as exc:
                raise MemoryBackendError(
                    "the query exceeded its time budget"
                ) from exc
            except Exception as exc:
                # Driver and engine failures carry backend details in their
                # messages; reduce them to the exception type name.
                raise MemoryBackendError(
                    f"query failed: {type(exc).__name__}"
                ) from exc

        return run()

    async def _embed(self, content: str) -> str | None:
        if self._embedder is None:
            return None
        try:
            vectors = await self._embedder.embed([content])
        except EmbeddingError as exc:
            raise MemoryBackendError(
                f"could not embed the memory: {exc}"
            ) from exc
        if not vectors:
            raise MemoryBackendError("the embedding provider returned no vector")
        return _validate_embedding(vectors[0], self._settings)


def _hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _metadata(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}
