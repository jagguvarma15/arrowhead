"""Jailed JSON file memory backend.

The zero-configuration default: each record is one JSON document in a
jailed tree under memory_root, written through the same store that backs
the corpus, so containment, atomic writes, and the quota walk are
inherited rather than re-implemented. The owner segment of every path is
the SHA-256 of the verified caller identity: identities are free-form
strings (emails, service names) and must never shape a filesystem path.

Recall is honest keyword matching: the fraction of query terms present in
a record's content, most recent first among ties. Layout:

    <owner-hash>/ns/<namespace>/<id>.json   one memory record
    <owner-hash>/kv/<key>.json              one scratchpad value
"""

import hashlib
import json
import secrets
import time
from collections.abc import Callable
from datetime import UTC, datetime

import anyio

from arrowhead.config import Settings
from arrowhead.memory.base import (
    MemoryBackendError,
    MemoryEntryNotFoundError,
    MemoryHit,
    MemorySummary,
)
from arrowhead.store.document_store import (
    DocumentNotFoundError,
    DocumentStore,
    DocumentStoreError,
)

_JSON_EXTENSIONS = frozenset({".json"})
# Headroom for the JSON envelope (keys, timestamps, hash) around a record
# whose content and metadata are already capped by their own settings.
_ENVELOPE_BYTES = 4096


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class FileMemoryBackend:
    """Owner-scoped memories and scratchpad values as jailed JSON files."""

    recall = "keyword"

    def __init__(
        self, settings: Settings, clock: Callable[[], float] = time.time
    ) -> None:
        self._settings = settings
        envelope = (
            settings.memory_max_content_bytes
            + settings.memory_max_metadata_bytes
            + _ENVELOPE_BYTES
        )
        kv_envelope = settings.kv_max_value_bytes + _ENVELOPE_BYTES
        self._store = DocumentStore(
            settings.memory_root,
            read_max_bytes=max(envelope, kv_envelope),
            write_max_bytes=max(envelope, kv_envelope),
            quota_bytes=settings.memory_quota_bytes,
        )
        self._clock = clock

    # ---- memories -----------------------------------------------------

    async def store(
        self,
        owner: str,
        namespace: str,
        content: str,
        metadata: dict,
        entry_id: str | None,
    ) -> tuple[str, str]:
        return await anyio.to_thread.run_sync(
            self._store_sync, owner, namespace, content, metadata, entry_id
        )

    def _store_sync(
        self,
        owner: str,
        namespace: str,
        content: str,
        metadata: dict,
        entry_id: str | None,
    ) -> tuple[str, str]:
        prefix = f"{_owner_segment(owner)}/ns/{namespace}"
        records = self._load_namespace(prefix)
        digest = _content_hash(content)
        for record in records:
            if record.get("content_hash") == digest:
                return str(record["id"]), "unchanged"

        now = self._now()
        if entry_id is not None:
            existing = next(
                (r for r in records if r.get("id") == entry_id), None
            )
            if existing is None:
                raise MemoryEntryNotFoundError("memory not found")
            record = {
                "id": entry_id,
                "content": content,
                "metadata": metadata,
                "content_hash": digest,
                "created_at": existing.get("created_at", now),
                "updated_at": now,
            }
            self._write_record(f"{prefix}/{entry_id}.json", record, True)
            return entry_id, "updated"

        settings = self._settings
        if len(records) >= settings.memory_max_entries_per_namespace:
            raise MemoryBackendError(
                "namespace is full; delete an entry before storing another"
            )
        if not records:
            owned = self._namespaces(owner)
            if (
                namespace not in owned
                and len(owned) >= settings.memory_max_namespaces
            ):
                raise MemoryBackendError(
                    "namespace limit reached for this caller"
                )
        minted = secrets.token_hex(16)
        record = {
            "id": minted,
            "content": content,
            "metadata": metadata,
            "content_hash": digest,
            "created_at": now,
            "updated_at": now,
        }
        self._write_record(f"{prefix}/{minted}.json", record, False)
        return minted, "created"

    async def search(
        self, owner: str, namespace: str, query: str, k: int
    ) -> list[MemoryHit]:
        return await anyio.to_thread.run_sync(
            self._search_sync, owner, namespace, query, k
        )

    def _search_sync(
        self, owner: str, namespace: str, query: str, k: int
    ) -> list[MemoryHit]:
        prefix = f"{_owner_segment(owner)}/ns/{namespace}"
        terms = {term for term in query.lower().split() if term}
        if not terms:
            return []
        scored: list[tuple[float, str, dict]] = []
        for record in self._load_namespace(prefix):
            content = str(record.get("content", ""))
            haystack = content.lower()
            matched = sum(1 for term in terms if term in haystack)
            if matched == 0:
                continue
            score = matched / len(terms)
            scored.append((score, str(record.get("updated_at", "")), record))
        # Highest score first; among ties, most recently updated first.
        scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
        return [
            MemoryHit(
                id=str(record["id"]),
                content=str(record.get("content", "")),
                score=score,
                metadata=dict(record.get("metadata") or {}),
            )
            for score, _updated, record in scored[:k]
        ]

    async def list(self, owner: str, namespace: str) -> list[MemorySummary]:
        return await anyio.to_thread.run_sync(
            self._list_sync, owner, namespace
        )

    def _list_sync(self, owner: str, namespace: str) -> list[MemorySummary]:
        prefix = f"{_owner_segment(owner)}/ns/{namespace}"
        summaries = [
            MemorySummary(
                id=str(record["id"]),
                size=len(str(record.get("content", "")).encode("utf-8")),
                created_at=str(record.get("created_at", "")),
                updated_at=str(record.get("updated_at", "")),
                metadata=dict(record.get("metadata") or {}),
            )
            for record in self._load_namespace(prefix)
        ]
        summaries.sort(key=lambda item: item.updated_at, reverse=True)
        return summaries

    async def delete(self, owner: str, namespace: str, entry_id: str) -> None:
        await anyio.to_thread.run_sync(
            self._delete_sync, owner, namespace, entry_id
        )

    def _delete_sync(self, owner: str, namespace: str, entry_id: str) -> None:
        path = f"{_owner_segment(owner)}/ns/{namespace}/{entry_id}.json"
        try:
            self._store.delete(path)
        except DocumentNotFoundError:
            raise MemoryEntryNotFoundError("memory not found") from None
        except DocumentStoreError as exc:
            raise MemoryBackendError(str(exc)) from exc

    # ---- scratchpad ---------------------------------------------------

    async def kv_set(
        self, owner: str, key: str, value: str, ttl_seconds: int | None
    ) -> str | None:
        return await anyio.to_thread.run_sync(
            self._kv_set_sync, owner, key, value, ttl_seconds
        )

    def _kv_set_sync(
        self, owner: str, key: str, value: str, ttl_seconds: int | None
    ) -> str | None:
        prefix = f"{_owner_segment(owner)}/kv"
        path = f"{prefix}/{key}.json"
        if not self._store.exists(path):
            listing = self._store.list(
                extensions=_JSON_EXTENSIONS,
                path_prefix=prefix,
                max_files=self._settings.kv_max_keys,
            )
            if len(listing.items) >= self._settings.kv_max_keys:
                raise MemoryBackendError(
                    "key limit reached for this caller; delete a key first"
                )
        expires_epoch = (
            self._clock() + ttl_seconds if ttl_seconds is not None else None
        )
        record = {"key": key, "value": value, "expires_at": expires_epoch}
        self._write_record(path, record, True)
        return _isoformat(expires_epoch) if expires_epoch is not None else None

    async def kv_get(self, owner: str, key: str) -> tuple[str, str | None]:
        return await anyio.to_thread.run_sync(self._kv_get_sync, owner, key)

    def _kv_get_sync(self, owner: str, key: str) -> tuple[str, str | None]:
        path = f"{_owner_segment(owner)}/kv/{key}.json"
        record = self._read_record(path)
        if record is None:
            raise MemoryEntryNotFoundError("key not found")
        expires_epoch = record.get("expires_at")
        if expires_epoch is not None and self._clock() >= float(expires_epoch):
            # Lazy expiry: the record is logically gone; remove it on read.
            try:
                self._store.delete(path)
            except DocumentStoreError:
                pass
            raise MemoryEntryNotFoundError("key not found")
        expires = (
            _isoformat(float(expires_epoch))
            if expires_epoch is not None
            else None
        )
        return str(record.get("value", "")), expires

    async def kv_delete(self, owner: str, key: str) -> None:
        await anyio.to_thread.run_sync(self._kv_delete_sync, owner, key)

    def _kv_delete_sync(self, owner: str, key: str) -> None:
        path = f"{_owner_segment(owner)}/kv/{key}.json"
        try:
            self._store.delete(path)
        except DocumentNotFoundError:
            raise MemoryEntryNotFoundError("key not found") from None
        except DocumentStoreError as exc:
            raise MemoryBackendError(str(exc)) from exc

    # ---- shared -------------------------------------------------------

    def _now(self) -> str:
        return _isoformat(self._clock())

    def _namespaces(self, owner: str) -> set[str]:
        prefix = f"{_owner_segment(owner)}/ns"
        listing = self._store.list(
            extensions=_JSON_EXTENSIONS, path_prefix=prefix
        )
        names = set()
        for info in listing.items:
            parts = info.path.split("/")
            if len(parts) >= 4:
                names.add(parts[2])
        return names

    def _load_namespace(self, prefix: str) -> list[dict]:
        listing = self._store.list(
            extensions=_JSON_EXTENSIONS, path_prefix=prefix
        )
        records = []
        for info in listing.items:
            record = self._read_record(info.path)
            if record is not None and "id" in record:
                records.append(record)
        return records

    def _read_record(self, path: str) -> dict | None:
        try:
            data = self._store.read_bytes(path)
        except DocumentNotFoundError:
            return None
        except DocumentStoreError:
            return None
        try:
            record = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        return record if isinstance(record, dict) else None

    def _write_record(self, path: str, record: dict, overwrite: bool) -> None:
        data = json.dumps(record, ensure_ascii=False, sort_keys=True).encode(
            "utf-8"
        )
        try:
            self._store.write_atomic(path, data, overwrite=overwrite)
        except DocumentStoreError as exc:
            raise MemoryBackendError(str(exc)) from exc


def _owner_segment(owner: str) -> str:
    return hashlib.sha256(owner.encode("utf-8")).hexdigest()[:32]


def _isoformat(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat()
