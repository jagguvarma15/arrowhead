"""The Postgres memory backend against a real database.

Applies deploy/memory_schema.sql (narrowed to eight-dimension vectors so
the deterministic embedder can exercise the semantic path), then proves
the upsert contract, both recall modes, kv expiry against the database
clock, and owner isolation.
"""

from pathlib import Path

import pytest

from arrowhead.config import Settings
from arrowhead.embeddings.deterministic import DeterministicEmbeddingProvider
from arrowhead.memory.base import MemoryBackendError, MemoryEntryNotFoundError
from arrowhead.memory.postgres_backend import PostgresMemoryBackend

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "deploy" / "memory_schema.sql"


@pytest.fixture
async def memory_db(postgres_url, run_ddl):
    ddl = SCHEMA_PATH.read_text().replace("vector(1536)", "vector(8)")
    statements = [
        "DROP TABLE IF EXISTS arrowhead_memory",
        "DROP TABLE IF EXISTS arrowhead_memory_kv",
        *[part.strip() for part in ddl.split(";") if part.strip()],
    ]
    await run_ddl(statements)
    yield postgres_url
    from arrowhead.connectors.sql import dispose_engines

    await dispose_engines()


def make_backend(url, embedder=None, **overrides):
    settings = Settings(memory_dsn=url, **overrides)
    return PostgresMemoryBackend(settings, embedder=embedder)


async def test_upsert_contract_and_listing(memory_db):
    backend = make_backend(memory_db)
    assert backend.recall == "keyword"
    entry_id, status = await backend.store(
        "alice", "prefs", "prefers metric units", {"kind": "pref"}, None
    )
    assert status == "created"
    same_id, status = await backend.store(
        "alice", "prefs", "prefers metric units", {}, None
    )
    assert (same_id, status) == (entry_id, "unchanged")
    updated_id, status = await backend.store(
        "alice", "prefs", "prefers imperial units", {"kind": "pref"}, entry_id
    )
    assert (updated_id, status) == (entry_id, "updated")
    summaries = await backend.list("alice", "prefs")
    assert [item.id for item in summaries] == [entry_id]
    assert summaries[0].metadata == {"kind": "pref"}
    assert summaries[0].size == len("prefers imperial units")
    with pytest.raises(MemoryEntryNotFoundError):
        await backend.store("alice", "prefs", "new content", {}, "ab" * 16)
    await backend.delete("alice", "prefs", entry_id)
    with pytest.raises(MemoryEntryNotFoundError):
        await backend.delete("alice", "prefs", entry_id)


async def test_fulltext_recall_without_an_embedder(memory_db):
    backend = make_backend(memory_db)
    await backend.store(
        "alice", "notes", "the quick brown fox jumps", {}, None
    )
    await backend.store("alice", "notes", "an unrelated sentence", {}, None)
    hits = await backend.search("alice", "notes", "fox", 5)
    assert [hit.content for hit in hits] == ["the quick brown fox jumps"]
    assert hits[0].score > 0


async def test_semantic_recall_with_an_embedder(memory_db):
    backend = make_backend(
        memory_db, embedder=DeterministicEmbeddingProvider(8)
    )
    assert backend.recall == "semantic"
    await backend.store("alice", "notes", "alpha beta gamma", {}, None)
    await backend.store("alice", "notes", "delta epsilon zeta", {}, None)
    hits = await backend.search("alice", "notes", "alpha beta gamma", 5)
    assert len(hits) == 2
    assert hits[0].content == "alpha beta gamma"
    assert hits[0].score >= hits[1].score


async def test_entry_and_namespace_caps(memory_db):
    backend = make_backend(memory_db, memory_max_entries_per_namespace=1)
    await backend.store("carol", "only", "one entry", {}, None)
    with pytest.raises(MemoryBackendError):
        await backend.store("carol", "only", "another", {}, None)
    capped = make_backend(memory_db, memory_max_namespaces=1)
    with pytest.raises(MemoryBackendError):
        await capped.store("carol", "second", "spill", {}, None)


async def test_kv_round_trip_and_database_clock_expiry(memory_db):
    backend = make_backend(memory_db)
    assert await backend.kv_set("alice", "pin", "value", None) is None
    value, expires = await backend.kv_get("alice", "pin")
    assert (value, expires) == ("value", None)
    stamped = await backend.kv_set("alice", "lease", "held", 3600)
    assert stamped is not None
    # A negative ttl lands the expiry in the past; the next read must
    # remove the record and report it missing (lazy expiry against now()).
    await backend.kv_set("alice", "stale", "gone", -5)
    with pytest.raises(MemoryEntryNotFoundError):
        await backend.kv_get("alice", "stale")
    await backend.kv_delete("alice", "pin")
    with pytest.raises(MemoryEntryNotFoundError):
        await backend.kv_delete("alice", "pin")


async def test_owner_isolation(memory_db):
    backend = make_backend(memory_db)
    entry_id, _ = await backend.store("alice", "prefs", "private", {}, None)
    assert await backend.list("mallory", "prefs") == []
    with pytest.raises(MemoryEntryNotFoundError):
        await backend.delete("mallory", "prefs", entry_id)
    await backend.kv_set("alice", "token", "secret", None)
    with pytest.raises(MemoryEntryNotFoundError):
        await backend.kv_get("mallory", "token")


def test_non_postgres_dsn_is_refused():
    with pytest.raises(MemoryBackendError):
        make_backend("sqlite+aiosqlite:///memory.db")
