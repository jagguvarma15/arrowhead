"""The jailed file memory backend: upsert semantics, bounds, isolation."""

import json

import pytest

from arrowhead.config import Settings
from arrowhead.memory.base import MemoryBackendError, MemoryEntryNotFoundError
from arrowhead.memory.file_backend import FileMemoryBackend


def make_backend(root, clock=None, **overrides):
    settings = Settings(memory_root=root, **overrides)
    if clock is None:
        return FileMemoryBackend(settings)
    return FileMemoryBackend(settings, clock=clock)


async def test_store_search_list_delete_round_trip(tmp_path):
    backend = make_backend(tmp_path)
    entry_id, status = await backend.store(
        "alice", "prefs", "prefers metric units", {"kind": "preference"}, None
    )
    assert status == "created"
    hits = await backend.search("alice", "prefs", "metric units", 5)
    assert [hit.id for hit in hits] == [entry_id]
    assert hits[0].metadata == {"kind": "preference"}
    summaries = await backend.list("alice", "prefs")
    assert [entry.id for entry in summaries] == [entry_id]
    assert summaries[0].created_at == summaries[0].updated_at
    await backend.delete("alice", "prefs", entry_id)
    assert await backend.list("alice", "prefs") == []


async def test_identical_content_dedupes_to_the_existing_id(tmp_path):
    backend = make_backend(tmp_path)
    first_id, _ = await backend.store("alice", "prefs", "same fact", {}, None)
    second_id, status = await backend.store(
        "alice", "prefs", "same fact", {"extra": True}, None
    )
    assert second_id == first_id
    assert status == "unchanged"
    assert len(await backend.list("alice", "prefs")) == 1


async def test_explicit_id_updates_in_place(tmp_path):
    ticks = [1000.0]
    backend = make_backend(tmp_path, clock=lambda: ticks[0])
    entry_id, _ = await backend.store("alice", "prefs", "old fact", {}, None)
    ticks[0] = 2000.0
    updated_id, status = await backend.store(
        "alice", "prefs", "new fact", {}, entry_id
    )
    assert (updated_id, status) == (entry_id, "updated")
    summaries = await backend.list("alice", "prefs")
    assert len(summaries) == 1
    assert summaries[0].updated_at > summaries[0].created_at
    hits = await backend.search("alice", "prefs", "new fact", 5)
    assert hits[0].content == "new fact"


async def test_unknown_explicit_id_is_refused(tmp_path):
    backend = make_backend(tmp_path)
    with pytest.raises(MemoryEntryNotFoundError):
        await backend.store("alice", "prefs", "content", {}, "ab" * 16)


async def test_namespace_entry_cap_is_enforced(tmp_path):
    backend = make_backend(tmp_path, memory_max_entries_per_namespace=2)
    await backend.store("alice", "prefs", "one", {}, None)
    await backend.store("alice", "prefs", "two", {}, None)
    with pytest.raises(MemoryBackendError):
        await backend.store("alice", "prefs", "three", {}, None)


async def test_namespace_count_cap_is_enforced(tmp_path):
    backend = make_backend(tmp_path, memory_max_namespaces=2)
    await backend.store("alice", "ns-one", "a", {}, None)
    await backend.store("alice", "ns-two", "b", {}, None)
    # An existing namespace still accepts entries; a new one is refused.
    await backend.store("alice", "ns-two", "c", {}, None)
    with pytest.raises(MemoryBackendError):
        await backend.store("alice", "ns-three", "d", {}, None)


async def test_owners_are_isolated(tmp_path):
    backend = make_backend(tmp_path)
    entry_id, _ = await backend.store("alice", "prefs", "alice fact", {}, None)
    assert await backend.list("bob", "prefs") == []
    assert await backend.search("bob", "prefs", "alice fact", 5) == []
    with pytest.raises(MemoryEntryNotFoundError):
        await backend.delete("bob", "prefs", entry_id)


async def test_search_ranks_by_term_coverage(tmp_path):
    backend = make_backend(tmp_path)
    await backend.store("alice", "notes", "alpha beta gamma", {}, None)
    await backend.store("alice", "notes", "alpha only here", {}, None)
    await backend.store("alice", "notes", "nothing relevant", {}, None)
    hits = await backend.search("alice", "notes", "alpha beta", 5)
    assert [hit.content for hit in hits] == [
        "alpha beta gamma",
        "alpha only here",
    ]
    assert hits[0].score > hits[1].score


async def test_search_bounds_results_to_k(tmp_path):
    backend = make_backend(tmp_path)
    for index in range(4):
        await backend.store("alice", "notes", f"common term {index}", {}, None)
    hits = await backend.search("alice", "notes", "common", 2)
    assert len(hits) == 2


async def test_corrupt_record_is_skipped_not_fatal(tmp_path):
    backend = make_backend(tmp_path)
    entry_id, _ = await backend.store("alice", "prefs", "good fact", {}, None)
    listing = list(tmp_path.rglob("*.json"))
    assert len(listing) == 1
    broken = listing[0].parent / f"{'0' * 32}.json"
    broken.write_text("not json at all")
    assert [entry.id for entry in await backend.list("alice", "prefs")] == [
        entry_id
    ]


async def test_kv_round_trip_and_ttl_expiry(tmp_path):
    ticks = [1000.0]
    backend = make_backend(tmp_path, clock=lambda: ticks[0])
    expires = await backend.kv_set("alice", "run:1", "phase1", 60)
    assert expires is not None
    value, expires_at = await backend.kv_get("alice", "run:1")
    assert value == "phase1"
    assert expires_at == expires
    ticks[0] = 1061.0
    with pytest.raises(MemoryEntryNotFoundError):
        await backend.kv_get("alice", "run:1")
    # Lazy expiry removed the record entirely.
    with pytest.raises(MemoryEntryNotFoundError):
        await backend.kv_delete("alice", "run:1")


async def test_kv_without_ttl_never_expires(tmp_path):
    ticks = [1000.0]
    backend = make_backend(tmp_path, clock=lambda: ticks[0])
    assert await backend.kv_set("alice", "pin", "value", None) is None
    ticks[0] = 10_000_000.0
    value, expires_at = await backend.kv_get("alice", "pin")
    assert (value, expires_at) == ("value", None)


async def test_kv_key_cap_is_enforced(tmp_path):
    backend = make_backend(tmp_path, kv_max_keys=2)
    await backend.kv_set("alice", "one", "1", None)
    await backend.kv_set("alice", "two", "2", None)
    # Overwriting an existing key is not a new key.
    await backend.kv_set("alice", "two", "2b", None)
    with pytest.raises(MemoryBackendError):
        await backend.kv_set("alice", "three", "3", None)


async def test_kv_owners_are_isolated(tmp_path):
    backend = make_backend(tmp_path)
    await backend.kv_set("alice", "shared-name", "alice value", None)
    with pytest.raises(MemoryEntryNotFoundError):
        await backend.kv_get("bob", "shared-name")


async def test_owner_identity_never_shapes_a_path(tmp_path):
    backend = make_backend(tmp_path)
    owner = "../../evil/../owner"
    await backend.store(owner, "prefs", "fact", {}, None)
    for record in tmp_path.rglob("*.json"):
        assert record.resolve().is_relative_to(tmp_path.resolve())
        payload = json.loads(record.read_text())
        assert "evil" not in str(record)
        assert payload["content"] == "fact"
