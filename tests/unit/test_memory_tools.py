"""The memory tools: validation, owner scoping, honest sanitized recall."""

import pytest

from arrowhead.auth.principal import as_principal
from arrowhead.content.provenance import UNTRUSTED_NOTICE
from arrowhead.errors import ToolError
from arrowhead.tools.memory import (
    memory_delete,
    memory_list,
    memory_search,
    memory_store,
)

SCOPES = {"memory:read", "memory:write"}


async def test_store_search_list_delete_round_trip(memory_jail):
    with as_principal("alice", SCOPES):
        stored = await memory_store(
            namespace="prefs",
            content="prefers metric units",
            metadata={"kind": "preference"},
        )
        assert stored["status"] == "created"
        found = await memory_search(namespace="prefs", query="metric")
        assert found["notice"] == UNTRUSTED_NOTICE
        assert found["recall"] == "keyword"
        assert [hit["id"] for hit in found["results"]] == [stored["id"]]
        listed = await memory_list(namespace="prefs")
        assert [entry["id"] for entry in listed["entries"]] == [stored["id"]]
        assert listed["entries"][0]["metadata"] == {"kind": "preference"}
        deleted = await memory_delete(namespace="prefs", id=stored["id"])
        assert deleted == {"id": stored["id"], "deleted": True}
        assert (await memory_list(namespace="prefs"))["entries"] == []


async def test_identical_content_reports_unchanged(memory_jail):
    with as_principal("alice", SCOPES):
        first = await memory_store(namespace="prefs", content="same fact")
        second = await memory_store(namespace="prefs", content="same fact")
    assert second == {"id": first["id"], "status": "unchanged"}


async def test_explicit_id_update_and_unknown_id(memory_jail):
    with as_principal("alice", SCOPES):
        stored = await memory_store(namespace="prefs", content="old")
        updated = await memory_store(
            namespace="prefs", content="new", id=stored["id"]
        )
        assert updated == {"id": stored["id"], "status": "updated"}
        with pytest.raises(ToolError):
            await memory_store(namespace="prefs", content="x", id="ab" * 16)


async def test_invalid_namespace_and_id_shapes_are_refused(memory_jail):
    with as_principal("alice", SCOPES):
        with pytest.raises(ToolError):
            await memory_store(namespace="../etc", content="x")
        with pytest.raises(ToolError):
            await memory_search(namespace="No/Slash", query="x")
        with pytest.raises(ToolError):
            await memory_delete(namespace="prefs", id="../../escape")


async def test_content_and_metadata_caps_are_enforced(
    memory_jail, configure_env
):
    configure_env(
        ARROWHEAD_MEMORY_MAX_CONTENT_BYTES="10",
        ARROWHEAD_MEMORY_MAX_METADATA_BYTES="20",
    )
    with as_principal("alice", SCOPES):
        with pytest.raises(ToolError):
            await memory_store(namespace="prefs", content="x" * 11)
        with pytest.raises(ToolError):
            await memory_store(
                namespace="prefs",
                content="ok",
                metadata={"key": "v" * 40},
            )
        with pytest.raises(ToolError):
            await memory_store(
                namespace="prefs", content="ok2", metadata={"bad": object()}
            )


async def test_empty_content_is_refused(memory_jail):
    with as_principal("alice", SCOPES):
        with pytest.raises(ToolError):
            await memory_store(namespace="prefs", content="   ")


async def test_search_k_is_bounded_by_the_setting(memory_jail, configure_env):
    configure_env(ARROWHEAD_MEMORY_MAX_K="1")
    with as_principal("alice", SCOPES):
        await memory_store(namespace="notes", content="common one")
        await memory_store(namespace="notes", content="common two")
        found = await memory_search(namespace="notes", query="common", k=50)
    assert len(found["results"]) == 1


async def test_snippets_are_sanitized_and_capped(memory_jail, configure_env):
    configure_env(ARROWHEAD_SEARCH_SNIPPET_MAX_CHARS="12")
    with as_principal("alice", SCOPES):
        await memory_store(
            namespace="notes", content="alert \x1b[31mred\x1b[0m payload tail"
        )
        found = await memory_search(namespace="notes", query="alert")
    snippet = found["results"][0]["snippet"]
    assert "\x1b" not in snippet
    assert len(snippet) <= 12


async def test_owners_cannot_reach_each_others_memories(memory_jail):
    with as_principal("alice", SCOPES):
        stored = await memory_store(namespace="prefs", content="alice fact")
    with as_principal("bob", SCOPES):
        assert (await memory_list(namespace="prefs"))["entries"] == []
        with pytest.raises(ToolError):
            await memory_delete(namespace="prefs", id=stored["id"])
    with as_principal("alice", SCOPES):
        assert len((await memory_list(namespace="prefs"))["entries"]) == 1
