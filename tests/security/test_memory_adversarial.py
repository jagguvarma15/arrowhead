"""Adversarial tests for the memory and scratchpad tools.

Every caller-supplied name lands on a jailed filesystem path, so each
tool's namespace, id, and key arguments are driven with the shared
traversal and oversize payload sets; all must be refused before any
filesystem work, and nothing may ever be created outside the memory
root.
"""

import pytest

from arrowhead.auth.principal import as_principal
from arrowhead.errors import ToolError
from arrowhead.tools.kv import kv_delete, kv_get, kv_set
from arrowhead.tools.memory import (
    memory_delete,
    memory_list,
    memory_search,
    memory_store,
)
from tests.security.payloads import OVERSIZED_INPUTS, PATH_TRAVERSAL_PAYLOADS

SCOPES = {"memory:read", "memory:write"}


@pytest.mark.parametrize("payload", PATH_TRAVERSAL_PAYLOADS)
async def test_traversal_namespaces_are_refused(memory_jail, payload):
    with as_principal("mallory", SCOPES):
        with pytest.raises(ToolError):
            await memory_store(namespace=payload, content="x")
        with pytest.raises(ToolError):
            await memory_search(namespace=payload, query="x")
        with pytest.raises(ToolError):
            await memory_list(namespace=payload)
        with pytest.raises(ToolError):
            await memory_delete(namespace=payload, id="ab" * 16)
    assert list(memory_jail.rglob("*")) == []


@pytest.mark.parametrize("payload", PATH_TRAVERSAL_PAYLOADS)
async def test_traversal_ids_are_refused(memory_jail, payload):
    with as_principal("mallory", SCOPES):
        with pytest.raises(ToolError):
            await memory_delete(namespace="prefs", id=payload)
        with pytest.raises(ToolError):
            await memory_store(namespace="prefs", content="x", id=payload)
    assert list(memory_jail.rglob("*")) == []


@pytest.mark.parametrize("payload", PATH_TRAVERSAL_PAYLOADS)
async def test_traversal_keys_are_refused(memory_jail, payload):
    with as_principal("mallory", SCOPES):
        with pytest.raises(ToolError):
            await kv_set(key=payload, value="v")
        with pytest.raises(ToolError):
            await kv_get(key=payload)
        with pytest.raises(ToolError):
            await kv_delete(key=payload)
    assert list(memory_jail.rglob("*")) == []


async def test_oversized_names_are_refused(memory_jail):
    long_path = OVERSIZED_INPUTS["path"]
    with as_principal("mallory", SCOPES):
        with pytest.raises(ToolError):
            await memory_store(namespace=long_path, content="x")
        with pytest.raises(ToolError):
            await kv_set(key=long_path, value="v")
    assert list(memory_jail.rglob("*")) == []


async def test_a_hostile_owner_identity_stays_jailed(memory_jail):
    # Identity is not an argument, but a deployment's subjects are
    # free-form; even a traversal-shaped subject must never shape a path.
    with as_principal("../../etc/../mallory", SCOPES):
        await memory_store(namespace="prefs", content="fact")
        await kv_set(key="state", value="v")
    for created in memory_jail.rglob("*"):
        assert created.resolve().is_relative_to(memory_jail.resolve())


async def test_search_query_never_reaches_the_filesystem_as_a_path(
    memory_jail,
):
    with as_principal("mallory", SCOPES):
        await memory_store(namespace="prefs", content="benign fact")
        found = await memory_search(
            namespace="prefs", query="../../etc/passwd"
        )
    assert found["results"] == []
