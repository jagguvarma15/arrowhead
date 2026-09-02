"""The scratchpad tools: round trip, TTL bounds, provenance envelope.

Lazy TTL expiry itself is proven against the backend with an injected
clock in test_memory_file_backend; here the tools' plumbing over it is
covered with real settings.
"""

import pytest

from arrowhead.auth.principal import as_principal
from arrowhead.errors import ToolError
from arrowhead.tools.kv import kv_delete, kv_get, kv_set

SCOPES = {"memory:read", "memory:write"}


async def test_set_get_delete_round_trip(memory_jail):
    with as_principal("alice", SCOPES):
        result = await kv_set(key="run:42:state", value="phase2")
        assert result == {"key": "run:42:state", "expires_at": None}
        fetched = await kv_get(key="run:42:state")
        assert "phase2" in fetched["content"]
        assert fetched["metadata"]["source"] == "kv:run:42:state"
        assert fetched["metadata"]["trust_level"] == "untrusted"
        deleted = await kv_delete(key="run:42:state")
        assert deleted == {"key": "run:42:state", "deleted": True}
        with pytest.raises(ToolError):
            await kv_get(key="run:42:state")


async def test_set_replaces_and_reports_expiry(memory_jail):
    with as_principal("alice", SCOPES):
        await kv_set(key="pin", value="old")
        result = await kv_set(key="pin", value="new", ttl_seconds=600)
        assert result["expires_at"] is not None
        fetched = await kv_get(key="pin")
    assert "new" in fetched["content"]
    assert "old" not in fetched["content"]


async def test_ttl_bounds_are_enforced(memory_jail, configure_env):
    configure_env(ARROWHEAD_KV_MAX_TTL_SECONDS="100")
    with as_principal("alice", SCOPES):
        with pytest.raises(ToolError):
            await kv_set(key="a", value="v", ttl_seconds=101)
        with pytest.raises(ToolError):
            await kv_set(key="a", value="v", ttl_seconds=0)
        with pytest.raises(ToolError):
            await kv_set(key="a", value="v", ttl_seconds=True)


async def test_value_and_key_shapes_are_enforced(memory_jail, configure_env):
    configure_env(ARROWHEAD_KV_MAX_VALUE_BYTES="8")
    with as_principal("alice", SCOPES):
        with pytest.raises(ToolError):
            await kv_set(key="big", value="x" * 9)
        with pytest.raises(ToolError):
            await kv_set(key="../escape", value="v")
        with pytest.raises(ToolError):
            await kv_set(key="nul", value="a\x00b")
        with pytest.raises(ToolError):
            await kv_get(key=".hidden")


async def test_value_is_sanitized_on_read(memory_jail):
    with as_principal("alice", SCOPES):
        await kv_set(key="term", value="clean \x1b[2Jwipe")
        fetched = await kv_get(key="term")
    assert "\x1b" not in fetched["content"]


async def test_owners_cannot_reach_each_others_keys(memory_jail):
    with as_principal("alice", SCOPES):
        await kv_set(key="shared-name", value="alice value")
    with as_principal("bob", SCOPES):
        with pytest.raises(ToolError):
            await kv_get(key="shared-name")
        with pytest.raises(ToolError):
            await kv_delete(key="shared-name")
