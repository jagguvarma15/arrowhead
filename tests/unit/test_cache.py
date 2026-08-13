"""Cacheable results carry freshness hints.

A list of tools, resources, prompts, or resource templates, and the
content of a single resource, change only on deploy or on a write, so
clients are told they may cache them through the protocol's native
ttl and scope fields. The scope is private rather than public because
visibility is per caller: scope checks, the per-resource policy, and the
kill switch can hide from one caller what another sees, so a shared
intermediary must not serve one caller's result to another.
"""

from mcp import Client


async def test_tool_list_carries_cache_hints():
    from arrowhead.server import create_server

    async with Client(create_server(), raise_exceptions=True) as client:
        result = await client.list_tools()

    assert result.ttl_ms == 3_600_000
    assert result.cache_scope == "private"
    names = {tool.name for tool in result.tools}
    assert {"safe_fetch", "calculate", "read_file", "doc_search", "doc_read"} <= names


async def test_resource_and_prompt_lists_carry_cache_hints():
    from arrowhead.server import create_server

    async with Client(create_server(), raise_exceptions=True) as client:
        resources = await client.list_resources()
        prompts = await client.list_prompts()

    for result in (resources, prompts):
        assert result.ttl_ms == 3_600_000
        assert result.cache_scope == "private"


async def test_resource_read_carries_a_shorter_ttl():
    from arrowhead.server import create_server

    async with Client(create_server(), raise_exceptions=True) as client:
        result = await client.read_resource("docs://index")

    assert result.ttl_ms == 60_000
    assert result.cache_scope == "private"


async def test_ttl_is_configurable(monkeypatch):
    monkeypatch.setenv("ARROWHEAD_TOOL_LIST_TTL_MS", "60000")
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    from arrowhead.server import create_server

    async with Client(create_server(), raise_exceptions=True) as client:
        result = await client.list_tools()

    assert result.ttl_ms == 60000
