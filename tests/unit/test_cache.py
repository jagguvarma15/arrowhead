from fastmcp import Client


async def test_tool_list_carries_cache_hints(stdio_transport):
    from arrowhead.server import create_server

    async with Client(create_server()) as client:
        result = await client.list_tools_mcp()

    assert result.meta is not None
    assert result.meta["ttlMs"] == 3_600_000
    assert result.meta["cacheScope"] == "private"
    names = {tool.name for tool in result.tools}
    assert {"safe_fetch", "calculate", "read_file", "doc_search", "doc_read"} <= names


async def test_resource_and_prompt_lists_carry_cache_hints(stdio_transport):
    from arrowhead.server import create_server

    async with Client(create_server()) as client:
        resources = await client.list_resources_mcp()
        prompts = await client.list_prompts_mcp()

    for result in (resources, prompts):
        assert result.meta is not None
        assert result.meta["ttlMs"] == 3_600_000
        assert result.meta["cacheScope"] == "private"


async def test_resource_read_carries_a_shorter_ttl(stdio_transport):
    from arrowhead.server import create_server

    async with Client(create_server()) as client:
        result = await client.read_resource_mcp("docs://index")

    assert result.meta is not None
    assert result.meta["ttlMs"] == 60_000
    assert result.meta["cacheScope"] == "private"


async def test_ttl_is_configurable(stdio_transport, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_TOOL_LIST_TTL_MS", "60000")
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    from arrowhead.server import create_server

    async with Client(create_server()) as client:
        result = await client.list_tools_mcp()

    assert result.meta["ttlMs"] == 60000
