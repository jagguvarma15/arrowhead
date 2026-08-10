import pytest
from fastmcp import Client
from mcp.shared.exceptions import McpError

from arrowhead.config import get_settings


async def test_disabled_tool_is_hidden_and_refused(
    monkeypatch, stdio_transport
):
    monkeypatch.setenv("ARROWHEAD_DISABLED_TOOLS", "safe_fetch")
    get_settings.cache_clear()
    from arrowhead.server import create_server

    async with Client(create_server()) as client:
        tools = {tool.name for tool in await client.list_tools()}
        assert "safe_fetch" not in tools
        assert {"calculate", "read_file"} <= tools

        result = await client.call_tool(
            "safe_fetch",
            {"url": "https://example.com/"},
            raise_on_error=False,
        )
        assert result.is_error
        assert "disabled" in result.content[0].text

        # Other tools keep working.
        result = await client.call_tool("calculate", {"expression": "1 + 1"})
        assert result.data == 2.0


async def test_disabled_prompt_is_hidden_and_refused(
    monkeypatch, stdio_transport
):
    monkeypatch.setenv("ARROWHEAD_DISABLED_TOOLS", "summarize_document")
    get_settings.cache_clear()
    from arrowhead.server import create_server

    async with Client(create_server()) as client:
        prompts = {p.name for p in await client.list_prompts()}
        assert "summarize_document" not in prompts
        assert "audit_corpus" in prompts

        with pytest.raises(McpError, match="disabled"):
            await client.get_prompt("summarize_document", {"path": "a.md"})


def test_disabled_tools_parsing():
    from arrowhead.config import Settings

    assert Settings(disabled_tools=" safe_fetch, read_file ").disabled_tool_set() == {
        "safe_fetch",
        "read_file",
    }
    assert Settings(disabled_tools="").disabled_tool_set() == set()
