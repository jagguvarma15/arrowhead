"""Token economy checks.

The tool list rides along in every model context that can call this
server, so its size is budgeted per tool: each tool schema must stay under
an average ceiling, which scales as tools are added rather than needing a
new absolute number each time. The estimator is the standard rough cut of
one token per four characters of serialized JSON.
"""

import inspect
import json

from fastmcp import Client

PER_TOOL_TOKEN_BUDGET = 220
CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    return -(-len(text) // CHARS_PER_TOKEN)


async def _list_tools(stdio_transport):
    from arrowhead.server import create_server

    async with Client(create_server()) as client:
        return (await client.list_tools_mcp()).tools


async def test_tool_schemas_fit_the_per_tool_budget(stdio_transport):
    tools = await _list_tools(stdio_transport)
    serialized = json.dumps([tool.model_dump(exclude_none=True) for tool in tools])
    average = estimate_tokens(serialized) / len(tools)
    assert average < PER_TOOL_TOKEN_BUDGET, (
        f"tool schemas average ~{average:.0f} tokens each, "
        f"budget is {PER_TOOL_TOKEN_BUDGET}"
    )


async def test_every_tool_description_includes_an_example(stdio_transport):
    tools = await _list_tools(stdio_transport)
    for tool in tools:
        assert "Example:" in (tool.description or ""), tool.name


def test_io_bound_tools_are_async():
    """Network and filesystem tools must not block the event loop."""
    from arrowhead.tools.doc_read import doc_read
    from arrowhead.tools.doc_search import doc_search
    from arrowhead.tools.read_file import read_file
    from arrowhead.tools.safe_fetch import safe_fetch

    for tool in (safe_fetch, read_file, doc_read, doc_search):
        assert inspect.iscoroutinefunction(tool), tool.__name__
