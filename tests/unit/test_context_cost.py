"""Token economy checks.

The tool list rides along in every model context that can call this
server, so its combined size is budgeted: all three schemas together
must stay under 500 estimated tokens. The estimator is the standard
rough cut of one token per four characters of serialized JSON.
"""

import inspect
import json

from fastmcp import Client

TOKEN_BUDGET = 500
CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    return -(-len(text) // CHARS_PER_TOKEN)


async def test_combined_tool_schemas_fit_the_token_budget(stdio_transport):
    from arrowhead.server import create_server

    async with Client(create_server()) as client:
        result = await client.list_tools_mcp()

    serialized = json.dumps(
        [tool.model_dump(exclude_none=True) for tool in result.tools]
    )
    tokens = estimate_tokens(serialized)
    assert tokens < TOKEN_BUDGET, (
        f"tool list costs ~{tokens} tokens, budget is {TOKEN_BUDGET}"
    )


def test_io_bound_tools_are_async():
    """Network and filesystem tools must not block the event loop."""
    from arrowhead.tools.read_file import read_file
    from arrowhead.tools.safe_fetch import safe_fetch

    assert inspect.iscoroutinefunction(safe_fetch)
    assert inspect.iscoroutinefunction(read_file)


def test_every_description_includes_an_example():
    from arrowhead.tools.calculate import calculate
    from arrowhead.tools.read_file import read_file
    from arrowhead.tools.safe_fetch import safe_fetch

    for tool in (safe_fetch, calculate, read_file):
        assert "Example:" in inspect.getdoc(tool)
