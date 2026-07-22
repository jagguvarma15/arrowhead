"""The Arrowhead facade is the importable front door: it runs calls through
the same hardened path as the server, honors injected settings at call time,
and adopts the current principal.
"""

import pytest
from fastmcp.exceptions import ToolError

from arrowhead import Arrowhead, Settings
from arrowhead.auth.identity import caller_identity


async def test_call_runs_a_tool_and_returns_its_result():
    app = Arrowhead()
    result = await app.call("calculate", {"expression": "2 * (3 + 4)"})
    assert result.structured_content == {"result": 14.0}


async def test_a_refused_call_raises_like_it_does_over_the_wire():
    app = Arrowhead()
    with pytest.raises(ToolError):
        await app.call("calculate", {"expression": "import os"})


async def test_injected_settings_take_effect_for_a_call():
    # The length cap is read when the tool runs, so an injected value must
    # reach the call, not only the build.
    app = Arrowhead(settings=Settings(expression_max_length=3))
    with pytest.raises(ToolError):
        await app.call("calculate", {"expression": "2 * (3 + 4)"})


async def test_the_same_handle_reuses_one_server():
    app = Arrowhead()
    assert app.server is app.server


async def test_list_tools_returns_the_catalog_when_auth_is_off():
    app = Arrowhead()
    from arrowhead.tools.catalog import TOOL_SPECS

    names = {tool.name for tool in await app.list_tools()}
    assert names == {spec.name for spec in TOOL_SPECS}


async def test_as_principal_adopts_the_caller():
    app = Arrowhead()
    assert caller_identity() == "anonymous"
    with app.as_principal("service:etl", {"docs:read"}):
        assert caller_identity() == "service:etl"
    assert caller_identity() == "anonymous"
