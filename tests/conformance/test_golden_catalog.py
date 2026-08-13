"""The catalog a client sees must match the recorded golden fixture.

The fixture pins the semantic surface of every component: names,
descriptions, input schema shape, annotations, output schema presence, and
the scope map. Any migration or refactor that changes what a connected
client sees fails here first, and a deliberate surface change must update
the fixture in the same review.

The test is framework-agnostic on purpose: it lists components over the
in-memory client of whichever MCP stack is installed, so the same file
guards the surface before and after an SDK migration.
"""

import json
from contextlib import contextmanager
from pathlib import Path

GOLDEN_PATH = Path(__file__).parent.parent / "fixtures" / "tool_list_golden.json"


def _client_class():
    try:
        from mcp import Client
    except ImportError:
        from fastmcp import Client
    return Client


@contextmanager
def _force_stdio():
    # The legacy stack hides scoped components from in-memory clients unless
    # the transport is pinned; the current stack needs no such override.
    try:
        from fastmcp.server import context as fastmcp_context
    except ImportError:
        yield
        return
    token = fastmcp_context._current_transport.set("stdio")
    try:
        yield
    finally:
        fastmcp_context._current_transport.reset(token)


def _get(obj, camel: str, snake: str):
    value = getattr(obj, camel, None)
    if value is None:
        value = getattr(obj, snake, None)
    return value


def _items(result, attr: str):
    found = getattr(result, attr, None)
    return list(result) if found is None else list(found)


def _annotations(obj) -> dict:
    ann = getattr(obj, "annotations", None)
    if ann is None:
        return {}
    return dict(sorted(ann.model_dump(by_alias=True, exclude_none=True).items()))


async def _list_catalog():
    from arrowhead.server import create_server

    client_cls = _client_class()
    with _force_stdio():
        async with client_cls(create_server()) as client:
            if hasattr(client, "list_tools_mcp"):
                tools = _items(await client.list_tools_mcp(), "tools")
                resources = _items(await client.list_resources_mcp(), "resources")
                templates = _items(
                    await client.list_resource_templates_mcp(), "resourceTemplates"
                )
                prompts = _items(await client.list_prompts_mcp(), "prompts")
            else:
                tools = _items(await client.list_tools(), "tools")
                resources = _items(await client.list_resources(), "resources")
                templates = _items(
                    await client.list_resource_templates(), "resource_templates"
                )
                prompts = _items(await client.list_prompts(), "prompts")
    return tools, resources, templates, prompts


async def test_catalog_matches_golden_fixture():
    from arrowhead.auth.scopes import TOOL_SCOPES

    golden = json.loads(GOLDEN_PATH.read_text())
    tools, resources, templates, prompts = await _list_catalog()

    observed_tools = []
    for tool in sorted(tools, key=lambda t: t.name):
        input_schema = _get(tool, "inputSchema", "input_schema") or {}
        observed_tools.append(
            {
                "name": tool.name,
                "description": tool.description,
                "input_required": sorted(input_schema.get("required", [])),
                "input_properties": sorted(
                    (input_schema.get("properties") or {}).keys()
                ),
                "annotations": _annotations(tool),
                "has_output_schema": _get(tool, "outputSchema", "output_schema")
                is not None,
                "scope": TOOL_SCOPES[tool.name],
            }
        )
    assert observed_tools == golden["tools"]

    observed_resources = [
        {
            "uri": str(_get(r, "uri", "uri")),
            "description": r.description,
            "mime_type": _get(r, "mimeType", "mime_type"),
        }
        for r in sorted(resources, key=lambda r: str(r.uri))
    ]
    assert observed_resources == golden["resources"]

    observed_templates = [
        {
            "uri_template": str(_get(t, "uriTemplate", "uri_template")),
            "description": t.description,
            "mime_type": _get(t, "mimeType", "mime_type"),
        }
        for t in sorted(
            templates, key=lambda t: str(_get(t, "uriTemplate", "uri_template"))
        )
    ]
    assert observed_templates == golden["resource_templates"]

    observed_prompts = [
        {"name": p.name, "description": p.description}
        for p in sorted(prompts, key=lambda p: p.name)
    ]
    assert observed_prompts == golden["prompts"]
