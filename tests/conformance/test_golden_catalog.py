"""The catalog a client sees must match the recorded golden fixture.

The fixture pins the semantic surface of every component as the previous
stack served it: names, descriptions, input schema shape, annotations,
output schema presence, and the scope map. Any migration or refactor that
changes what a connected client sees fails here first, and a deliberate
surface change must update the fixture in the same review.
"""

import json
from pathlib import Path

from mcp import Client

GOLDEN_PATH = Path(__file__).parent.parent / "fixtures" / "tool_list_golden.json"


def _annotations(obj) -> dict:
    ann = getattr(obj, "annotations", None)
    if ann is None:
        return {}
    return dict(sorted(ann.model_dump(by_alias=True, exclude_none=True).items()))


async def _list_catalog():
    from arrowhead.server import create_server

    async with Client(create_server(), raise_exceptions=True) as client:
        tools = (await client.list_tools()).tools
        resources = (await client.list_resources()).resources
        templates = (
            await client.list_resource_templates()
        ).resource_templates
        prompts = (await client.list_prompts()).prompts
    return tools, resources, templates, prompts


async def test_catalog_matches_golden_fixture():
    from arrowhead.auth.scopes import TOOL_SCOPES

    golden = json.loads(GOLDEN_PATH.read_text())
    tools, resources, templates, prompts = await _list_catalog()

    observed_tools = []
    for tool in sorted(tools, key=lambda t: t.name):
        input_schema = tool.input_schema or {}
        observed_tools.append(
            {
                "name": tool.name,
                "description": tool.description,
                "input_required": sorted(input_schema.get("required", [])),
                "input_properties": sorted(
                    (input_schema.get("properties") or {}).keys()
                ),
                "annotations": _annotations(tool),
                "has_output_schema": tool.output_schema is not None,
                "scope": TOOL_SCOPES[tool.name],
            }
        )
    assert observed_tools == golden["tools"]

    observed_resources = [
        {
            "uri": str(r.uri),
            "description": r.description,
            "mime_type": r.mime_type,
        }
        for r in sorted(resources, key=lambda r: str(r.uri))
    ]
    assert observed_resources == golden["resources"]

    observed_templates = [
        {
            "uri_template": str(t.uri_template),
            "description": t.description,
            "mime_type": t.mime_type,
        }
        for t in sorted(templates, key=lambda t: str(t.uri_template))
    ]
    assert observed_templates == golden["resource_templates"]

    observed_prompts = [
        {"name": p.name, "description": p.description}
        for p in sorted(prompts, key=lambda p: p.name)
    ]
    assert observed_prompts == golden["prompts"]
