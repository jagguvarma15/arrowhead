"""Command-line entry point for running and inspecting the server.

    arrowhead serve        run the server over the configured transport
    arrowhead list-tools   print each tool and the scope it requires

Configuration is read from the environment (the ARROWHEAD_ prefix); see the
settings module for the full set.
"""

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arrowhead",
        description="Run the hardened MCP server or inspect the tools it exposes.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "serve", help="Run the server over the configured transport."
    )
    list_tools = subparsers.add_parser(
        "list-tools",
        help="Print each tool this server exposes and the scope it requires.",
    )
    list_tools.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help=(
            "Emit the full catalog as JSON: tools with input schemas and "
            "annotations, resources, resource templates, and prompts, exactly "
            "as a connected client would list them under the active profile."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        return _serve()
    if args.command == "list-tools":
        if args.as_json:
            return _list_tools_json()
        return _list_tools()
    return 1


def _serve() -> int:
    from arrowhead.server import main as run_server

    run_server()
    return 0


def _list_tools() -> int:
    from arrowhead.tools.catalog import TOOL_SPECS

    for spec in TOOL_SPECS:
        print(f"{spec.name}\t{spec.scope}")
    return 0


def _list_tools_json() -> int:
    import asyncio
    import json

    print(json.dumps(asyncio.run(_catalog_snapshot()), indent=2, sort_keys=True))
    return 0


async def _catalog_snapshot() -> dict:
    """The client-visible catalog, listed over the same path the wire uses.

    The snapshot is taken by a real in-process client against a freshly built
    server, so it reflects the active profile and any disabled tools rather
    than the static spec list, and the schemas are exactly the SDK-derived
    ones a connected client receives.
    """
    from mcp import Client

    from arrowhead.auth.scopes import TOOL_SCOPES
    from arrowhead.server import create_server
    from arrowhead.tools.catalog import PROMPT_SPECS, RESOURCE_SPECS, TOOL_SPECS

    tool_families = {spec.name: spec.family for spec in TOOL_SPECS}
    resource_specs = {spec.uri: spec for spec in RESOURCE_SPECS}
    prompt_specs = {spec.name: spec for spec in PROMPT_SPECS}

    async with Client(create_server(), raise_exceptions=True) as client:
        tools = (await client.list_tools()).tools
        resources = (await client.list_resources()).resources
        templates = (await client.list_resource_templates()).resource_templates
        prompts = (await client.list_prompts()).prompts

    def annotations(component) -> dict:
        noted = getattr(component, "annotations", None)
        if noted is None:
            return {}
        return noted.model_dump(by_alias=True, exclude_none=True)

    snapshot: dict = {"tools": [], "resources": [], "prompts": []}
    for tool in sorted(tools, key=lambda entry: entry.name):
        snapshot["tools"].append(
            {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
                "outputSchema": tool.output_schema,
                "annotations": annotations(tool),
                "scope": TOOL_SCOPES.get(tool.name),
                "family": tool_families.get(tool.name),
            }
        )
    for resource in sorted(resources, key=lambda entry: str(entry.uri)):
        spec = resource_specs.get(str(resource.uri))
        snapshot["resources"].append(
            {
                "uri": str(resource.uri),
                "name": resource.name,
                "description": resource.description,
                "mimeType": resource.mime_type,
                "scope": spec.scope if spec else None,
                "family": spec.family if spec else None,
            }
        )
    for template in sorted(templates, key=lambda entry: entry.uri_template):
        spec = resource_specs.get(template.uri_template)
        snapshot["resources"].append(
            {
                "uriTemplate": template.uri_template,
                "name": template.name,
                "description": template.description,
                "mimeType": template.mime_type,
                "scope": spec.scope if spec else None,
                "family": spec.family if spec else None,
            }
        )
    for prompt in sorted(prompts, key=lambda entry: entry.name):
        spec = prompt_specs.get(prompt.name)
        snapshot["prompts"].append(
            {
                "name": prompt.name,
                "description": prompt.description,
                "arguments": [
                    argument.model_dump(by_alias=True, exclude_none=True)
                    for argument in prompt.arguments or []
                ],
                "scope": spec.scope if spec else None,
                "family": spec.family if spec else None,
            }
        )
    return snapshot


if __name__ == "__main__":
    sys.exit(main())
