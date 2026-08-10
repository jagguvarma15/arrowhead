"""Protocol conformance for the resource, prompt, and completion primitives.

Exercises the real wire path through an in-memory client: the components
register, list, and respond exactly as a remote client would see them.
"""

from fastmcp import Client
from mcp.types import PromptReference, ResourceTemplateReference

from arrowhead.server import create_server


async def test_resources_list_and_read(docs, stdio_transport):
    (docs / "notes").mkdir()
    (docs / "notes" / "todo.md").write_text("# Todo\nbuy milk")
    async with Client(create_server()) as client:
        templates = {t.uriTemplate for t in await client.list_resource_templates()}
        assert "doc://{path*}" in templates
        resources = {str(r.uri) for r in await client.list_resources()}
        assert "docs://index" in resources
        contents = await client.read_resource("doc://notes/todo.md")
        assert contents[0].text == "# Todo\nbuy milk"


async def test_prompts_list_and_get(docs, stdio_transport):
    async with Client(create_server()) as client:
        names = {p.name for p in await client.list_prompts()}
        assert {"summarize_document", "audit_corpus"} <= names
        result = await client.get_prompt(
            "summarize_document", {"path": "notes/x.md"}
        )
        assert "doc://notes/x.md" in result.messages[0].content.text


async def test_completion_over_the_protocol(docs, stdio_transport):
    (docs / "notes").mkdir()
    (docs / "notes" / "a.md").write_text("x")
    (docs / "notes" / "b.md").write_text("y")
    async with Client(create_server()) as client:
        completion = await client.complete(
            ref=PromptReference(type="ref/prompt", name="summarize_document"),
            argument={"name": "path", "value": "notes/"},
        )
        assert completion.values == ["notes/a.md", "notes/b.md"]
        # A resource-template reference completes the same way.
        completion = await client.complete(
            ref=ResourceTemplateReference(
                type="ref/resource", uri="doc://{path*}"
            ),
            argument={"name": "path", "value": "notes/a"},
        )
        assert completion.values == ["notes/a.md"]
