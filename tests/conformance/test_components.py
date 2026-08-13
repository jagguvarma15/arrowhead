"""Protocol conformance for the resource, prompt, and completion primitives.

Exercises the real wire path through an in-memory client: the components
register, list, and respond exactly as a remote client would see them.
"""

from mcp import Client
from mcp.types import PromptReference, ResourceTemplateReference

from arrowhead.server import create_server


async def test_resources_list_and_read(docs):
    (docs / "notes").mkdir()
    (docs / "notes" / "todo.md").write_text("# Todo\nbuy milk")
    async with Client(create_server(), raise_exceptions=True) as client:
        templates = {
            t.uri_template
            for t in (await client.list_resource_templates()).resource_templates
        }
        assert "doc://{+path}" in templates
        resources = {
            str(r.uri) for r in (await client.list_resources()).resources
        }
        assert "docs://index" in resources
        contents = (await client.read_resource("doc://notes/todo.md")).contents
        assert contents[0].text == "# Todo\nbuy milk"


async def test_prompts_list_and_get(docs):
    async with Client(create_server(), raise_exceptions=True) as client:
        names = {p.name for p in (await client.list_prompts()).prompts}
        assert {"summarize_document", "audit_corpus"} <= names
        result = await client.get_prompt(
            "summarize_document", {"path": "notes/x.md"}
        )
        assert "doc://notes/x.md" in result.messages[0].content.text


async def test_completion_over_the_protocol(docs):
    (docs / "notes").mkdir()
    (docs / "notes" / "a.md").write_text("x")
    (docs / "notes" / "b.md").write_text("y")
    async with Client(create_server(), raise_exceptions=True) as client:
        result = await client.complete(
            ref=PromptReference(type="ref/prompt", name="summarize_document"),
            argument={"name": "path", "value": "notes/"},
        )
        assert result.completion.values == ["notes/a.md", "notes/b.md"]
        # A resource-template reference completes the same way.
        result = await client.complete(
            ref=ResourceTemplateReference(
                type="ref/resource", uri="doc://{+path}"
            ),
            argument={"name": "path", "value": "notes/a"},
        )
        assert result.completion.values == ["notes/a.md"]
