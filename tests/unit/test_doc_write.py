import pytest
from mcp.server.elicitation import AcceptedElicitation, DeclinedElicitation

from arrowhead.authz.confirmation import ConfirmOverwrite
from arrowhead.authz.enforce import get_authorizer
from arrowhead.config import get_settings
from arrowhead.errors import ToolError
from arrowhead.tools.doc_read import doc_read
from arrowhead.tools.doc_write import doc_write

ACCEPTED = AcceptedElicitation(data=ConfirmOverwrite(confirm=True))


async def test_write_new_document(docs):
    result = await doc_write("notes/a.md", "# Hello")
    assert result["created"] is True
    assert result["path"] == "notes/a.md"
    assert (docs / "notes" / "a.md").read_text() == "# Hello"


async def test_written_document_round_trips_through_read(docs):
    await doc_write("note.txt", "round trip")
    assert "round trip" in (await doc_read("note.txt"))["content"]


async def test_no_clobber_without_overwrite(docs):
    await doc_write("a.txt", "first")
    with pytest.raises(ToolError):
        await doc_write("a.txt", "second")
    assert (docs / "a.txt").read_text() == "first"


async def test_overwrite_declined_blocks(docs):
    await doc_write("a.txt", "first")
    with pytest.raises(ToolError, match="declined"):
        await doc_write(
            "a.txt", "second", overwrite=True, confirmation=DeclinedElicitation()
        )
    assert (docs / "a.txt").read_text() == "first"


async def test_overwrite_answered_no_blocks(docs):
    await doc_write("a.txt", "first")
    with pytest.raises(ToolError, match="declined"):
        await doc_write(
            "a.txt",
            "second",
            overwrite=True,
            confirmation=AcceptedElicitation(data=ConfirmOverwrite(confirm=False)),
        )
    assert (docs / "a.txt").read_text() == "first"


async def test_overwrite_accepted_replaces(docs):
    await doc_write("a.txt", "first")
    result = await doc_write(
        "a.txt", "second", overwrite=True, confirmation=ACCEPTED
    )
    assert result["created"] is False
    assert (docs / "a.txt").read_text() == "second"


async def test_overwrite_without_confirmation_channel_uses_explicit_flag(docs):
    # No resolved confirmation (a client that cannot elicit): the explicit
    # overwrite flag stands in as the opt-in.
    await doc_write("a.txt", "first")
    await doc_write("a.txt", "second", overwrite=True)
    assert (docs / "a.txt").read_text() == "second"


async def test_confirmation_skipped_when_disabled(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_REQUIRE_WRITE_CONFIRMATION", "false")
    get_settings.cache_clear()
    await doc_write("a.txt", "first")
    await doc_write(
        "a.txt", "second", overwrite=True, confirmation=DeclinedElicitation()
    )
    assert (docs / "a.txt").read_text() == "second"


async def test_json_canonicalized_on_write(docs):
    await doc_write("data.json", '{"b": 2, "a": 1}')
    assert (docs / "data.json").read_text() == '{\n  "a": 1,\n  "b": 2\n}'


async def test_invalid_json_rejected(docs):
    with pytest.raises(ToolError):
        await doc_write("data.json", "{not json}")


@pytest.mark.parametrize(
    "path", ["../../etc/passwd.txt", "script.sh", "no_extension", "/abs.txt"]
)
async def test_bad_paths_rejected(docs, path):
    with pytest.raises(ToolError):
        await doc_write(path, "x")


async def test_null_byte_content_rejected(docs):
    with pytest.raises(ToolError):
        await doc_write("a.txt", "bad\x00content")


async def test_oversized_content_rejected(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_DOC_WRITE_MAX_BYTES", "8")
    get_settings.cache_clear()
    with pytest.raises(ToolError):
        await doc_write("a.txt", "x" * 64)


async def test_cross_subject_write_denied(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    get_settings.cache_clear()
    get_authorizer.cache_clear()
    # The default policy confines writes to the caller's own namespace.
    # The direct-call identity is "anonymous".
    await doc_write("anonymous/mine.txt", "ok")
    with pytest.raises(ToolError):
        await doc_write("someone-else/theirs.txt", "no")


def _answering_client(server, answers: list):
    """A client whose elicitation callback records questions and answers."""
    from mcp import Client
    from mcp.types import ElicitResult

    asked = []

    async def on_elicit(context, params):
        asked.append(params.message)
        return ElicitResult(**answers.pop(0))

    return Client(server, elicitation_callback=on_elicit), asked


async def test_overwrite_asks_the_connected_client(docs):
    """The full wire round trip: the framework resolves the confirmation by
    asking the client, and the answer decides the write."""
    from arrowhead.server import create_server

    server = create_server()
    client, asked = _answering_client(
        server,
        [
            {"action": "accept", "content": {"confirm": True}},
            {"action": "decline"},
        ],
    )
    async with client:
        await client.call_tool(
            "doc_write", {"path": "a.txt", "content": "first"}
        )
        accepted = await client.call_tool(
            "doc_write",
            {"path": "a.txt", "content": "second", "overwrite": True},
        )
        assert accepted.is_error is False
        declined = await client.call_tool(
            "doc_write",
            {"path": "a.txt", "content": "third", "overwrite": True},
        )
        assert declined.is_error
        assert "declined" in declined.content[0].text

    assert len(asked) == 2
    assert all("a.txt" in message for message in asked)
    assert (docs / "a.txt").read_text() == "second"
