import pytest
from fastmcp.exceptions import ToolError
from fastmcp.server.elicitation import AcceptedElicitation, DeclinedElicitation

from arrowhead.authz.enforce import get_authorizer
from arrowhead.config import get_settings
from arrowhead.tools.doc_read import doc_read
from arrowhead.tools.doc_write import doc_write


class FakeContext:
    def __init__(self, result):
        self._result = result

    async def elicit(self, message, response_type=None):
        return self._result


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
            "a.txt", "second", overwrite=True, ctx=FakeContext(DeclinedElicitation())
        )
    assert (docs / "a.txt").read_text() == "first"


async def test_overwrite_accepted_replaces(docs):
    await doc_write("a.txt", "first")
    result = await doc_write(
        "a.txt",
        "second",
        overwrite=True,
        ctx=FakeContext(AcceptedElicitation(data=None)),
    )
    assert result["created"] is False
    assert (docs / "a.txt").read_text() == "second"


async def test_overwrite_without_confirmation_channel_uses_explicit_flag(docs):
    # No context (stdio / non-eliciting client): the explicit overwrite flag
    # stands in as the opt-in.
    await doc_write("a.txt", "first")
    await doc_write("a.txt", "second", overwrite=True, ctx=None)
    assert (docs / "a.txt").read_text() == "second"


async def test_confirmation_skipped_when_disabled(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_REQUIRE_WRITE_CONFIRMATION", "false")
    get_settings.cache_clear()
    await doc_write("a.txt", "first")
    await doc_write(
        "a.txt", "second", overwrite=True, ctx=FakeContext(DeclinedElicitation())
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
