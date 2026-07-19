from arrowhead.content.provenance import UNTRUSTED_NOTICE, wrap_content


def test_wrap_carries_metadata_and_notice():
    wrapped = wrap_content(
        "the body",
        source="notes.md",
        content_format="md",
        retrieved_at="2026-07-19T00:00:00Z",
    )
    assert wrapped["notice"] == UNTRUSTED_NOTICE
    assert wrapped["metadata"]["source"] == "notes.md"
    assert wrapped["metadata"]["format"] == "md"
    assert wrapped["metadata"]["trust_level"] == "untrusted"
    assert wrapped["metadata"]["retrieved_at"] == "2026-07-19T00:00:00Z"
    assert "the body" in wrapped["content"]


def test_delimiters_are_randomized_per_call():
    first = wrap_content(
        "same", source="s", content_format="txt", retrieved_at="t"
    )
    second = wrap_content(
        "same", source="s", content_format="txt", retrieved_at="t"
    )
    assert first["content"] != second["content"]


def test_content_is_delimited():
    wrapped = wrap_content(
        "payload", source="s", content_format="txt", retrieved_at="t"
    )
    body = wrapped["content"]
    assert body.startswith("<<UNTRUSTED-")
    assert body.rstrip().endswith(">>")
    assert "payload" in body
