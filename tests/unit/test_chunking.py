import pytest

from arrowhead.content.chunking import ChunkingError, chunk_text


def test_windows_carry_overlap():
    chunks = chunk_text("abcdefghij", max_chars=4, overlap=1)
    assert chunks == ["abcd", "defg", "ghij", "j"]


def test_no_overlap_tiles_the_text():
    assert chunk_text("abcdef", max_chars=3, overlap=0) == ["abc", "def"]


def test_empty_or_whitespace_yields_nothing():
    assert chunk_text("", max_chars=10, overlap=0) == []
    assert chunk_text("   \n\t ", max_chars=10, overlap=0) == []


def test_chunk_count_is_capped():
    chunks = chunk_text("a" * 100, max_chars=5, overlap=0, max_chunks=3)
    assert len(chunks) == 3


def test_overlap_must_be_less_than_max():
    with pytest.raises(ChunkingError):
        chunk_text("abc", max_chars=4, overlap=4)


def test_max_chars_must_be_positive():
    with pytest.raises(ChunkingError):
        chunk_text("abc", max_chars=0, overlap=0)


def test_control_characters_are_stripped():
    chunks = chunk_text("a\x1b[31mb", max_chars=100, overlap=0)
    assert "\x1b" not in chunks[0]
