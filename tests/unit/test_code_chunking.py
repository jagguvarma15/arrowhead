"""Code chunks follow structure; prose chunking is untouched.

A Python file splits at its top-level definitions so a chunk carries a
whole function whenever it fits; unparsable source degrades to plain
windows; other code splits at blank-line blocks; and a prose or data file
routes through the original character windows unchanged.
"""

from arrowhead.config import Settings
from arrowhead.content.chunking import chunk_text
from arrowhead.content.code_chunking import (
    chunk_code_blocks,
    chunk_for_path,
    chunk_python,
)

SETTINGS = Settings()

PY_SOURCE = '''"""Module docstring."""

import os


def first():
    return os.getcwd()


def second(value):
    doubled = value * 2
    return doubled


class Widget:
    def method(self):
        return "widget"
'''


def test_python_splits_at_top_level_definitions():
    chunks = chunk_python(PY_SOURCE, max_chars=2000)
    assert len(chunks) == 4
    assert chunks[0].startswith('"""Module docstring."""')
    assert chunks[1].startswith("def first():")
    assert chunks[2].startswith("def second(value):")
    assert chunks[3].startswith("class Widget:")


def test_python_keeps_a_function_whole_when_it_fits():
    chunks = chunk_python(PY_SOURCE, max_chars=2000)
    assert "return doubled" in chunks[2]


def test_oversized_definition_still_windows():
    body = "\n".join(f"    line_{i} = {i}" for i in range(200))
    source = f"def huge():\n{body}\n"
    chunks = chunk_python(source, max_chars=300, overlap=50)
    assert len(chunks) > 1
    assert all(len(chunk) <= 300 for chunk in chunks)


def test_syntax_error_degrades_to_plain_windows():
    broken = "def broken(:\n    pass\n" * 10
    chunks = chunk_python(broken, max_chars=100)
    assert chunks == chunk_text(broken, max_chars=100)


def test_max_chunks_caps_across_segments():
    chunks = chunk_python(PY_SOURCE, max_chars=2000, max_chunks=2)
    assert len(chunks) == 2


def test_code_blocks_pack_neighbors_without_crossing_boundaries():
    source = "int a() {\n  return 1;\n}\n\nint b() {\n  return 2;\n}\n"
    packed = chunk_code_blocks(source, max_chars=2000)
    assert len(packed) == 1
    split = chunk_code_blocks(source, max_chars=30)
    assert len(split) == 2
    assert split[0].startswith("int a()")
    assert split[1].startswith("int b()")


def test_chunk_for_path_routes_by_suffix():
    assert chunk_for_path("m.py", PY_SOURCE, SETTINGS)[1].startswith(
        "def first():"
    )
    prose = "One sentence. " * 300
    # Prose and data files chunk exactly as before the code path existed.
    assert chunk_for_path("notes.md", prose, SETTINGS) == chunk_text(
        prose,
        max_chars=SETTINGS.vector_index_chunk_max_chars,
        overlap=SETTINGS.vector_index_chunk_overlap,
    )


def test_chunks_are_sanitized():
    dirty = "def f():\n    return '\x07bell'\n"
    chunks = chunk_python(dirty, max_chars=200)
    assert all("\x07" not in chunk for chunk in chunks)
