"""Split source code into chunks that follow its structure.

A code file retrieves badly when it is cut into arbitrary character
windows: a function body severed from its signature embeds as noise. A
Python file is therefore split at its top-level definitions through the
stdlib parser, and other recognized code files at blank-line block
boundaries, before the bounded windowing that caps chunk size and count.
A file that fails to parse degrades to plain windows rather than erroring,
and prose formats are untouched: chunk_for_path routes only recognized
code suffixes here, so document chunking behaves exactly as before.

Every path ends in chunk_text, so all chunks are sanitized text-safe and
both the window size and the chunk count stay bounded.
"""

import ast
from pathlib import PurePosixPath

from arrowhead.content.chunking import chunk_text

_PYTHON_SUFFIXES = frozenset({".py", ".pyi"})
_CODE_SUFFIXES = frozenset(
    {
        ".c",
        ".cpp",
        ".cs",
        ".go",
        ".h",
        ".hpp",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".php",
        ".rb",
        ".rs",
        ".scala",
        ".sh",
        ".sql",
        ".swift",
        ".ts",
        ".tsx",
    }
)


def chunk_for_path(
    path: str, text: str, settings, *, max_chunks: int | None = None
) -> list[str]:
    """Chunk a document with the strategy its suffix calls for."""
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in _PYTHON_SUFFIXES:
        return chunk_python(
            text,
            max_chars=settings.code_chunk_max_chars,
            overlap=settings.vector_index_chunk_overlap,
            max_chunks=max_chunks,
        )
    if suffix in _CODE_SUFFIXES:
        return chunk_code_blocks(
            text,
            max_chars=settings.code_chunk_max_chars,
            overlap=settings.vector_index_chunk_overlap,
            max_chunks=max_chunks,
        )
    return chunk_text(
        text,
        max_chars=settings.vector_index_chunk_max_chars,
        overlap=settings.vector_index_chunk_overlap,
        max_chunks=max_chunks,
    )


def chunk_python(
    text: str,
    *,
    max_chars: int,
    overlap: int = 0,
    max_chunks: int | None = None,
) -> list[str]:
    """Split Python source at its top-level definitions, then window.

    Each segment runs from one top-level def, async def, or class to the
    next, with the module preamble as its own segment, so a chunk carries
    a whole definition whenever it fits the window. Source that does not
    parse degrades to plain windows.
    """
    try:
        module = ast.parse(text)
    except (SyntaxError, ValueError):
        return chunk_text(
            text, max_chars=max_chars, overlap=overlap, max_chunks=max_chunks
        )
    lines = text.splitlines(keepends=True)
    boundaries = sorted(
        {
            node.lineno - 1
            for node in module.body
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            )
        }
    )
    segments = _segments_from_boundaries(lines, boundaries)
    return _window_segments(
        segments, max_chars=max_chars, overlap=overlap, max_chunks=max_chunks
    )


def chunk_code_blocks(
    text: str,
    *,
    max_chars: int,
    overlap: int = 0,
    max_chunks: int | None = None,
) -> list[str]:
    """Split non-Python code at blank-line block boundaries, then window.

    Blocks are greedily packed so short neighbors share a chunk while a
    block boundary is never crossed mid-window unless a single block is
    itself larger than the window.
    """
    blocks: list[str] = []
    current: list[str] = []
    for line in text.splitlines(keepends=True):
        if line.strip():
            current.append(line)
        elif current:
            blocks.append("".join(current))
            current = []
    if current:
        blocks.append("".join(current))
    segments: list[str] = []
    packed = ""
    for block in blocks:
        if packed and len(packed) + len(block) > max_chars:
            segments.append(packed)
            packed = block
        else:
            packed = f"{packed}\n{block}" if packed else block
    if packed:
        segments.append(packed)
    return _window_segments(
        segments, max_chars=max_chars, overlap=overlap, max_chunks=max_chunks
    )


def _segments_from_boundaries(
    lines: list[str], boundaries: list[int]
) -> list[str]:
    if not boundaries:
        return ["".join(lines)]
    starts = boundaries if boundaries[0] == 0 else [0, *boundaries]
    segments = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(lines)
        segments.append("".join(lines[start:end]))
    return segments


def _window_segments(
    segments: list[str],
    *,
    max_chars: int,
    overlap: int,
    max_chunks: int | None,
) -> list[str]:
    """Window each segment, keeping the total bounded across segments."""
    chunks: list[str] = []
    for segment in segments:
        remaining = None if max_chunks is None else max_chunks - len(chunks)
        if remaining is not None and remaining <= 0:
            break
        # A segment that fits its window needs no overlap; overlap only
        # applies inside a segment large enough to split.
        effective_overlap = overlap if len(segment) > max_chars else 0
        chunks.extend(
            chunk_text(
                segment,
                max_chars=max_chars,
                overlap=effective_overlap,
                max_chunks=remaining,
            )
        )
    return chunks
