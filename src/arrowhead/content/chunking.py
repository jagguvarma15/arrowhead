"""Split a document into bounded, overlapping chunks for embedding.

The text is sanitized text-safe so control and invisible characters never reach
the vector store, and both the window size and the number of windows are
bounded so one document cannot produce an unbounded amount of work. Windows are
character-based; token-aware chunking is a later refinement.
"""

from arrowhead.content.text_safe import sanitize_text


class ChunkingError(Exception):
    """The chunking parameters were invalid."""


def chunk_text(
    text: str,
    *,
    max_chars: int,
    overlap: int = 0,
    max_chunks: int | None = None,
) -> list[str]:
    """Return sanitized, overlapping windows of the text.

    Each window is at most max_chars characters and starts overlap characters
    before the previous window ended, so context is not lost at a boundary.
    Empty or whitespace-only text yields no chunks, and the result is capped at
    max_chunks when it is set.
    """
    if max_chars <= 0:
        raise ChunkingError("max_chars must be positive")
    if overlap < 0 or overlap >= max_chars:
        raise ChunkingError("overlap must be in the range [0, max_chars)")
    cleaned = sanitize_text(text)
    if not cleaned.strip():
        return []
    step = max_chars - overlap
    chunks: list[str] = []
    start = 0
    length = len(cleaned)
    while start < length:
        window = cleaned[start : start + max_chars].strip()
        if window:
            chunks.append(window)
            if max_chunks is not None and len(chunks) >= max_chunks:
                break
        start += step
    return chunks
