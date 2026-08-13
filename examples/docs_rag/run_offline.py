"""An offline walkthrough of the retrieval loop, with no server or database.

It chunks the small corpus in this directory, embeds the chunks with the
deterministic provider, and answers a query by ranking chunks with cosine
similarity, printing each hit with its source and chunk index as a citation.
The deterministic embedder is not semantic, so the ranking here is illustrative
of the shape, not the quality; the real loop uses a real embedding provider and
pgvector (see this directory's README).

Run it with: uv run python examples/docs_rag/run_offline.py
"""

import asyncio
from pathlib import Path

from arrowhead.content.chunking import chunk_text
from arrowhead.embeddings.deterministic import DeterministicEmbeddingProvider

CORPUS = Path(__file__).parent / "corpus"
DIMENSIONS = 256
MAX_CHARS = 400
OVERLAP = 40
TOP_K = 3
QUERY = "how long do refunds take?"


def _dot(a, b):
    return sum(x * y for x, y in zip(a, b, strict=True))


async def main() -> None:
    provider = DeterministicEmbeddingProvider(DIMENSIONS)
    chunks = []
    for path in sorted(CORPUS.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        for index, piece in enumerate(
            chunk_text(text, max_chars=MAX_CHARS, overlap=OVERLAP)
        ):
            chunks.append((path.name, index, piece))

    vectors = await provider.embed([text for _source, _index, text in chunks])
    [query_vector] = await provider.embed([QUERY])

    ranked = sorted(
        zip(chunks, vectors, strict=True),
        key=lambda pair: _dot(query_vector, pair[1]),
        reverse=True,
    )
    print(f"query: {QUERY}\n")
    for (source, index, text), _vector in ranked[:TOP_K]:
        snippet = " ".join(text.split())[:120]
        print(f"[{source} #{index}] {snippet}")


if __name__ == "__main__":
    asyncio.run(main())
