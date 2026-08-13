"""A stdlib, offline, deterministic embedder for tests and local development.

It maps text to a stable unit vector by hashing, so the same text always
yields the same vector and the ingest to query pipeline can be exercised with
no model and no network. It carries no meaning: the similarity between two
different texts is essentially random, so it is NOT for production retrieval.
"""

import hashlib
import math
import struct

from arrowhead.embeddings.base import EmbeddingError

_INT32_SCALE = 2147483648.0


class DeterministicEmbeddingProvider:
    """Hash-based, L2-normalized, deterministic vectors. Not semantic."""

    def __init__(self, dimensions: int) -> None:
        if dimensions <= 0:
            raise EmbeddingError("embedding dimensions must be positive")
        self._dimensions = dimensions

    @property
    def dimensions(self) -> int:
        return self._dimensions

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._vector(text) for text in texts]

    def _vector(self, text: str) -> list[float]:
        raw = bytearray()
        counter = 0
        needed = self._dimensions * 4
        while len(raw) < needed:
            raw.extend(hashlib.sha256(f"{counter}:{text}".encode()).digest())
            counter += 1
        components = [
            struct.unpack_from(">i", raw, index * 4)[0] / _INT32_SCALE
            for index in range(self._dimensions)
        ]
        norm = math.sqrt(sum(value * value for value in components))
        if norm == 0.0:
            unit = [0.0] * self._dimensions
            unit[0] = 1.0
            return unit
        return [value / norm for value in components]
