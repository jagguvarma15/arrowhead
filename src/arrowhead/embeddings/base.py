"""The embedding provider seam.

A provider turns a batch of texts into fixed-dimension vectors. The interface
is deliberately small so a deployment can supply its own provider without
pulling a heavy dependency into the base install.
"""

from typing import Protocol


class EmbeddingError(Exception):
    """An embedding could not be produced."""


class EmbeddingProvider(Protocol):
    """Turns texts into fixed-dimension vectors.

    dimensions is the length every returned vector has, so a caller can check
    it against the vector column before writing or querying.
    """

    @property
    def dimensions(self) -> int: ...

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Return one vector per input text, each of length dimensions."""
        ...
