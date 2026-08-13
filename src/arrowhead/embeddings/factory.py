"""Select the embedding provider named by configuration.

The provider is imported lazily so the deterministic default carries no
dependency and the http provider's client code loads only when configured.
"""

from arrowhead.config import Settings
from arrowhead.embeddings.base import EmbeddingError, EmbeddingProvider


def build_embedding_provider(settings: Settings) -> EmbeddingProvider:
    """Return the provider named by settings.embedding_provider."""
    if settings.embedding_provider == "deterministic":
        from arrowhead.embeddings.deterministic import (
            DeterministicEmbeddingProvider,
        )

        return DeterministicEmbeddingProvider(settings.embedding_dimensions)
    if settings.embedding_provider == "http":
        from arrowhead.embeddings.http import HTTPEmbeddingProvider

        return HTTPEmbeddingProvider(settings)
    raise EmbeddingError(
        f"unknown embedding provider: {settings.embedding_provider!r}"
    )
