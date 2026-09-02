"""Select the memory backend named by configuration.

Backends are imported lazily so the file default carries no database
dependency and the Postgres backend's connector code loads only when a
DSN is configured. Semantic recall is enabled only when the embedding
provider is the real one; the deterministic development provider would
fake semantics, so Postgres without it stays honestly keyword (full-text)
recall.
"""

from arrowhead.config import Settings
from arrowhead.memory.base import MemoryBackend


def build_memory_backend(settings: Settings) -> MemoryBackend:
    """Return the backend selected by settings.memory_dsn."""
    if settings.memory_dsn:
        from arrowhead.embeddings.factory import build_embedding_provider
        from arrowhead.memory.postgres_backend import PostgresMemoryBackend

        embedder = (
            build_embedding_provider(settings)
            if settings.embedding_provider == "http"
            else None
        )
        return PostgresMemoryBackend(settings, embedder=embedder)
    from arrowhead.memory.file_backend import FileMemoryBackend

    return FileMemoryBackend(settings)
