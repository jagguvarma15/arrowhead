"""The retrieval loop against a real Postgres with pgvector: doc_index writes
chunks and vector_query returns them with citations, and one tenant can never
read another's chunks. Uses the deterministic embedder so no network is needed;
runs only when ARROWHEAD_POSTGRES_TEST_URL is set.
"""

from arrowhead.auth.principal import as_principal
from arrowhead.authz.enforce import get_authorizer
from arrowhead.config import get_settings

_SCHEMA = [
    "CREATE EXTENSION IF NOT EXISTS vector",
    "DROP TABLE IF EXISTS doc_chunks",
    "CREATE TABLE doc_chunks (id text PRIMARY KEY, tenant text NOT NULL, "
    "source text NOT NULL, chunk_index int NOT NULL, content text NOT NULL, "
    "embedding vector(8) NOT NULL, "
    "content_hash text NOT NULL DEFAULT '', "
    "content_tsv tsvector GENERATED ALWAYS AS "
    "(to_tsvector('english', content)) STORED, "
    "UNIQUE (tenant, source, chunk_index))",
]


def _configure(monkeypatch, docs_root, url):
    monkeypatch.setenv("ARROWHEAD_SQL_DSN", url)
    monkeypatch.setenv("ARROWHEAD_VECTOR_WRITE_DSN", url)
    monkeypatch.setenv("ARROWHEAD_PGVECTOR_COLLECTIONS", "doc_chunks")
    monkeypatch.setenv("ARROWHEAD_EMBEDDING_PROVIDER", "deterministic")
    monkeypatch.setenv("ARROWHEAD_EMBEDDING_DIMENSIONS", "8")
    monkeypatch.setenv("ARROWHEAD_DOCS_ROOT", str(docs_root))
    get_settings.cache_clear()
    get_authorizer.cache_clear()


async def test_index_then_query_returns_cited_chunks(
    postgres_url, run_ddl, tmp_path, monkeypatch
):
    await run_ddl(_SCHEMA)
    (tmp_path / "handbook.md").write_text(
        "Refunds are issued within five business days of approval."
    )
    _configure(monkeypatch, tmp_path, postgres_url)
    from arrowhead.connectors.pgvector import vector_query
    from arrowhead.connectors.pgvector_index import doc_index
    from arrowhead.connectors.sql import dispose_engines

    try:
        indexed = await doc_index("doc_chunks")
        assert indexed["chunks_written"] >= 1
        result = await vector_query("doc_chunks", "refunds", k=3)
        assert result["metadata"]["row_count"] >= 1
        assert "source" in result["metadata"]["columns"]
        assert "chunk_index" in result["metadata"]["columns"]
        assert "handbook.md" in result["content"]
    finally:
        await dispose_engines()


async def test_reindex_reuses_unchanged_chunks(
    postgres_url, run_ddl, tmp_path, monkeypatch
):
    """A second index of an unedited corpus embeds nothing and rewrites
    nothing; an edit re-embeds only the changed document's chunks."""
    await run_ddl(_SCHEMA)
    (tmp_path / "stable.md").write_text("The refund window is five days.")
    (tmp_path / "edited.md").write_text("Shipping is free over fifty.")
    _configure(monkeypatch, tmp_path, postgres_url)

    from arrowhead.connectors import pgvector_index
    from arrowhead.connectors.pgvector_index import doc_index
    from arrowhead.connectors.sql import dispose_engines

    embed_batches: list[int] = []
    real_build = pgvector_index.build_embedding_provider

    def counting_build(settings):
        provider = real_build(settings)

        class Counting:
            dimensions = provider.dimensions

            async def embed(self, texts):
                embed_batches.append(len(texts))
                return await provider.embed(texts)

        return Counting()

    monkeypatch.setattr(
        pgvector_index, "build_embedding_provider", counting_build
    )

    try:
        first = await doc_index("doc_chunks")
        assert first["chunks_written"] == 2
        assert first["chunks_reused"] == 0
        assert embed_batches == [2]

        second = await doc_index("doc_chunks")
        assert second["chunks_written"] == 0
        assert second["chunks_reused"] == 2
        # No embedding call happened for the unchanged corpus.
        assert embed_batches == [2]

        (tmp_path / "edited.md").write_text("Shipping is free over sixty.")
        third = await doc_index("doc_chunks")
        assert third["chunks_written"] == 1
        assert third["chunks_reused"] == 1
        assert embed_batches == [2, 1]
    finally:
        await dispose_engines()


async def test_two_tenants_are_isolated(
    postgres_url, run_ddl, tmp_path, monkeypatch
):
    await run_ddl(_SCHEMA)
    doc = tmp_path / "shared.md"
    _configure(monkeypatch, tmp_path, postgres_url)
    from arrowhead.connectors.pgvector import vector_query
    from arrowhead.connectors.pgvector_index import doc_index
    from arrowhead.connectors.sql import dispose_engines

    try:
        doc.write_text("alpha marker refunds take five days")
        with as_principal("tenant-a"):
            await doc_index("doc_chunks")
        doc.write_text("beta marker refunds take ten days")
        with as_principal("tenant-b"):
            await doc_index("doc_chunks")

        with as_principal("tenant-a"):
            a = await vector_query("doc_chunks", "refunds", k=5)
        assert "alpha" in a["content"]
        assert "beta" not in a["content"]

        with as_principal("tenant-b"):
            b = await vector_query("doc_chunks", "refunds", k=5)
        assert "beta" in b["content"]
        assert "alpha" not in b["content"]
    finally:
        await dispose_engines()
