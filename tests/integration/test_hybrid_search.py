"""Hybrid retrieval against a real Postgres: the full-text branch surfaces
exact identifiers the vector branch misses, the fused ranking returns
citations, and tenant isolation holds. Uses the deterministic embedder, whose
similarity is deliberately non-semantic, which is exactly what proves the
lexical branch contributes: an exact token match must surface regardless of
where the random vectors rank it. Runs only when ARROWHEAD_POSTGRES_TEST_URL
is set.
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
    "CREATE INDEX doc_chunks_fts ON doc_chunks USING gin (content_tsv)",
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


async def test_exact_identifier_surfaces_through_the_lexical_branch(
    postgres_url, run_ddl, tmp_path, monkeypatch
):
    await run_ddl(_SCHEMA)
    (tmp_path / "errors.md").write_text(
        "The dispatcher raises FROBNICATE_TIMEOUT when the upstream stalls."
    )
    for index in range(8):
        (tmp_path / f"noise{index}.md").write_text(
            f"Unrelated prose about deadline number {index} and nothing else."
        )
    _configure(monkeypatch, tmp_path, postgres_url)
    from arrowhead.connectors.hybrid import hybrid_query
    from arrowhead.connectors.pgvector_index import doc_index
    from arrowhead.connectors.sql import dispose_engines

    try:
        await doc_index("doc_chunks")
        result = await hybrid_query("doc_chunks", "FROBNICATE_TIMEOUT", k=3)
        assert result["metadata"]["row_count"] >= 1
        assert "errors.md" in result["content"]
        assert "score" in result["metadata"]["columns"]
        assert "source" in result["metadata"]["columns"]
        assert "chunk_index" in result["metadata"]["columns"]
    finally:
        await dispose_engines()


async def test_fusion_returns_rows_for_plain_queries_too(
    postgres_url, run_ddl, tmp_path, monkeypatch
):
    await run_ddl(_SCHEMA)
    (tmp_path / "refunds.md").write_text(
        "Refunds are approved within five business days."
    )
    _configure(monkeypatch, tmp_path, postgres_url)
    from arrowhead.connectors.hybrid import hybrid_query
    from arrowhead.connectors.pgvector_index import doc_index
    from arrowhead.connectors.sql import dispose_engines

    try:
        await doc_index("doc_chunks")
        result = await hybrid_query("doc_chunks", "refunds", k=5)
        assert result["metadata"]["row_count"] >= 1
        assert "refunds.md" in result["content"]
    finally:
        await dispose_engines()


async def test_hybrid_respects_tenant_isolation(
    postgres_url, run_ddl, tmp_path, monkeypatch
):
    await run_ddl(_SCHEMA)
    doc = tmp_path / "shared.md"
    _configure(monkeypatch, tmp_path, postgres_url)
    from arrowhead.connectors.hybrid import hybrid_query
    from arrowhead.connectors.pgvector_index import doc_index
    from arrowhead.connectors.sql import dispose_engines

    try:
        doc.write_text("alpha SECRET_MARKER refunds take five days")
        with as_principal("tenant-a"):
            await doc_index("doc_chunks")
        doc.write_text("beta refunds take ten days")
        with as_principal("tenant-b"):
            await doc_index("doc_chunks")

        with as_principal("tenant-b"):
            result = await hybrid_query("doc_chunks", "SECRET_MARKER", k=5)
        assert "alpha" not in result["content"]
        assert "SECRET_MARKER" not in result["content"]
    finally:
        await dispose_engines()
