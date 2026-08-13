import pytest

from arrowhead.config import get_settings
from arrowhead.errors import ToolError

POSTGRES = "postgresql+asyncpg://u@h/db"


def _configure(monkeypatch, **env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()


async def test_unconfigured_write_connector_refuses(monkeypatch):
    monkeypatch.delenv("ARROWHEAD_VECTOR_WRITE_DSN", raising=False)
    get_settings.cache_clear()
    from arrowhead.connectors.pgvector_index import doc_index

    with pytest.raises(ToolError):
        await doc_index("doc_chunks")


async def test_non_postgres_write_dsn_refuses(monkeypatch):
    _configure(
        monkeypatch, ARROWHEAD_VECTOR_WRITE_DSN="sqlite+aiosqlite:///x.db"
    )
    from arrowhead.connectors.pgvector_index import doc_index

    with pytest.raises(ToolError):
        await doc_index("doc_chunks")


async def test_traversal_prefix_refused(monkeypatch):
    _configure(
        monkeypatch,
        ARROWHEAD_VECTOR_WRITE_DSN=POSTGRES,
        ARROWHEAD_PGVECTOR_COLLECTIONS="doc_chunks",
    )
    from arrowhead.connectors.pgvector_index import doc_index

    with pytest.raises(ToolError):
        await doc_index("doc_chunks", "../../etc")


async def test_unknown_collection_refuses(monkeypatch):
    _configure(
        monkeypatch,
        ARROWHEAD_VECTOR_WRITE_DSN=POSTGRES,
        ARROWHEAD_PGVECTOR_COLLECTIONS="allowed",
    )
    from arrowhead.connectors.pgvector_index import doc_index

    with pytest.raises(ToolError):
        await doc_index("other")


async def test_ingestion_denied_by_default_policy(monkeypatch):
    from arrowhead.authz.enforce import get_authorizer

    _configure(
        monkeypatch,
        ARROWHEAD_VECTOR_WRITE_DSN=POSTGRES,
        ARROWHEAD_PGVECTOR_COLLECTIONS="doc_chunks",
        ARROWHEAD_AUTH_ENABLED="true",
    )
    get_authorizer.cache_clear()
    from arrowhead.connectors.pgvector_index import doc_index

    # The default policy grants no ingest action, so ingestion is denied before
    # any document is read, embedded, or written.
    with pytest.raises(ToolError):
        await doc_index("doc_chunks")
    get_authorizer.cache_clear()


def test_chunk_id_is_stable_and_tenant_scoped():
    from arrowhead.connectors.pgvector_index import _chunk_id

    base = _chunk_id("t1", "a.md", 0)
    assert base == _chunk_id("t1", "a.md", 0)
    assert base != _chunk_id("t2", "a.md", 0)
    assert base != _chunk_id("t1", "b.md", 0)
    assert base != _chunk_id("t1", "a.md", 1)


async def test_gather_chunks_reads_the_corpus(docs):
    get_settings.cache_clear()
    (docs / "handbook.md").write_text("Refunds take five days. " * 20)
    from arrowhead.connectors.pgvector_index import _gather_chunks

    gathered, _truncated = _gather_chunks("", "tester", get_settings())
    assert "handbook.md" in gathered
    assert gathered["handbook.md"][0][0] == 0
    assert all(content.strip() for _index, content in gathered["handbook.md"])


async def test_embed_attaches_vector_literals():
    get_settings.cache_clear()
    from arrowhead.connectors.pgvector_index import _embed

    prepared = await _embed(
        [("a.md", 0, "hello"), ("a.md", 1, "world")], get_settings()
    )
    assert list(prepared) == ["a.md"]
    assert len(prepared["a.md"]) == 2
    index, content, literal = prepared["a.md"][0]
    assert index == 0
    assert content == "hello"
    assert literal.startswith("[") and literal.endswith("]")
