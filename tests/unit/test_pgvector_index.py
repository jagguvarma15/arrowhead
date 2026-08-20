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
    from arrowhead.connectors.pgvector_index import _content_hash, _embed

    prepared = await _embed(
        [
            ("a.md", 0, "hello", _content_hash("hello")),
            ("a.md", 1, "world", _content_hash("world")),
        ],
        get_settings(),
    )
    assert list(prepared) == ["a.md"]
    assert len(prepared["a.md"]) == 2
    index, content, literal, digest = prepared["a.md"][0]
    assert index == 0
    assert content == "hello"
    assert literal.startswith("[") and literal.endswith("]")
    assert digest == _content_hash("hello")


async def test_files_indexed_counts_reused_sources(docs, monkeypatch):
    _configure(
        monkeypatch,
        ARROWHEAD_VECTOR_WRITE_DSN=POSTGRES,
        ARROWHEAD_PGVECTOR_COLLECTIONS="doc_chunks",
    )
    (docs / "handbook.md").write_text("Refunds take five days. " * 20)
    import arrowhead.connectors.pgvector_index as mod

    async def fake_existing(collection, tenant, sources, settings):
        gathered, _truncated = mod._gather_chunks("", tenant, settings)
        return {
            (source, index): mod._content_hash(content)
            for source, chunks in gathered.items()
            for index, content in chunks
        }

    async def fake_write(collection, tenant, prepared, counts, settings):
        return 0

    monkeypatch.setattr(mod, "_existing_hashes", fake_existing)
    monkeypatch.setattr(mod, "_write_chunks", fake_write)
    result = await mod.doc_index("doc_chunks")
    # A re-index of a fully unchanged corpus still indexed every gathered
    # file; the chunk counts carry the reuse detail.
    assert result["files_indexed"] == 1
    assert result["chunks_reused"] > 0
    assert result["chunks_written"] == 0


class TestPartitionChunks:
    def test_all_new_chunks_are_embedded(self):
        from arrowhead.connectors.pgvector_index import _partition_chunks

        gathered = {"a.md": [(0, "one"), (1, "two")]}
        flat, counts, reused = _partition_chunks(gathered, {})
        assert [(s, i, c) for s, i, c, _h in flat] == [
            ("a.md", 0, "one"),
            ("a.md", 1, "two"),
        ]
        assert counts == {"a.md": 2}
        assert reused == 0

    def test_unchanged_chunks_are_reused_not_embedded(self):
        from arrowhead.connectors.pgvector_index import (
            _content_hash,
            _partition_chunks,
        )

        gathered = {"a.md": [(0, "same"), (1, "edited")]}
        existing = {
            ("a.md", 0): _content_hash("same"),
            ("a.md", 1): _content_hash("original"),
        }
        flat, counts, reused = _partition_chunks(gathered, existing)
        assert [(s, i) for s, i, _c, _h in flat] == [("a.md", 1)]
        assert counts == {"a.md": 2}
        assert reused == 1

    def test_counts_cover_sources_with_nothing_to_write(self):
        # A fully unchanged source still reports its count, so the write
        # path can delete rows past the end of a shrunk document.
        from arrowhead.connectors.pgvector_index import (
            _content_hash,
            _partition_chunks,
        )

        gathered = {"a.md": [(0, "same")]}
        existing = {
            ("a.md", 0): _content_hash("same"),
            ("a.md", 1): _content_hash("stale tail"),
        }
        flat, counts, reused = _partition_chunks(gathered, existing)
        assert flat == []
        assert counts == {"a.md": 1}
        assert reused == 1
