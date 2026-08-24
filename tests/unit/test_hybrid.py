"""hybrid_query holds every vector-tool guard before touching a database.

The fused search itself runs in Postgres and is covered by the
integration suite; these tests pin the refusal order and the guard
parity with vector_query: configuration, dialect, input validation,
collection allow-listing, and authorization before embedding.
"""

import pytest

from arrowhead.config import get_settings
from arrowhead.errors import ToolError

POSTGRES = "postgresql+asyncpg://u@h/db"


async def test_unconfigured_connector_refuses(monkeypatch):
    monkeypatch.delenv("ARROWHEAD_SQL_DSN", raising=False)
    get_settings.cache_clear()
    from arrowhead.connectors.hybrid import hybrid_query

    with pytest.raises(ToolError, match="not configured"):
        await hybrid_query("doc_chunks", "refunds")


async def test_non_postgres_dsn_refuses(configure_env):
    configure_env(ARROWHEAD_SQL_DSN="sqlite+aiosqlite:///x.db")
    from arrowhead.connectors.hybrid import hybrid_query

    with pytest.raises(ToolError, match="PostgreSQL"):
        await hybrid_query("doc_chunks", "refunds")


async def test_empty_query_refused(configure_env):
    configure_env(
        ARROWHEAD_SQL_DSN=POSTGRES,
        ARROWHEAD_PGVECTOR_COLLECTIONS="doc_chunks",
    )
    from arrowhead.connectors.hybrid import hybrid_query

    with pytest.raises(ToolError, match="non-empty"):
        await hybrid_query("doc_chunks", "   ")


async def test_unknown_collection_refused(configure_env):
    configure_env(
        ARROWHEAD_SQL_DSN=POSTGRES,
        ARROWHEAD_PGVECTOR_COLLECTIONS="allowed",
    )
    from arrowhead.connectors.hybrid import hybrid_query

    with pytest.raises(ToolError, match="unknown vector collection"):
        await hybrid_query("other", "refunds")


async def test_no_collections_configured_refused(configure_env):
    configure_env(ARROWHEAD_SQL_DSN=POSTGRES)
    from arrowhead.connectors.hybrid import hybrid_query

    with pytest.raises(ToolError, match="no vector collections"):
        await hybrid_query("doc_chunks", "refunds")


async def test_unauthorized_caller_never_reaches_the_embedder(
    configure_env, monkeypatch
):
    """Authorization runs before embedding, so a denied caller cannot
    trigger an outbound embedding request."""
    from arrowhead.authz.enforce import get_authorizer

    configure_env(
        ARROWHEAD_SQL_DSN=POSTGRES,
        ARROWHEAD_PGVECTOR_COLLECTIONS="doc_chunks",
        ARROWHEAD_AUTH_ENABLED="true",
        ARROWHEAD_AUTHZ_POLICY='{"grants": []}',
    )
    get_authorizer.cache_clear()

    calls = {"embed": 0}

    def counting_provider(settings):
        calls["embed"] += 1
        raise AssertionError("the embedder must not be reached")

    monkeypatch.setattr(
        "arrowhead.embeddings.factory.build_embedding_provider",
        counting_provider,
    )
    from arrowhead.connectors.hybrid import hybrid_query

    with pytest.raises(ToolError, match="not authorized"):
        await hybrid_query("doc_chunks", "refunds")
    assert calls["embed"] == 0
    get_authorizer.cache_clear()


def test_fusion_sql_binds_every_caller_value(configure_env):
    """The statement interpolates only allow-listed or configured
    identifiers; the embedding, query, language, tenant, and limits are
    bound parameters."""
    configure_env(
        ARROWHEAD_SQL_DSN=POSTGRES,
        ARROWHEAD_PGVECTOR_COLLECTIONS="doc_chunks",
    )
    import inspect

    from arrowhead.connectors import hybrid

    source = inspect.getsource(hybrid._fused_search)
    for bound in (":q", ":query", ":lang", ":tenant", ":pool", ":rrf_k", ":k"):
        assert bound in source
    assert "plainto_tsquery(CAST(:lang AS regconfig)" in source
