import pytest

from arrowhead.config import get_settings
from arrowhead.errors import ToolError

POSTGRES = "postgresql+asyncpg://u@h/db"


async def test_unconfigured_connector_refuses(monkeypatch):
    monkeypatch.delenv("ARROWHEAD_SQL_DSN", raising=False)
    get_settings.cache_clear()
    from arrowhead.connectors.pgvector import vector_query

    with pytest.raises(ToolError):
        await vector_query("doc_chunks", "hello")


async def test_non_postgres_dsn_refuses(configure_env):
    configure_env(ARROWHEAD_SQL_DSN="sqlite+aiosqlite:///x.db")
    from arrowhead.connectors.pgvector import vector_query

    with pytest.raises(ToolError):
        await vector_query("doc_chunks", "hello")


async def test_empty_query_refuses(configure_env):
    configure_env(
        ARROWHEAD_SQL_DSN=POSTGRES,
        ARROWHEAD_PGVECTOR_COLLECTIONS="doc_chunks",
    )
    from arrowhead.connectors.pgvector import vector_query

    with pytest.raises(ToolError):
        await vector_query("doc_chunks", "   ")


async def test_unknown_collection_refuses(configure_env):
    configure_env(
        ARROWHEAD_SQL_DSN=POSTGRES,
        ARROWHEAD_PGVECTOR_COLLECTIONS="allowed",
    )
    from arrowhead.connectors.pgvector import vector_query

    with pytest.raises(ToolError):
        await vector_query("other", "hello")


async def test_authorization_is_checked_before_embedding(configure_env):
    from arrowhead.authz.enforce import get_authorizer

    configure_env(
        ARROWHEAD_SQL_DSN=POSTGRES,
        ARROWHEAD_PGVECTOR_COLLECTIONS="doc_chunks",
        ARROWHEAD_AUTH_ENABLED="true",
        ARROWHEAD_AUTHZ_POLICY=(
            '{"grants": [{"subject": "*", "actions": ["read"], "prefix": ""}]}'
        ),
    )
    get_authorizer.cache_clear()
    from arrowhead.connectors.pgvector import vector_query

    # The default-deny policy grants read but not query, so authorization fails
    # before the query is ever embedded or the database is touched.
    with pytest.raises(ToolError):
        await vector_query("doc_chunks", "hello")
    get_authorizer.cache_clear()
