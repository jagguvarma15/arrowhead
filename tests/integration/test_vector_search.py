"""vector_search against a real pgvector collection: nearest-neighbour results
are returned, and the tenant filter is the authenticated caller so one tenant
can never read another's rows.
"""

import json

from arrowhead.auth.principal import as_principal

_SCHEMA = [
    "CREATE EXTENSION IF NOT EXISTS vector",
    "DROP TABLE IF EXISTS docs",
    "CREATE TABLE docs (id int, tenant text, content text, embedding vector(3))",
    "INSERT INTO docs VALUES "
    "(1, 'acme', 'acme apple', '[1,0,0]'), "
    "(2, 'acme', 'acme banana', '[0.9,0.1,0]'), "
    "(3, 'other', 'other secret', '[1,0,0]')",
]


def _contents(result):
    rows = json.loads(result["content"].splitlines()[1])
    return {row["content"] for row in rows}


async def test_search_returns_nearest_rows_for_the_tenant(
    postgres_url, run_ddl, monkeypatch
):
    await run_ddl(_SCHEMA)
    monkeypatch.setenv("ARROWHEAD_SQL_DSN", postgres_url)
    monkeypatch.setenv("ARROWHEAD_PGVECTOR_COLLECTIONS", "docs")
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    from arrowhead.connectors.pgvector import vector_search
    from arrowhead.connectors.sql import dispose_engines

    try:
        with as_principal("acme", {"vector:search"}):
            result = await vector_search("docs", [1.0, 0.0, 0.0], k=5)
        assert _contents(result) == {"acme apple", "acme banana"}
    finally:
        await dispose_engines()


async def test_tenant_cannot_read_another_tenants_rows(
    postgres_url, run_ddl, monkeypatch
):
    await run_ddl(_SCHEMA)
    monkeypatch.setenv("ARROWHEAD_SQL_DSN", postgres_url)
    monkeypatch.setenv("ARROWHEAD_PGVECTOR_COLLECTIONS", "docs")
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    from arrowhead.connectors.pgvector import vector_search
    from arrowhead.connectors.sql import dispose_engines

    try:
        # 'other' asks for the same vector 'acme' rows are nearest to, yet only
        # its own row comes back, because the tenant filter is the caller.
        with as_principal("other", {"vector:search"}):
            result = await vector_search("docs", [1.0, 0.0, 0.0], k=5)
        assert _contents(result) == {"other secret"}
    finally:
        await dispose_engines()
