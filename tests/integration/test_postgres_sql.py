"""The SQL connector against a real Postgres: reads work, and the read-only
transaction and server-side statement timeout enforce the guarantees the
connector's docstring claims.
"""

import pytest

from arrowhead.errors import ToolError

_SCHEMA = [
    "DROP TABLE IF EXISTS t",
    "CREATE TABLE t (id int, name text)",
    "INSERT INTO t VALUES (1, 'a'), (2, 'b')",
]


async def test_read_returns_rows(postgres_url, run_ddl, monkeypatch):
    await run_ddl(_SCHEMA)
    monkeypatch.setenv("ARROWHEAD_SQL_DSN", postgres_url)
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    from arrowhead.connectors.sql import dispose_engines, sql_query

    try:
        result = await sql_query("SELECT id, name FROM t ORDER BY id")
        assert result["metadata"]["row_count"] == 2
        assert result["metadata"]["columns"] == ["id", "name"]
    finally:
        await dispose_engines()


async def test_statement_timeout_stops_a_long_query(
    postgres_url, run_ddl, monkeypatch
):
    monkeypatch.setenv("ARROWHEAD_SQL_DSN", postgres_url)
    monkeypatch.setenv("ARROWHEAD_SQL_TIMEOUT_SECONDS", "1")
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    from arrowhead.connectors.sql import dispose_engines, sql_query

    try:
        # A slow but allowed query (pg_sleep is refused by the function
        # denylist before it reaches the database); the server-side statement
        # timeout must stop it and surface a clean error.
        with pytest.raises(ToolError):
            await sql_query("SELECT count(*) FROM generate_series(1, 100000000000)")
    finally:
        await dispose_engines()


async def test_read_only_transaction_refuses_a_write(
    postgres_url, run_ddl, monkeypatch
):
    # The parser blocks a write before it reaches the database, so the
    # read-only transaction is exercised directly: with the session guards
    # applied, an INSERT must be refused by Postgres itself.
    await run_ddl(_SCHEMA)
    monkeypatch.setenv("ARROWHEAD_SQL_DSN", postgres_url)
    from sqlalchemy import text
    from sqlalchemy.exc import SQLAlchemyError

    from arrowhead.config import get_settings

    get_settings.cache_clear()
    from arrowhead.connectors.sql import (
        _get_engine,
        _session_guards,
        dispose_engines,
    )

    engine = _get_engine(postgres_url)
    try:
        async with engine.connect() as conn:
            async with conn.begin():
                for statement in _session_guards("postgres", get_settings()):
                    await conn.execute(text(statement))
                with pytest.raises(SQLAlchemyError):
                    await conn.execute(text("INSERT INTO t VALUES (99, 'x')"))
    finally:
        await dispose_engines()
