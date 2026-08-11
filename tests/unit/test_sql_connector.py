"""The SQL read tool over a real SQLite database: it returns bound, capped,
sanitized rows as untrusted data, refuses writes, and scopes the caller to the
tables a policy allows.
"""

import sqlite3

import pytest
from fastmcp.exceptions import ToolError


@pytest.fixture(autouse=True)
async def _dispose_engines():
    yield
    from arrowhead.connectors.sql import dispose_engines

    await dispose_engines()


@pytest.fixture
def sql_db(tmp_path, monkeypatch):
    path = tmp_path / "app.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE users (id INTEGER, email TEXT, org TEXT)")
    conn.executemany(
        "INSERT INTO users VALUES (?, ?, ?)",
        [
            (1, "a@example.com", "acme"),
            (2, "b@example.com", "acme"),
            # An email carrying an ANSI escape, to prove cells are sanitized.
            (3, "c\x1b[31m@example.com", "other"),
        ],
    )
    conn.execute("CREATE TABLE secrets (id INTEGER, value TEXT)")
    conn.execute("INSERT INTO secrets VALUES (1, 'topsecret')")
    conn.commit()
    conn.close()
    monkeypatch.setenv("ARROWHEAD_SQL_DSN", f"sqlite+aiosqlite:///{path}")
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    return path


async def test_a_select_returns_its_rows(sql_db):
    from arrowhead.connectors.sql import sql_query

    result = await sql_query("SELECT id, email FROM users ORDER BY id")
    assert result["metadata"]["row_count"] == 3
    assert result["metadata"]["columns"] == ["id", "email"]
    assert "a@example.com" in result["content"]


async def test_named_parameters_are_bound(sql_db):
    from arrowhead.connectors.sql import sql_query

    result = await sql_query(
        "SELECT id FROM users WHERE org = :org", {"org": "acme"}
    )
    assert result["metadata"]["row_count"] == 2


async def test_a_write_is_refused(sql_db):
    from arrowhead.connectors.sql import sql_query

    with pytest.raises(ToolError):
        await sql_query("DELETE FROM users")


async def test_a_stacked_query_is_refused(sql_db):
    from arrowhead.connectors.sql import sql_query

    with pytest.raises(ToolError):
        await sql_query("SELECT 1; DROP TABLE users")


async def test_rows_are_capped_and_flagged(sql_db, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_SQL_MAX_ROWS", "2")
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    from arrowhead.connectors.sql import sql_query

    result = await sql_query("SELECT id FROM users")
    assert result["metadata"]["row_count"] == 2
    assert result["metadata"]["truncated"] is True


async def test_string_cells_are_sanitized(sql_db):
    from arrowhead.connectors.sql import sql_query

    result = await sql_query("SELECT email FROM users WHERE id = 3")
    assert "\x1b" not in result["content"]


async def test_result_is_wrapped_as_untrusted(sql_db):
    from arrowhead.connectors.sql import sql_query

    result = await sql_query("SELECT id FROM users WHERE id = 1")
    assert result["metadata"]["trust_level"] == "untrusted"
    assert "notice" in result


async def test_an_unconfigured_connector_refuses(monkeypatch):
    monkeypatch.setenv("ARROWHEAD_SQL_DSN", "")
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    from arrowhead.connectors.sql import sql_query

    with pytest.raises(ToolError):
        await sql_query("SELECT 1")


async def test_a_policy_scopes_the_caller_to_tables(sql_db, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    monkeypatch.setenv(
        "ARROWHEAD_AUTHZ_POLICY",
        '{"grants": [{"subject": "*", "actions": ["query"], "prefix": "users"}]}',
    )
    from arrowhead.authz.enforce import get_authorizer
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    get_authorizer.cache_clear()
    from arrowhead.connectors.sql import sql_query

    allowed = await sql_query("SELECT id FROM users")
    assert allowed["metadata"]["row_count"] == 3

    with pytest.raises(ToolError):
        await sql_query("SELECT value FROM secrets")


async def test_the_bad_param_names_are_refused(sql_db):
    from arrowhead.connectors.sql import sql_query

    with pytest.raises(ToolError):
        await sql_query("SELECT :x", {"1bad": "v"})


async def test_a_tableless_query_is_authorized_against_the_sentinel(
    sql_db, monkeypatch
):
    # A policy scoped to the users table must still refuse a query that reads
    # no table, so it cannot slip past authorization by referencing nothing.
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    monkeypatch.setenv(
        "ARROWHEAD_AUTHZ_POLICY",
        '{"grants": [{"subject": "*", "actions": ["query"], "prefix": "users"}]}',
    )
    from arrowhead.authz.enforce import get_authorizer
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    get_authorizer.cache_clear()
    from arrowhead.connectors.sql import sql_query

    with pytest.raises(ToolError):
        await sql_query("SELECT 1")


async def test_column_names_are_sanitized(sql_db):
    from arrowhead.connectors.sql import sql_query

    result = await sql_query('SELECT id AS "x\x1b[31m​" FROM users')
    column = result["metadata"]["columns"][0]
    assert "\x1b" not in column
    assert "​" not in column


def test_record_keys_disambiguate_collisions():
    from arrowhead.connectors.sql import _record_keys

    # Two columns that sanitize to the same name must not collapse into one
    # record key; a repeat is suffixed with its column index so no column's
    # values are silently dropped.
    assert _record_keys(["a", "b", "a", "a"]) == ["a", "b", "a#2", "a#3"]


async def test_the_dialect_is_derived_from_the_dsn():
    # A DSN-derived dialect keeps the guard from regenerating a query through a
    # generic dialect that would silently drop a dialect-specific clause.
    from arrowhead.connectors.sql import _dialect_from_dsn, guard_read_query

    assert _dialect_from_dsn("sqlite+aiosqlite:///x.db") == "sqlite"
    assert _dialect_from_dsn("postgresql+asyncpg://u@h/db") == "postgres"
    guarded = guard_read_query(
        "SELECT * FROM users WHERE name ILIKE 'a%'", dialect="postgres"
    )
    assert "ILIKE" in guarded.sql


def test_guard_rejects_deeply_nested_query():
    from arrowhead.connectors.sql import SqlGuardError, guard_read_query

    with pytest.raises(SqlGuardError):
        guard_read_query("SELECT " + "(" * 200 + "1" + ")" * 200, dialect="sqlite")


@pytest.mark.parametrize(
    "query",
    [
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT dblink_exec('a', 'b')",
        "SELECT query_to_xml('select 1', true, true, '')",
        "SELECT pg_terminate_backend(1) FROM pg_stat_activity",
        "SELECT LOAD_FILE('/etc/passwd')",
    ],
)
def test_guard_rejects_denied_functions(query):
    from arrowhead.connectors.sql import SqlGuardError, guard_read_query

    with pytest.raises(SqlGuardError):
        guard_read_query(query, dialect="postgres")


def test_guard_rejects_row_locking():
    from arrowhead.connectors.sql import SqlGuardError, guard_read_query

    with pytest.raises(SqlGuardError):
        guard_read_query("SELECT * FROM t FOR UPDATE", dialect="postgres")


def test_default_policy_denies_a_tableless_query():
    from arrowhead.authz.policy import (
        ACTION_QUERY,
        KIND_TABLE,
        KIND_TABLELESS,
        Resource,
        build_authorizer,
    )
    from arrowhead.config import Settings

    authorizer = build_authorizer(Settings(auth_enabled=True))
    # a real referenced table is queryable by default
    assert authorizer.authorize(
        "a", ACTION_QUERY, Resource(KIND_TABLE, "users")
    ).allowed
    # a functions-only (tableless) query is not
    assert not authorizer.authorize(
        "a", ACTION_QUERY, Resource(KIND_TABLELESS, "(no-table)")
    ).allowed
