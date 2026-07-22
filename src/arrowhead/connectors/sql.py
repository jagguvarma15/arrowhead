"""SQL connector: the statement guard.

Before any query reaches a database it is parsed and checked here, so the read
path can only ever run a single read-only statement. The guard parses the query
with a real SQL parser, requires exactly one statement (which stops a stacked
`SELECT ...; DROP ...` from smuggling a second one), requires that statement to
be a read (rejecting INSERT, UPDATE, DELETE, DDL, SET, and `SELECT ... INTO`),
and returns the canonical statement to run together with the tables it reads.

The canonical statement, not the caller's raw text, is what the connector
executes, so comments and trailing whitespace cannot hide a second statement.
The table set lets the authorizer scope a caller to the tables it may read.
This is the first line of defense; the connector also runs the statement under
a read-only database role, so a bypass here is still refused by the database.
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime

import anyio
from fastmcp.exceptions import ToolError

from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import ACTION_QUERY, KIND_TABLE, Resource
from arrowhead.config import get_settings
from arrowhead.content.provenance import wrap_content
from arrowhead.content.text_safe import sanitize_text

_MISSING_SQL_EXTRA = (
    "the SQL connector requires the 'sql' extra: install arrowhead[sql]"
)


class SqlGuardError(Exception):
    """A query was refused before it could run."""


class SqlConnectorError(Exception):
    """A vetted query could not be executed safely."""


@dataclass(frozen=True)
class GuardedQuery:
    """A vetted read-only query and the tables it reads."""

    sql: str
    tables: frozenset[str]


def guard_read_query(query: str, *, dialect: str | None = None) -> GuardedQuery:
    """Parse and vet a read-only query, or raise SqlGuardError.

    dialect names the SQL dialect to parse against (e.g. "postgres",
    "sqlite"); None uses the parser's default.
    """
    try:
        import sqlglot
        from sqlglot import exp
        from sqlglot.errors import ParseError
    except ImportError as exc:  # pragma: no cover - only without the extra
        raise SqlGuardError(_MISSING_SQL_EXTRA) from exc

    try:
        statements = sqlglot.parse(query, dialect=dialect)
    except ParseError as exc:
        raise SqlGuardError("query could not be parsed") from exc

    statements = [statement for statement in statements if statement is not None]
    if not statements:
        raise SqlGuardError("no statement to run")
    if len(statements) > 1:
        raise SqlGuardError("only a single statement may run per call")

    root = statements[0]
    if not isinstance(root, exp.Query):
        raise SqlGuardError("only read-only SELECT statements are allowed")

    write_nodes = (
        exp.Insert,
        exp.Update,
        exp.Delete,
        exp.Merge,
        exp.Create,
        exp.Drop,
        exp.Alter,
        exp.Command,
        exp.Set,
        exp.Into,
    )
    if root.find(*write_nodes) is not None:
        raise SqlGuardError("only read-only SELECT statements are allowed")

    return GuardedQuery(sql=root.sql(dialect=dialect), tables=_referenced_tables(root))


def _referenced_tables(root) -> frozenset[str]:
    """The real tables a parsed query reads, excluding CTE names."""
    from sqlglot import exp

    cte_aliases = {cte.alias for cte in root.find_all(exp.CTE) if cte.alias}
    tables: set[str] = set()
    for table in root.find_all(exp.Table):
        if not table.catalog and not table.db and table.name in cte_aliases:
            continue
        parts = [part for part in (table.catalog, table.db, table.name) if part]
        if parts:
            tables.add(".".join(parts).lower())
    return frozenset(tables)


# Engines hold a connection pool and are expensive to build, so one is created
# per DSN on first use and reused. dispose_engines closes them on shutdown.
_engines: dict[str, object] = {}


def _get_engine(dsn: str):
    engine = _engines.get(dsn)
    if engine is None:
        try:
            from sqlalchemy.ext.asyncio import create_async_engine
        except ImportError as exc:  # pragma: no cover - only without the extra
            raise SqlConnectorError(_MISSING_SQL_EXTRA) from exc
        engine = create_async_engine(dsn, pool_pre_ping=True)
        _engines[dsn] = engine
    return engine


async def dispose_engines() -> None:
    """Close every open engine. Called from the server lifespan on shutdown."""
    for engine in list(_engines.values()):
        await engine.dispose()
    _engines.clear()


async def sql_query(query: str, params: dict | None = None) -> dict:
    """Run a read-only SQL query and return its rows as untrusted data. Only a
    single SELECT may run; every referenced table is authorized, and results
    are capped. Bind values with named parameters. Example: sql_query(query=
    "select id, email from users where org = :org", params={"org": "acme"}).
    """
    settings = get_settings()
    if not settings.sql_dsn:
        raise ToolError("the SQL connector is not configured")
    if len(query) > settings.sql_query_max_length:
        raise ToolError(
            f"query exceeds {settings.sql_query_max_length} characters"
        )
    bind = _validate_params(params)

    try:
        guarded = guard_read_query(query, dialect=settings.sql_dialect or None)
    except SqlGuardError as exc:
        raise ToolError(str(exc)) from exc

    # A scope lets the caller reach the tool; this scopes them to the tables.
    for table in sorted(guarded.tables):
        authorize_action(ACTION_QUERY, Resource(kind=KIND_TABLE, identifier=table))

    try:
        rows, columns, truncated = await _execute(guarded, bind, settings)
    except SqlConnectorError as exc:
        raise ToolError(str(exc)) from exc

    payload = json.dumps(rows, ensure_ascii=False, sort_keys=True, default=str)
    wrapped = wrap_content(
        payload,
        source="sql",
        content_format="json",
        retrieved_at=datetime.now(UTC).isoformat(),
    )
    wrapped["metadata"]["columns"] = columns
    wrapped["metadata"]["row_count"] = len(rows)
    wrapped["metadata"]["truncated"] = truncated
    return wrapped


def _validate_params(params: dict | None) -> dict:
    if params is None:
        return {}
    if not isinstance(params, dict):
        raise ToolError("params must be an object of named bind values")
    bind: dict = {}
    for key, value in params.items():
        if not isinstance(key, str) or not key.isidentifier():
            raise ToolError("param names must be identifiers")
        if value is not None and not isinstance(value, (str, int, float, bool)):
            raise ToolError("param values must be scalars")
        bind[key] = value
    return bind


async def _execute(guarded: GuardedQuery, bind: dict, settings):
    try:
        from sqlalchemy import text
        from sqlalchemy.exc import SQLAlchemyError
    except ImportError as exc:  # pragma: no cover - only without the extra
        raise SqlConnectorError(_MISSING_SQL_EXTRA) from exc

    engine = _get_engine(settings.sql_dsn)
    rows: list[dict] = []
    truncated = False
    total_bytes = 0
    try:
        with anyio.fail_after(settings.sql_timeout_seconds):
            async with engine.connect() as conn:
                result = await conn.stream(text(guarded.sql), bind)
                columns = list(result.keys())
                if len(columns) > settings.sql_max_columns:
                    await result.close()
                    raise SqlConnectorError(
                        f"result exceeds {settings.sql_max_columns} columns"
                    )
                async for row in result:
                    record = {
                        column: _cell(value)
                        for column, value in row._mapping.items()
                    }
                    rows.append(record)
                    total_bytes += len(str(record))
                    if (
                        len(rows) >= settings.sql_max_rows
                        or total_bytes > settings.sql_max_bytes
                    ):
                        truncated = True
                        break
                await result.close()
    except TimeoutError as exc:
        raise SqlConnectorError("the query exceeded its time budget") from exc
    except SQLAlchemyError as exc:
        raise SqlConnectorError(f"query failed: {type(exc).__name__}") from exc
    return rows, columns, truncated


def _cell(value):
    """Return a JSON-safe, sanitized form of a database value."""
    if isinstance(value, str):
        return sanitize_text(value)
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    return sanitize_text(str(value))
