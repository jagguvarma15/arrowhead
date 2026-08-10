"""SQL connector: the statement guard.

Before any query reaches a database it is parsed and checked here, so the read
path can only ever run a single read-only statement. The guard parses the query
with a real SQL parser, requires exactly one statement (which stops a stacked
`SELECT ...; DROP ...` from smuggling a second one), requires that statement to
be a read (rejecting INSERT, UPDATE, DELETE, DDL, SET, and `SELECT ... INTO`),
and returns the canonical statement to run together with the tables it reads.

The canonical statement, not the caller's raw text, is what the connector
executes, so comments and trailing whitespace cannot hide a second statement,
and it is regenerated in the database's own dialect so no clause is silently
dropped. The table set lets the authorizer scope a caller to the tables it may
read; a query that reads no table is authorized against a sentinel resource so
the policy still decides. The parser is the first line of defense: where the
database supports it the connector also runs the statement in a read-only
transaction under a server-side statement timeout, and a read-only database
role is the recommended credential, so a bypass here is still refused.
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime

import anyio
from fastmcp.exceptions import ToolError

from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import ACTION_QUERY, KIND_TABLE, Resource
from arrowhead.config import get_settings
from arrowhead.content.provenance import ProvenancedResult, wrap_content
from arrowhead.content.text_safe import sanitize_text

# A query that references no table is authorized against this sentinel resource
# rather than skipping authorization, so a policy scoped to specific tables can
# still refuse a tableless call such as SELECT pg_sleep(30). Parentheses keep it
# from colliding with any real "schema.table" identifier.
_TABLELESS_RESOURCE = "(no-table)"

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


# SQLAlchemy URL backends mapped to the sqlglot dialect that parses them, so
# the guard vets and regenerates a query in the database's own dialect.
_DSN_DIALECTS = {
    "postgresql": "postgres",
    "postgres": "postgres",
    "sqlite": "sqlite",
    "mysql": "mysql",
    "mariadb": "mysql",
}


def _dialect_from_dsn(dsn: str) -> str | None:
    """Return the sqlglot dialect for a SQLAlchemy DSN, or None if unknown."""
    scheme = dsn.split(":", 1)[0].lower()
    backend = scheme.split("+", 1)[0]
    return _DSN_DIALECTS.get(backend)


# The database statement timeout is the primary per-query bound; the in-process
# deadline is a backstop for a connection that hangs before the database can
# enforce it, so it is given this much grace beyond the configured budget.
_TIMEOUT_GRACE_SECONDS = 5.0


def _session_guards(dialect: str | None, settings) -> tuple[str, ...]:
    """SET statements that enforce read-only and a timeout, where supported.

    Postgres honors a read-only transaction and a per-statement timeout; other
    engines (SQLite) return nothing and rely on the parser guard alone.
    """
    if dialect == "postgres":
        timeout_ms = max(1, int(settings.sql_timeout_seconds * 1000))
        return (
            "SET TRANSACTION READ ONLY",
            f"SET LOCAL statement_timeout = {timeout_ms}",
        )
    return ()


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


async def sql_query(
    query: str, params: dict | None = None
) -> ProvenancedResult:
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

    # Parse against the database's own dialect so the canonical statement the
    # connector runs matches the caller's, rather than round-tripping through a
    # generic dialect that would drop dialect-specific clauses.
    dialect = settings.sql_dialect or _dialect_from_dsn(settings.sql_dsn)
    try:
        guarded = guard_read_query(query, dialect=dialect)
    except SqlGuardError as exc:
        raise ToolError(str(exc)) from exc

    # A scope lets the caller reach the tool; this scopes them to the tables.
    # A tableless query is authorized against a sentinel so it cannot skip the
    # check by referencing nothing.
    for table in sorted(guarded.tables) or [_TABLELESS_RESOURCE]:
        authorize_action(ACTION_QUERY, Resource(kind=KIND_TABLE, identifier=table))

    try:
        rows, columns, truncated = await _execute(guarded, bind, settings, dialect)
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


async def _execute(guarded: GuardedQuery, bind: dict, settings, dialect):
    try:
        from sqlalchemy import text
        from sqlalchemy.exc import SQLAlchemyError
    except ImportError as exc:  # pragma: no cover - only without the extra
        raise SqlConnectorError(_MISSING_SQL_EXTRA) from exc

    engine = _get_engine(settings.sql_dsn)
    guards = _session_guards(dialect, settings)
    try:
        with anyio.fail_after(settings.sql_timeout_seconds + _TIMEOUT_GRACE_SECONDS):
            async with engine.connect() as conn:
                if guards:
                    # Run inside a read-only transaction so the SET LOCAL
                    # timeout and read-only mode apply to this query alone.
                    async with conn.begin():
                        for statement in guards:
                            await conn.execute(text(statement))
                        result = await conn.stream(text(guarded.sql), bind)
                        return await _collect(result, settings)
                result = await conn.stream(text(guarded.sql), bind)
                return await _collect(result, settings)
    except TimeoutError as exc:
        raise SqlConnectorError("the query exceeded its time budget") from exc
    except SQLAlchemyError as exc:
        raise SqlConnectorError(f"query failed: {type(exc).__name__}") from exc
    except Exception as exc:
        # A driver-level error the ORM did not wrap (for example an asyncpg
        # statement cancellation raised while streaming rows) still becomes a
        # clean connector error rather than crashing the call. CancelledError
        # derives from BaseException, so the in-process deadline is unaffected.
        raise SqlConnectorError(f"query failed: {type(exc).__name__}") from exc


async def _collect(result, settings):
    """Drain a streamed result into capped, sanitized rows and columns."""
    rows: list[dict] = []
    truncated = False
    total_bytes = 0
    # Column names are attacker-influenced when the queried table's DDL is not
    # fully trusted, so they are sanitized like values, both in the metadata
    # and as the keys of every row record.
    columns = [sanitize_text(str(name)) for name in result.keys()]
    if len(columns) > settings.sql_max_columns:
        await result.close()
        raise SqlConnectorError(
            f"result exceeds {settings.sql_max_columns} columns"
        )
    async for row in result:
        record = {
            sanitize_text(str(column)): _cell(value)
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
