"""SQL connector: the statement guard.

Before any query reaches a database it is parsed and checked here. The guard
parses the query with a real SQL parser, bounds its nesting so a pathological
statement cannot exhaust the parser stack, requires exactly one statement (which
stops a stacked `SELECT ...; DROP ...` from smuggling a second one), requires
that statement to be a read (rejecting INSERT, UPDATE, DELETE, DDL, SET, and
`SELECT ... INTO`), rejects row-locking clauses (`FOR UPDATE`), and refuses a
denylist of side-effecting, file, network, and administrative functions
(`pg_read_file`, `dblink`, `query_to_xml`, `pg_terminate_backend`, `LOAD_FILE`,
`BENCHMARK`, and the like) that a read query could otherwise smuggle. It returns
the canonical statement to run together with the tables it reads.

The single-statement check, not comment stripping, is what stops a second
statement: the parser preserves comment bodies, so the guard relies on the
statement count rather than on the canonical text being comment-free. The table
set lets the authorizer scope a caller to the tables it may read; a query that
reads no table is authorized against a dedicated tableless resource the default
policy does not grant, so a functions-only query is denied unless a deployment
opts in.

The parser is defense in depth, not a complete sandbox. The primary controls are
a least-privilege read-only database role and the network egress controls. On
Postgres the connector additionally runs each query in a read-only transaction
under a server-side statement timeout; other engines rely on the parser guard,
the function denylist, the in-process deadline, and the read-only role.
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime

import anyio
from fastmcp.exceptions import ToolError

from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import (
    ACTION_QUERY,
    KIND_TABLE,
    KIND_TABLELESS,
    Resource,
)
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

# The parser is recursive-descent and exhausts the Python stack on deeply
# nested parentheses (a RecursionError well under the length cap). Refuse a
# query whose parenthesis nesting exceeds this before parsing; a real query
# never approaches it.
_MAX_PAREN_DEPTH = 32

# Functions a read query must never call: they read files, reach the network,
# run administrative side effects, or burn server resources, none of which the
# single-SELECT and no-write-node checks catch (query_to_xml and dblink even
# read a table without it appearing in the parsed statement). Matched by name,
# case-insensitively, in any dialect, as defense in depth behind a read-only
# database role.
_DENIED_FUNCTIONS = frozenset(
    {
        # Postgres: files, large objects, network, admin, sleeps.
        "pg_read_file",
        "pg_read_binary_file",
        "pg_read_server_files",
        "pg_ls_dir",
        "pg_stat_file",
        "pg_reload_conf",
        "pg_terminate_backend",
        "pg_cancel_backend",
        "pg_sleep",
        "pg_sleep_for",
        "pg_sleep_until",
        "set_config",
        "lo_import",
        "lo_export",
        "lo_get",
        "lo_put",
        "dblink",
        "dblink_exec",
        "dblink_connect",
        "dblink_open",
        "query_to_xml",
        "query_to_xmlschema",
        "query_to_xml_and_xmlschema",
        "copy",
        # MySQL / MariaDB: files, sleeps, benchmarks, locks, shell.
        "load_file",
        "sleep",
        "benchmark",
        "get_lock",
        "release_lock",
        "sys_exec",
        "sys_eval",
        # SQLite: extension loading and file IO.
        "load_extension",
        "readfile",
        "writefile",
        "fileio_read",
        "edit",
    }
)


def _reject_deep_nesting(query: str) -> None:
    depth = 0
    max_depth = 0
    for char in query:
        if char == "(":
            depth += 1
            max_depth = max(max_depth, depth)
        elif char == ")":
            depth = max(0, depth - 1)
    if max_depth > _MAX_PAREN_DEPTH:
        raise SqlGuardError("query nesting is too deep")


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

    _reject_deep_nesting(query)

    try:
        statements = sqlglot.parse(query, dialect=dialect)
    except (ParseError, RecursionError) as exc:
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

    # A row-locking clause (FOR UPDATE, LOCK IN SHARE MODE) takes write locks
    # and, where no read-only transaction applies, holds them with no timeout.
    if root.find(exp.Lock) is not None:
        raise SqlGuardError("row-locking clauses are not allowed")

    # Refuse a denylisted function (files, network, admin, resource burn) that
    # a read query could otherwise smuggle. These parse as unknown functions.
    for func in root.find_all(exp.Anonymous):
        if (func.name or "").lower() in _DENIED_FUNCTIONS:
            raise SqlGuardError("query uses a function that is not allowed")

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
    # A tableless query is authorized against a dedicated resource kind the
    # default policy does not grant, so a functions-only query cannot skip the
    # check by referencing no table.
    if guarded.tables:
        for table in sorted(guarded.tables):
            authorize_action(
                ACTION_QUERY, Resource(kind=KIND_TABLE, identifier=table)
            )
    else:
        authorize_action(
            ACTION_QUERY,
            Resource(kind=KIND_TABLELESS, identifier=_TABLELESS_RESOURCE),
        )

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

    guards = _session_guards(dialect, settings)
    try:
        # Building the engine can raise a driver-load error that leaks the
        # backend name, so it is inside the wrapped block and becomes a clean
        # connector error like every other failure here.
        engine = _get_engine(settings.sql_dsn)
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
    except SqlConnectorError:
        # A cap breached inside _collect is already a precise message; keep it
        # rather than flattening it into the generic failure below.
        raise
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
    """Drain a streamed result into capped, sanitized rows and columns.

    Bytes, not characters, are counted; a single cell is length-bounded so an
    enormous value is never sanitized or buffered in full; and the byte budget
    is checked before a further row is appended, so no one row is accepted past
    the cap.
    """
    rows: list[dict] = []
    truncated = False
    total_bytes = 0
    max_bytes = settings.sql_max_bytes
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
        record: dict = {}
        for column, value in row._mapping.items():
            key = sanitize_text(str(column))
            if key in record:
                # Two columns that sanitize to the same name would otherwise
                # collapse into one, silently dropping a column's values.
                key = f"{key}#{len(record)}"
            record[key] = _cell(value, max_bytes)
        row_bytes = len(json.dumps(record, default=str).encode("utf-8"))
        if rows and total_bytes + row_bytes > max_bytes:
            truncated = True
            break
        rows.append(record)
        total_bytes += row_bytes
        if len(rows) >= settings.sql_max_rows or total_bytes >= max_bytes:
            truncated = True
            break
    await result.close()
    return rows, columns, truncated


def _cell(value, max_len: int):
    """Return a JSON-safe, sanitized, length-bounded form of a value."""
    if isinstance(value, str):
        return sanitize_text(value[:max_len])
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    return sanitize_text(str(value)[:max_len])
