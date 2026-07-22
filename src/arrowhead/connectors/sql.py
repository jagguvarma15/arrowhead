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

from dataclasses import dataclass

_MISSING_SQL_EXTRA = (
    "the SQL connector requires the 'sql' extra: install arrowhead[sql]"
)


class SqlGuardError(Exception):
    """A query was refused before it could run."""


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
