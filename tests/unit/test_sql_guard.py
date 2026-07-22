"""The SQL guard admits only single read-only statements and reports the tables
a query reads, so the connector can run it under a read-only role and the
authorizer can scope the caller to those tables.
"""

import pytest

from arrowhead.connectors.sql import SqlGuardError, guard_read_query


def test_a_plain_select_is_allowed():
    guarded = guard_read_query("select id, email from users where org = :org")
    assert guarded.sql.upper().startswith("SELECT")
    assert guarded.tables == frozenset({"users"})


def test_schema_qualified_tables_are_extracted():
    guarded = guard_read_query(
        "SELECT * FROM app.users u JOIN acct.orgs o ON u.org = o.id"
    )
    assert guarded.tables == frozenset({"app.users", "acct.orgs"})


def test_cte_names_are_not_treated_as_tables():
    guarded = guard_read_query("WITH x AS (SELECT * FROM real_t) SELECT * FROM x")
    assert guarded.tables == frozenset({"real_t"})


def test_a_set_operation_is_allowed():
    guarded = guard_read_query("SELECT a FROM t1 UNION SELECT a FROM t2")
    assert guarded.tables == frozenset({"t1", "t2"})


@pytest.mark.parametrize(
    "query",
    [
        "SELECT 1; DROP TABLE users",
        "DROP TABLE users",
        "INSERT INTO t VALUES (1)",
        "UPDATE t SET a = 1",
        "DELETE FROM t",
        "SELECT * INTO newt FROM t",
        "SET search_path = evil",
        "CREATE TABLE t (a int)",
        "ALTER TABLE t ADD COLUMN c int",
    ],
)
def test_writes_and_stacked_queries_are_refused(query):
    with pytest.raises(SqlGuardError):
        guard_read_query(query)


def test_an_unparseable_query_is_refused():
    with pytest.raises(SqlGuardError):
        guard_read_query("this is not sql !!!")


def test_an_empty_query_is_refused():
    with pytest.raises(SqlGuardError):
        guard_read_query("   ")


def test_the_returned_sql_is_a_single_canonical_statement():
    guarded = guard_read_query("select   id  from users   -- trailing")
    assert guarded.sql.split()[:4] == ["SELECT", "id", "FROM", "users"]
    assert ";" not in guarded.sql
    assert "--" not in guarded.sql


def test_named_placeholders_survive_normalization():
    guarded = guard_read_query(
        "SELECT id FROM users WHERE org = :org AND n > :n"
    )
    assert ":org" in guarded.sql
    assert ":n" in guarded.sql
