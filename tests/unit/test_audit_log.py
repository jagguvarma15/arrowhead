import json
import logging

from mcp import Client

from arrowhead.observability.audit_log import describe_arguments, describe_resource


def test_describe_resource_hides_the_path():
    # A doc:// URI carries a caller-supplied path that must not reach the log.
    described = describe_resource("doc://notes/secret-plans.md")
    assert "secret-plans" not in described
    assert "notes" not in described
    assert described.startswith("doc://str[")
    # A bare string with no scheme is still shape-only.
    assert describe_resource("plain").startswith("str[")


def audit_records(caplog):
    return [
        json.loads(r.message)
        for r in caplog.records
        if r.name == "arrowhead.audit"
    ]


class TestDescribeArguments:
    def test_values_are_reduced_to_shapes(self):
        shapes = describe_arguments(
            {"url": "https://example.com/?token=hunter2", "count": 3,
             "flags": [1, 2], "opts": {"a": 1}, "ratio": 0.5, "on": True}
        )
        assert shapes == {
            "url": "str[34]",
            "count": "int",
            "flags": "list[2]",
            "opts": "dict[1]",
            "ratio": "float",
            "on": "bool",
        }
        assert "hunter2" not in json.dumps(shapes)

    def test_no_arguments(self):
        assert describe_arguments(None) == {}


async def test_one_line_per_call_without_raw_values(caplog, jail):
    from arrowhead.server import create_server

    with caplog.at_level(logging.INFO, logger="arrowhead.audit"):
        async with Client(create_server(), raise_exceptions=True) as client:
            await client.call_tool("calculate", {"expression": "2 * (3 + 4)"})

    records = audit_records(caplog)
    assert len(records) == 1
    record = records[0]
    assert record["tool"] == "calculate"
    assert record["status"] == "ok"
    assert record["caller"] == "anonymous"
    assert record["arguments"] == {"expression": "str[11]"}
    assert record["duration_ms"] >= 0
    assert "2 * (3 + 4)" not in caplog.text


async def test_refused_jail_escape_never_logs_the_path(caplog, jail):
    from arrowhead.server import create_server

    with caplog.at_level(logging.INFO, logger="arrowhead.audit"):
        async with Client(create_server()) as client:
            result = await client.call_tool(
                "read_file", {"path": "../../etc/passwd"}
            )
            assert result.is_error

    records = audit_records(caplog)
    assert len(records) == 1
    assert records[0]["status"] == "refused"
    assert records[0]["arguments"] == {"path": "str[16]"}
    assert "etc/passwd" not in caplog.text


async def test_authorization_denial_is_audited_distinctly(caplog):
    """An authorization denial is recorded as a refusal tagged with its
    error type, distinct from a validation refusal, and never echoes the
    resource value. The guard wrapper is exercised directly, as the
    registration path applies it."""
    import pytest

    from arrowhead.authz.enforce import AuthorizationError
    from arrowhead.runtime.guards import Guards, guard_tool

    async def guarded_impl(target: str) -> str:
        raise AuthorizationError("not authorized for this document")

    class Spec:
        name = "guarded"
        scope = "docs:read"

        def load(self):
            return guarded_impl

    tool = guard_tool(
        Spec(),
        Guards(enforce_scopes=False, rate_limiter=None, disabled=frozenset()),
    )

    with caplog.at_level(logging.INFO, logger="arrowhead.audit"):
        with pytest.raises(AuthorizationError):
            await tool(target="secret/plan.txt")

    record = audit_records(caplog)[0]
    assert record["status"] == "refused"
    assert record["error_type"] == "AuthorizationError"
    assert "secret/plan.txt" not in caplog.text
