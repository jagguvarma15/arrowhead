import json
import logging

from fastmcp import Client

from arrowhead.observability.audit_log import describe_arguments


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


async def test_one_line_per_call_without_raw_values(
    caplog, stdio_transport, jail
):
    from arrowhead.server import create_server

    with caplog.at_level(logging.INFO, logger="arrowhead.audit"):
        async with Client(create_server()) as client:
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


async def test_refused_jail_escape_never_logs_the_path(
    caplog, stdio_transport, jail
):
    from arrowhead.server import create_server

    with caplog.at_level(logging.INFO, logger="arrowhead.audit"):
        async with Client(create_server()) as client:
            result = await client.call_tool(
                "read_file",
                {"path": "../../etc/passwd"},
                raise_on_error=False,
            )
            assert result.is_error

    records = audit_records(caplog)
    assert len(records) == 1
    assert records[0]["status"] == "refused"
    assert records[0]["arguments"] == {"path": "str[16]"}
    assert "etc/passwd" not in caplog.text
