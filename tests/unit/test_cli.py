"""The command-line entry point lists tools and delegates serving."""

import pytest

from arrowhead import cli


def test_list_tools_prints_each_tool_with_its_scope(capsys):
    exit_code = cli.main(["list-tools"])
    assert exit_code == 0
    lines = capsys.readouterr().out.splitlines()
    printed = dict(line.split("\t") for line in lines)
    assert printed["calculate"] == "tools:read"
    assert printed["doc_write"] == "docs:write"

    from arrowhead.tools.catalog import TOOL_SPECS

    assert set(printed) == {spec.name for spec in TOOL_SPECS}


def test_serve_runs_the_server(monkeypatch):
    calls = []
    monkeypatch.setattr("arrowhead.server.main", lambda: calls.append(True))
    assert cli.main(["serve"]) == 0
    assert calls == [True]


def test_no_command_is_an_error():
    with pytest.raises(SystemExit):
        cli.main([])
