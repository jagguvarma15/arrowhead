"""The command-line entry point lists tools and delegates serving."""

import json
from pathlib import Path

import pytest

from arrowhead import cli

GOLDEN_PATH = Path(__file__).parent.parent / "fixtures" / "tool_list_golden.json"


def test_list_tools_prints_each_tool_with_its_scope(capsys):
    exit_code = cli.main(["list-tools"])
    assert exit_code == 0
    lines = capsys.readouterr().out.splitlines()
    printed = dict(line.split("\t") for line in lines)
    assert printed["calculate"] == "tools:read"
    assert printed["doc_write"] == "docs:write"

    from arrowhead.tools.catalog import TOOL_SPECS

    assert set(printed) == {spec.name for spec in TOOL_SPECS}


def test_list_tools_json_emits_the_full_catalog(capsys):
    assert cli.main(["list-tools", "--json"]) == 0
    snapshot = json.loads(capsys.readouterr().out)

    assert set(snapshot) == {"tools", "resources", "prompts"}
    names = [tool["name"] for tool in snapshot["tools"]]
    assert names == sorted(names)
    for tool in snapshot["tools"]:
        assert set(tool) == {
            "name",
            "description",
            "inputSchema",
            "outputSchema",
            "annotations",
            "scope",
            "family",
        }
        assert tool["scope"]
        assert tool["family"]
        assert isinstance(tool["inputSchema"], dict)
    assert {entry.get("uri") for entry in snapshot["resources"]} >= {
        "arrowhead://integrity",
        "docs://index",
    }
    assert [prompt["name"] for prompt in snapshot["prompts"]] == [
        "audit_corpus",
        "summarize_document",
    ]


def test_list_tools_json_agrees_with_the_golden_fixture(capsys):
    assert cli.main(["list-tools", "--json"]) == 0
    snapshot = json.loads(capsys.readouterr().out)
    golden = json.loads(GOLDEN_PATH.read_text())

    observed = [
        {
            "name": tool["name"],
            "description": tool["description"],
            "input_required": sorted(tool["inputSchema"].get("required", [])),
            "input_properties": sorted(
                (tool["inputSchema"].get("properties") or {}).keys()
            ),
            "annotations": dict(sorted(tool["annotations"].items())),
            "has_output_schema": tool["outputSchema"] is not None,
            "scope": tool["scope"],
        }
        for tool in snapshot["tools"]
    ]
    assert observed == golden["tools"]


def test_list_tools_json_honors_the_active_profile(capsys):
    from arrowhead.config import Settings, use_settings

    with use_settings(Settings(profile="core")):
        assert cli.main(["list-tools", "--json"]) == 0
    snapshot = json.loads(capsys.readouterr().out)

    assert {tool["family"] for tool in snapshot["tools"]} == {"core"}
    assert {tool["name"] for tool in snapshot["tools"]} == {
        "safe_fetch",
        "calculate",
        "read_file",
    }
    assert snapshot["prompts"] == []


def test_serve_runs_the_server(monkeypatch):
    calls = []
    monkeypatch.setattr("arrowhead.server.main", lambda: calls.append(True))
    assert cli.main(["serve"]) == 0
    assert calls == [True]


def test_no_command_is_an_error():
    with pytest.raises(SystemExit):
        cli.main([])
