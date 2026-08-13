"""Symbol extraction: exact for Python, best effort elsewhere, never an error."""

import pytest

from arrowhead.repo.symbols import extract_symbols

PY = '''class Widget:
    def method(self):
        return 1


async def handler():
    return 2
'''


def test_python_symbols_are_exact_with_qualified_names():
    symbols = extract_symbols("m.py", PY)
    names = {(s["name"], s["kind"]) for s in symbols}
    assert names == {
        ("Widget", "class"),
        ("Widget.method", "function"),
        ("handler", "function"),
    }
    widget = next(s for s in symbols if s["name"] == "Widget")
    assert widget["line_start"] == 1
    assert widget["line_end"] == 3


def test_unparsable_python_yields_no_symbols():
    assert extract_symbols("m.py", "def broken(:\n") == []


def test_unknown_suffix_yields_no_symbols():
    assert extract_symbols("data.csv", "a,b,c\n") == []


GO = """package main

func Serve(addr string) error {
\treturn nil
}

type Config struct {
\tPort int
}
"""


def test_go_definitions_are_found():
    symbols = extract_symbols("main.go", GO)
    names = {(s["name"], s["kind"]) for s in symbols}
    assert ("Serve", "function") in names
    assert ("Config", "type") in names


TS = """export async function fetchUser(id: string) {
  return id;
}

export class UserStore {
}
"""


def test_typescript_definitions_are_found():
    symbols = extract_symbols("store.ts", TS)
    names = {(s["name"], s["kind"]) for s in symbols}
    assert ("fetchUser", "function") in names
    assert ("UserStore", "class") in names


def test_tree_sitter_backend_when_installed():
    pytest.importorskip("tree_sitter_language_pack")
    RS = "pub fn frobnicate(input: &str) -> String {\n    input.into()\n}\n"
    symbols = extract_symbols("lib.rs", RS)
    assert any(
        s["name"] == "frobnicate" and s["kind"] == "function" for s in symbols
    )
