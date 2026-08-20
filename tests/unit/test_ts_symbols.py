"""The optional tree-sitter backend, exercised when the extra is
installed (CI installs every extra; a default checkout skips)."""

import pytest

pytest.importorskip("tree_sitter_language_pack")

from arrowhead.repo.ts_symbols import extract_with_tree_sitter  # noqa: E402


def test_go_functions_methods_and_types():
    source = (
        "package main\n\n"
        "type Server struct{}\n\n"
        "func (s *Server) Serve() error { return nil }\n\n"
        "func main() {}\n"
    )
    symbols = extract_with_tree_sitter("main.go", ".go", source)
    names = {(s["name"], s["kind"]) for s in symbols}
    assert ("Server", "type") in names
    assert ("Serve", "function") in names
    assert ("main", "function") in names
    assert all(s["line_start"] <= s["line_end"] for s in symbols)


def test_typescript_classes_and_interfaces():
    source = (
        "interface Shape { area(): number }\n"
        "class Circle {}\n"
        "function draw() {}\n"
    )
    symbols = extract_with_tree_sitter("shapes.ts", ".ts", source)
    names = {(s["name"], s["kind"]) for s in symbols}
    assert ("Shape", "interface") in names
    assert ("Circle", "class") in names
    assert ("draw", "function") in names


def test_symbols_are_ordered_by_line():
    source = "func b() {}\n\nfunc a() {}\n"
    symbols = extract_with_tree_sitter("x.go", ".go", source)
    assert [s["name"] for s in symbols] == ["b", "a"]
    assert [s["line_start"] for s in symbols] == [1, 3]


def test_unmapped_suffix_returns_none():
    assert extract_with_tree_sitter("x.zig", ".zig", "fn main() {}") is None
