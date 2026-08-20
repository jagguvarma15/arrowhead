"""Symbol extraction with graceful degradation.

Python files are parsed with the stdlib compiler for exact definition
spans. Other languages try the optional tree-sitter backend when the
treesitter extra is installed, and otherwise fall back to a line
heuristic that recognizes common definition keywords. A file no strategy
understands yields no symbols; extraction never errors, so one odd file
cannot fail a whole map.
"""

import ast
import re
from functools import lru_cache
from pathlib import PurePosixPath
from typing import TypedDict


class Symbol(TypedDict):
    """One named definition and where it lives."""

    path: str
    name: str
    kind: str
    line_start: int
    line_end: int


_PYTHON_SUFFIXES = frozenset({".py", ".pyi"})

# One conservative pattern per recognized non-Python language family:
# a definition keyword at the start of a line, then the name.
_HEURISTICS: dict[str, re.Pattern] = {
    suffix: pattern
    for suffixes, pattern in (
        (
            (".js", ".jsx", ".ts", ".tsx"),
            re.compile(
                r"^\s*(?:export\s+)?(?:async\s+)?"
                r"(?P<kind>function|class|interface|enum)\s+"
                r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)"
            ),
        ),
        (
            (".go",),
            re.compile(
                r"^(?P<kind>func|type)\s+(?:\([^)]*\)\s+)?"
                r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
            ),
        ),
        (
            (".rs",),
            re.compile(
                r"^\s*(?:pub(?:\([^)]*\))?\s+)?"
                r"(?P<kind>fn|struct|enum|trait|impl)\s+"
                r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
            ),
        ),
        (
            (".java", ".kt", ".scala", ".cs"),
            re.compile(
                r"^\s*(?:public|private|protected|internal|abstract|final"
                r"|sealed|open|static|\s)*"
                r"(?P<kind>class|interface|enum|object|fun)\s+"
                r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
            ),
        ),
        (
            (".rb",),
            re.compile(
                r"^\s*(?P<kind>def|class|module)\s+"
                r"(?P<name>[A-Za-z_][A-Za-z0-9_.?!]*)"
            ),
        ),
    )
    for suffix in suffixes
}

_KIND_NAMES = {
    "func": "function",
    "fn": "function",
    "fun": "function",
    "def": "function",
    "type": "type",
}


def extract_symbols(path: str, text: str) -> list[Symbol]:
    """Extract the named definitions of one file, best effort."""
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in _PYTHON_SUFFIXES:
        return _python_symbols(path, text)
    backend = _tree_sitter_symbols(path, suffix, text)
    if backend is not None:
        return backend
    pattern = _HEURISTICS.get(suffix)
    if pattern is None:
        return []
    return _heuristic_symbols(path, text, pattern)


def _python_symbols(path: str, text: str) -> list[Symbol]:
    try:
        module = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    symbols: list[Symbol] = []

    def visit(nodes, qualifier: str) -> None:
        for node in nodes:
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                name = f"{qualifier}{node.name}"
                kind = (
                    "class" if isinstance(node, ast.ClassDef) else "function"
                )
                symbols.append(
                    {
                        "path": path,
                        "name": name,
                        "kind": kind,
                        "line_start": node.lineno,
                        "line_end": node.end_lineno or node.lineno,
                    }
                )
                visit(node.body, f"{name}.")

    visit(module.body, "")
    return symbols


def _heuristic_symbols(path: str, text: str, pattern) -> list[Symbol]:
    symbols: list[Symbol] = []
    for number, line in enumerate(text.splitlines(), start=1):
        match = pattern.match(line)
        if match is None:
            continue
        kind = match.group("kind")
        symbols.append(
            {
                "path": path,
                "name": match.group("name"),
                "kind": _KIND_NAMES.get(kind, kind),
                "line_start": number,
                "line_end": number,
            }
        )
    return symbols


@lru_cache(maxsize=1)
def _ts_extractor():
    """The optional tree-sitter extractor, probed once per process.

    A failed import is not cached by Python itself, so without this the
    probe would pay the full import machinery again for every file.
    """
    try:
        from arrowhead.repo.ts_symbols import extract_with_tree_sitter
    except ImportError:
        return None
    return extract_with_tree_sitter


def _tree_sitter_symbols(path: str, suffix: str, text: str):
    """Symbols from the optional tree-sitter backend, or None without it."""
    extractor = _ts_extractor()
    if extractor is None:
        return None
    try:
        return extractor(path, suffix, text)
    except Exception:
        # The optional backend must never take down extraction; the
        # heuristic still runs when it cannot parse a file.
        return None
