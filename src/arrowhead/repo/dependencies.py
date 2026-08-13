"""Python import graph over the jailed repository.

Walks the repository's Python files through the stdlib parser and
resolves each import against the set of modules the repository itself
defines: a resolvable target becomes an internal edge, anything else is
reported as an external dependency by name. Relative imports resolve
against the importing module's package. The walk and the parse are both
bounded, and a file that fails to parse contributes no edges rather than
failing the graph.
"""

import ast
from typing import TypedDict

from arrowhead.repo.store import RepoStore, RepoStoreError


class DependencyEdge(TypedDict):
    """One import: the module that imports and the module imported."""

    source: str
    target: str
    external: bool


def module_name(path: str) -> str:
    """The dotted module a repo-relative Python file defines."""
    trimmed = path.removesuffix(".py").removesuffix(".pyi")
    parts = [part for part in trimmed.split("/") if part]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def build_dependency_graph(
    store: RepoStore,
    *,
    path_prefix: str = "",
    max_files: int,
    allow=None,
) -> tuple[list[DependencyEdge], bool]:
    """The bounded import graph under a prefix, plus a truncation flag.

    allow, when given, is a per-path predicate; a file it refuses
    contributes no edges and no module name, so the graph never reveals a
    module the caller could not read directly.
    """
    listing = store.list(
        extensions=frozenset({".py", ".pyi"}),
        max_files=max_files,
        path_prefix=path_prefix,
    )
    if allow is not None:
        listing = type(listing)(
            items=[info for info in listing.items if allow(info.path)],
            truncated=listing.truncated,
        )
    internal = {
        name
        for info in listing.items
        if (name := module_name(info.path))
    }
    packages = {part for name in internal for part in _prefixes(name)}
    edges: list[DependencyEdge] = []
    seen: set[tuple[str, str]] = set()
    for info in listing.items:
        source = module_name(info.path)
        if not source:
            continue
        try:
            text = store.read_text(info.path)
            module = ast.parse(text)
        except (RepoStoreError, SyntaxError, ValueError):
            continue
        known = internal | packages
        for target in _imports(module, source, known):
            key = (source, target)
            if key in seen or not target:
                continue
            seen.add(key)
            root = target.split(".")[0]
            external = (
                target not in internal
                and target not in packages
                and root not in internal
                and root not in packages
            )
            edges.append(
                {"source": source, "target": target, "external": external}
            )
    return edges, listing.truncated


def _prefixes(name: str):
    parts = name.split(".")
    for index in range(1, len(parts) + 1):
        yield ".".join(parts[:index])


def _imports(module: ast.Module, source: str, known: set[str]):
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = source.split(".")
                # Level 1 is the current package for a module inside one;
                # each further level walks one package up.
                trim = node.level if len(base) > 1 else node.level - 1
                anchor = base[: len(base) - trim] if trim else base
                stem = ".".join(anchor)
                stem = f"{stem}.{node.module}" if node.module else stem
            elif node.module:
                stem = node.module
            else:
                continue
            # "from pkg import util" names either a submodule or a symbol;
            # prefer the submodule edge when the repository defines it.
            for alias in node.names:
                candidate = f"{stem}.{alias.name}"
                yield candidate if candidate in known else stem
