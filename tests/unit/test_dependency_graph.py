"""The import graph: internal resolution, externals, bounds, and filtering."""

import pytest

from arrowhead.config import get_settings
from arrowhead.repo.dependencies import build_dependency_graph, module_name
from arrowhead.repo.store import build_repo_store


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_REPO_ROOT", str(tmp_path))
    get_settings.cache_clear()
    return tmp_path


def test_module_name_maps_files_and_packages():
    assert module_name("pkg/mod.py") == "pkg.mod"
    assert module_name("pkg/__init__.py") == "pkg"
    assert module_name("top.py") == "top"


def test_internal_and_external_edges(repo):
    pkg = repo / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "core.py").write_text("import json\nfrom pkg import util\n")
    (pkg / "util.py").write_text("import httpx\n")
    edges, truncated = build_dependency_graph(
        build_repo_store(get_settings()), max_files=100
    )
    assert truncated is False
    by_pair = {(e["source"], e["target"]): e["external"] for e in edges}
    assert by_pair[("pkg.core", "pkg.util")] is False
    assert by_pair[("pkg.core", "json")] is True
    assert by_pair[("pkg.util", "httpx")] is True


def test_relative_imports_resolve_inside_the_package(repo):
    pkg = repo / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "a.py").write_text("from .b import thing\n")
    (pkg / "b.py").write_text("thing = 1\n")
    edges, _ = build_dependency_graph(
        build_repo_store(get_settings()), max_files=100
    )
    assert {("pkg.a", "pkg.b")} <= {(e["source"], e["target"]) for e in edges}


def test_unparsable_file_contributes_nothing(repo):
    (repo / "ok.py").write_text("import json\n")
    (repo / "broken.py").write_text("def broken(:\n")
    edges, _ = build_dependency_graph(
        build_repo_store(get_settings()), max_files=100
    )
    assert all(e["source"] == "ok" for e in edges)


def test_disallowed_files_contribute_nothing(repo):
    (repo / "open.py").write_text("import hidden\n")
    (repo / "hidden.py").write_text("import json\n")
    edges, _ = build_dependency_graph(
        build_repo_store(get_settings()),
        max_files=100,
        allow=lambda path: path != "hidden.py",
    )
    sources = {e["source"] for e in edges}
    assert "hidden" not in sources
    # With hidden.py filtered out, its module is unknown to the graph and
    # reports as external rather than confirming the module exists.
    pair = next(e for e in edges if e["target"] == "hidden")
    assert pair["external"] is True


def test_walk_is_bounded(repo):
    for index in range(6):
        (repo / f"m{index}.py").write_text("import json\n")
    edges, truncated = build_dependency_graph(
        build_repo_store(get_settings()), max_files=3
    )
    assert truncated is True
    assert len({e["source"] for e in edges}) == 3
