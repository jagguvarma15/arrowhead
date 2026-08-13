"""Working sets: ownership isolation, bounds, validation, and authorization."""

import pytest

from arrowhead.auth.principal import as_principal
from arrowhead.config import get_settings
from arrowhead.errors import ToolError
from arrowhead.tools.workingset import workingset_get, workingset_update
from arrowhead.workingsets import reset_registry


@pytest.fixture(autouse=True)
def fresh_registry():
    reset_registry()
    yield
    reset_registry()


@pytest.fixture
def docs_and_repo(tmp_path, monkeypatch):
    docs = tmp_path / "docs"
    repo = tmp_path / "repo"
    docs.mkdir()
    repo.mkdir()
    (docs / "notes.md").write_text("a note")
    (repo / "app.py").write_text("x = 1\n")
    monkeypatch.setenv("ARROWHEAD_DOCS_ROOT", str(docs))
    monkeypatch.setenv("ARROWHEAD_REPO_ROOT", str(repo))
    get_settings.cache_clear()
    return docs, repo


async def test_pin_get_and_clear(docs_and_repo):
    await workingset_update(
        "bug",
        "pin",
        items=[
            {"kind": "doc", "identifier": "notes.md", "note": "the report"},
            {"kind": "repo_file", "identifier": "app.py"},
        ],
    )
    view = await workingset_get("bug")
    assert view["item_count"] == 2
    identifiers = {item["identifier"] for item in view["items"]}
    assert identifiers == {"notes.md", "app.py"}

    await workingset_update("bug", "clear")
    with pytest.raises(ToolError, match="not found"):
        await workingset_get("bug")


async def test_unpin_removes_one_item(docs_and_repo):
    await workingset_update(
        "bug",
        "pin",
        items=[
            {"kind": "doc", "identifier": "notes.md"},
            {"kind": "repo_file", "identifier": "app.py"},
        ],
    )
    await workingset_update(
        "bug", "unpin", items=[{"kind": "doc", "identifier": "notes.md"}]
    )
    view = await workingset_get("bug")
    assert {item["identifier"] for item in view["items"]} == {"app.py"}


async def test_sets_are_owner_isolated(docs_and_repo):
    with as_principal("alice"):
        await workingset_update(
            "shared", "pin", items=[{"kind": "repo_file", "identifier": "app.py"}]
        )
    with as_principal("bob"):
        with pytest.raises(ToolError, match="not found"):
            await workingset_get("shared")
    with as_principal("alice"):
        assert (await workingset_get("shared"))["item_count"] == 1


async def test_item_count_is_bounded(docs_and_repo, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_WORKINGSET_MAX_ITEMS", "1")
    get_settings.cache_clear()
    reset_registry()
    await workingset_update(
        "bug", "pin", items=[{"kind": "repo_file", "identifier": "app.py"}]
    )
    with pytest.raises(ToolError, match="at most"):
        await workingset_update(
            "bug", "pin", items=[{"kind": "doc", "identifier": "notes.md"}]
        )


async def test_pinning_authorizes_each_item(docs_and_repo, monkeypatch):
    from arrowhead.authz.enforce import get_authorizer

    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    monkeypatch.setenv(
        "ARROWHEAD_AUTHZ_POLICY",
        '{"grants": [{"subject": "*", "actions": ["read"], "prefix": "", '
        '"kinds": ["document", "prefix"]}]}',
    )
    get_settings.cache_clear()
    get_authorizer.cache_clear()
    # The policy grants document reads but not repo reads, so pinning a
    # repo file is refused at pin time.
    with pytest.raises(ToolError, match="not authorized"):
        await workingset_update(
            "bug", "pin", items=[{"kind": "repo_file", "identifier": "app.py"}]
        )
    get_authorizer.cache_clear()


async def test_bad_input_is_refused(docs_and_repo):
    with pytest.raises(ToolError):
        await workingset_update("", "pin", items=[])
    with pytest.raises(ToolError, match="action"):
        await workingset_update("bug", "explode")
    with pytest.raises(ToolError, match="kind"):
        await workingset_update(
            "bug", "pin", items=[{"kind": "other", "identifier": "x"}]
        )
    with pytest.raises(ToolError):
        await workingset_update(
            "bug",
            "pin",
            items=[{"kind": "doc", "identifier": "../../etc/passwd.md"}],
        )
