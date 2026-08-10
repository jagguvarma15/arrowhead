from mcp.types import CompletionArgument

from arrowhead.authz.enforce import get_authorizer
from arrowhead.completions.handlers import complete_argument
from arrowhead.config import get_settings


def _arg(name, value=""):
    return CompletionArgument(name=name, value=value)


async def test_completes_matching_authorized_paths(docs):
    (docs / "notes").mkdir()
    (docs / "notes" / "a.md").write_text("x")
    (docs / "notes" / "b.md").write_text("y")
    (docs / "other.txt").write_text("z")
    result = await complete_argument(None, _arg("path", "notes/"), None)
    assert result.values == ["notes/a.md", "notes/b.md"]


async def test_non_path_argument_returns_no_completion(docs):
    (docs / "a.txt").write_text("x")
    result = await complete_argument(None, _arg("query", "a"), None)
    assert result is None


async def test_completions_are_authorization_filtered(docs, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    monkeypatch.setenv(
        "ARROWHEAD_AUTHZ_POLICY",
        '{"grants": [{"subject": "*", "actions": ["read"], "prefix": "public/"}]}',
    )
    get_settings.cache_clear()
    get_authorizer.cache_clear()
    (docs / "public").mkdir()
    (docs / "public" / "ok.txt").write_text("x")
    (docs / "secret.txt").write_text("y")
    result = await complete_argument(None, _arg("path", ""), None)
    assert result.values == ["public/ok.txt"]
