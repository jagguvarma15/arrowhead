import logging

from mcp.types import CompletionArgument

from arrowhead.authz.enforce import get_authorizer
from arrowhead.completions.handlers import complete_argument, guarded_completion
from arrowhead.config import get_settings


def _arg(name, value=""):
    return CompletionArgument(name=name, value=value)


class _Limiter:
    def __init__(self, allowed: bool) -> None:
        self._allowed = allowed

    async def allow(self, component: str) -> bool:
        return self._allowed


async def test_guarded_completion_rate_limited_returns_empty_and_audits(caplog):
    handler = guarded_completion(_Limiter(allowed=False), frozenset())
    with caplog.at_level(logging.INFO, logger="arrowhead.audit"):
        result = await handler(None, _arg("path", ""), None)
    # rate-limited: no values and the corpus walk never ran
    assert result.values == [] and result.total == 0
    assert any('"event": "complete"' in r.getMessage() for r in caplog.records)


async def test_guarded_completion_kill_switch_returns_empty():
    handler = guarded_completion(_Limiter(allowed=True), frozenset({"completion"}))
    result = await handler(None, _arg("path", ""), None)
    assert result.values == []


async def test_guarded_completion_without_scope_returns_empty(docs):
    (docs / "notes").mkdir()
    (docs / "notes" / "a.md").write_text("x")
    # Scope enforcement on and no token carrying docs:search: the corpus walk
    # must not run, so an under-scoped caller cannot enumerate document paths.
    handler = guarded_completion(
        _Limiter(allowed=True),
        frozenset(),
        enforce_scopes=True,
        scope="docs:search",
    )
    result = await handler(None, _arg("path", "notes/"), None)
    assert result.values == []


async def test_guarded_completion_completes_when_scope_not_enforced(docs):
    (docs / "notes").mkdir()
    (docs / "notes" / "a.md").write_text("x")
    handler = guarded_completion(
        _Limiter(allowed=True),
        frozenset(),
        enforce_scopes=False,
        scope="docs:search",
    )
    result = await handler(None, _arg("path", "notes/"), None)
    assert result.values == ["notes/a.md"]


async def test_completes_matching_authorized_paths(docs):
    (docs / "notes").mkdir()
    (docs / "notes" / "a.md").write_text("x")
    (docs / "notes" / "b.md").write_text("y")
    (docs / "other.txt").write_text("z")
    result = await complete_argument(None, _arg("path", "notes/"), None)
    assert result.values == ["notes/a.md", "notes/b.md"]


async def test_completes_a_partially_typed_segment(docs):
    # The value is an as-you-type fragment, not a whole segment: "no" must
    # still surface notes/a.md.
    (docs / "notes").mkdir()
    (docs / "notes" / "a.md").write_text("x")
    result = await complete_argument(None, _arg("path", "no"), None)
    assert result.values == ["notes/a.md"]


async def test_unauthorized_paths_do_not_consume_the_candidate_cap(
    docs, monkeypatch
):
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    monkeypatch.setenv(
        "ARROWHEAD_AUTHZ_POLICY",
        '{"grants": [{"subject": "*", "actions": ["read"], "prefix": "z/"}]}',
    )
    monkeypatch.setenv("ARROWHEAD_SEARCH_MAX_FILES", "2")
    get_settings.cache_clear()
    get_authorizer.cache_clear()
    for index in range(5):
        (docs / f"a{index}.txt").write_text("x")
    (docs / "z").mkdir()
    (docs / "z" / "ok.txt").write_text("x")
    result = await complete_argument(None, _arg("path", ""), None)
    assert result.values == ["z/ok.txt"]


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
