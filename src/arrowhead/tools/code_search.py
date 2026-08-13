"""Search the jailed repository for a query, bounded and authorized.

The document-search discipline applied to source code: the query is
validated, the search is authorized as a range over the repo namespace,
each candidate file is filtered by the caller's per-file authorization,
regex stays opt-in behind the same setting, matches and aggregate snippet
bytes are bounded, and every snippet is sanitized and framed as untrusted
data. Error text never echoes a path.
"""

from typing import TypedDict

import anyio

from arrowhead.authz.enforce import authorize_action, get_authorizer
from arrowhead.authz.policy import (
    ACTION_READ,
    ACTION_SEARCH,
    KIND_REPO_FILE,
    KIND_REPO_PREFIX,
    Resource,
)
from arrowhead.config import get_settings
from arrowhead.content.markdown_safe import sanitize_markdown
from arrowhead.content.provenance import UNTRUSTED_NOTICE
from arrowhead.content.text_safe import sanitize_text
from arrowhead.errors import ToolError
from arrowhead.repo.store import RepoStoreError, build_repo_store
from arrowhead.security.input_validation import (
    ValidationError,
    validate_relative_path,
    validate_search_query,
)
from arrowhead.security.search_match import (
    SearchError,
    build_matcher,
    find_line_matches,
)


class CodeMatch(TypedDict):
    """One matching line: the file, the line number, and a sanitized snippet."""

    path: str
    line: int
    snippet: str


class CodeSearchResult(TypedDict):
    """The bounded, sanitized result of a repository search."""

    notice: str
    query: str
    match_count: int
    truncated: bool
    matches: list[CodeMatch]


async def code_search(
    query: str, path_prefix: str = "", use_regex: bool = False
) -> CodeSearchResult:
    """Search repository files for a query and return bounded, sanitized
    snippets with line numbers. Literal by default; set use_regex when
    enabled. Example: code_search(query="TODO", path_prefix="src/").
    """
    settings = get_settings()
    try:
        validate_search_query(query, max_length=settings.search_query_max_length)
        if path_prefix:
            validate_relative_path(path_prefix)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc
    if use_regex and not settings.search_regex_enabled:
        raise ToolError("regex search is disabled")

    subject = authorize_action(
        ACTION_SEARCH, Resource(kind=KIND_REPO_PREFIX, identifier=path_prefix)
    )

    try:
        return await anyio.to_thread.run_sync(
            _run_search, query, path_prefix, use_regex, subject, settings
        )
    except SearchError as exc:
        raise ToolError(str(exc)) from exc


def _run_search(query, path_prefix, use_regex, subject, settings) -> dict:
    store = build_repo_store(settings)
    authorizer = get_authorizer()
    matcher = build_matcher(
        query,
        is_regex=use_regex,
        timeout_ms=settings.search_regex_timeout_ms,
    )
    limit = settings.search_max_results
    matches: list[dict] = []
    total_bytes = 0
    result_capped = False

    listing = store.list(
        extensions=settings.repo_allowed_extension_set(),
        max_files=settings.repo_search_max_files,
        path_prefix=path_prefix,
    )

    for info in listing.items:
        if not authorizer.authorize(
            subject,
            ACTION_READ,
            Resource(kind=KIND_REPO_FILE, identifier=info.path),
        ).allowed:
            continue
        try:
            text = store.read_text(info.path)
        except RepoStoreError:
            continue
        text = sanitize_text(text)
        for line_match in find_line_matches(
            text,
            matcher,
            max_matches=limit,
            snippet_max_chars=settings.search_snippet_max_chars,
        ):
            snippet = sanitize_markdown(sanitize_text(line_match.snippet))
            matches.append(
                {"path": info.path, "line": line_match.line, "snippet": snippet}
            )
            total_bytes += len(snippet)
            if (
                len(matches) >= limit
                or total_bytes >= settings.search_max_total_bytes
            ):
                result_capped = True
                break
        if result_capped:
            break

    return {
        "notice": UNTRUSTED_NOTICE,
        "query": query,
        "match_count": len(matches),
        "truncated": listing.truncated or result_capped,
        "matches": matches,
    }
