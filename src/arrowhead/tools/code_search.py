"""Search the jailed repository for a query, bounded and authorized.

The document-search discipline applied to source code: the query is
validated, the search is authorized as a range over the repo namespace,
each candidate file is filtered by the caller's per-file authorization,
regex stays opt-in behind the same setting, matches and aggregate snippet
bytes are bounded, and every snippet is sanitized and framed as untrusted
data. Error text never echoes a path. The flow itself lives in
search_core, shared with doc_search.
"""

from typing import TypedDict

from arrowhead.authz.policy import KIND_REPO_FILE, KIND_REPO_PREFIX
from arrowhead.repo.store import RepoStoreError, build_repo_store
from arrowhead.tools.search_core import run_search


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
    return await run_search(
        query,
        path_prefix,
        use_regex,
        prefix_kind=KIND_REPO_PREFIX,
        point_kind=KIND_REPO_FILE,
        build_store=build_repo_store,
        extensions=lambda settings: settings.repo_allowed_extension_set(),
        max_files=lambda settings: settings.repo_search_max_files,
        read=lambda store, path: store.read_text(path),
        store_error=RepoStoreError,
    )
