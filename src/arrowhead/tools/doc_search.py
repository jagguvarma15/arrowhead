"""Search the corpus for a query, bounded and authorization-filtered.

Validates the query, authorizes the search, then scans the corpus in a
worker thread. Regex is opt-in and disabled by default because it is a
denial-of-service surface. Each candidate document is filtered by the
caller's per-document read authorization, so search never reveals a
snippet the caller could not read directly. Results and aggregate snippet
bytes are bounded, and every returned snippet is sanitized and carries the
untrusted-data notice. The flow itself lives in search_core, shared with
code_search.
"""

from typing import TypedDict

from arrowhead.authz.policy import KIND_DOCUMENT, KIND_PREFIX
from arrowhead.store.document_store import DocumentStoreError, build_document_store
from arrowhead.tools.search_core import run_search


class SearchMatch(TypedDict):
    """One matching line: the document, the line number, and a sanitized snippet."""

    path: str
    line: int
    snippet: str


class SearchResult(TypedDict):
    """The bounded, sanitized result of a corpus search."""

    notice: str
    query: str
    match_count: int
    truncated: bool
    matches: list[SearchMatch]


async def doc_search(
    query: str, path_prefix: str = "", use_regex: bool = False
) -> SearchResult:
    """Search corpus documents for a query and return bounded, sanitized
    snippets. Literal by default; set use_regex when enabled. Example:
    doc_search(query="deadline", path_prefix="notes/").
    """
    return await run_search(
        query,
        path_prefix,
        use_regex,
        prefix_kind=KIND_PREFIX,
        point_kind=KIND_DOCUMENT,
        build_store=build_document_store,
        extensions=lambda settings: settings.doc_allowed_extension_set(),
        max_files=lambda settings: settings.search_max_files,
        read=lambda store, path: store.read_bytes(path),
        store_error=DocumentStoreError,
    )
