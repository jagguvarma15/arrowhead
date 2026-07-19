"""Search the corpus for a query, bounded and authorization-filtered.

Validates the query, authorizes the search, then scans the corpus in a
worker thread. Regex is opt-in and disabled by default because it is a
denial-of-service surface. Each candidate document is filtered by the
caller's per-document read authorization, so search never reveals a
snippet the caller could not read directly. Results and aggregate snippet
bytes are bounded, and every returned snippet is sanitized and carries the
untrusted-data notice.
"""

import anyio
from fastmcp.exceptions import ToolError

from arrowhead.authz.enforce import authorize_action, get_authorizer
from arrowhead.authz.policy import ACTION_READ, ACTION_SEARCH, Resource
from arrowhead.config import get_settings
from arrowhead.content.markdown_safe import sanitize_markdown
from arrowhead.content.provenance import UNTRUSTED_NOTICE
from arrowhead.content.text_safe import sanitize_text
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
from arrowhead.store.document_store import DocumentStoreError, build_document_store


async def doc_search(
    query: str, path_prefix: str = "", use_regex: bool = False
) -> dict:
    """Search corpus documents for a query and return bounded, sanitized
    snippets. Literal by default; set use_regex when enabled. Example:
    doc_search(query="deadline", path_prefix="notes/").
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
        ACTION_SEARCH, Resource(kind="document", identifier=path_prefix)
    )

    try:
        return await anyio.to_thread.run_sync(
            _run_search, query, path_prefix, use_regex, subject, settings
        )
    except SearchError as exc:
        raise ToolError(str(exc)) from exc


def _run_search(query, path_prefix, use_regex, subject, settings) -> dict:
    store = build_document_store(settings)
    authorizer = get_authorizer()
    matcher = build_matcher(
        query,
        is_regex=use_regex,
        timeout_ms=settings.search_regex_timeout_ms,
    )
    limit = settings.search_max_results
    matches: list[dict] = []
    total_bytes = 0
    truncated = False

    for info in store.list(
        extensions=settings.doc_allowed_extension_set(),
        max_files=settings.search_max_files,
    ):
        if path_prefix and not info.path.startswith(path_prefix):
            continue
        if not authorizer.authorize(
            subject, ACTION_READ, Resource(kind="document", identifier=info.path)
        ).allowed:
            continue
        try:
            data = store.read_bytes(info.path)
        except DocumentStoreError:
            continue
        text = sanitize_text(data)
        for line_match in find_line_matches(
            text,
            matcher,
            max_matches=limit,
            snippet_max_chars=settings.search_snippet_max_chars,
        ):
            # A snippet may come from any format, so neutralize Markdown
            # exfiltration vectors (image URLs, HTML) as well as escapes.
            snippet = sanitize_markdown(sanitize_text(line_match.snippet))
            matches.append(
                {"path": info.path, "line": line_match.line, "snippet": snippet}
            )
            total_bytes += len(snippet)
            if (
                len(matches) >= limit
                or total_bytes >= settings.search_max_total_bytes
            ):
                truncated = True
                break
        if truncated:
            break

    return {
        "notice": UNTRUSTED_NOTICE,
        "query": query,
        "match_count": len(matches),
        "truncated": truncated,
        "matches": matches,
    }
