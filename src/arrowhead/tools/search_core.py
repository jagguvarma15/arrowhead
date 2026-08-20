"""The shared search runner behind doc_search and code_search.

Both tools follow one discipline: validate the query, authorize the
search as a range over their namespace, then scan in a worker thread
with per-file read authorization, bounded matches and aggregate snippet
bytes, and sanitized snippets. This module carries that flow once, so a
fix to the filter-and-cap logic cannot land in one tool and silently
miss the other. Each tool keeps its own public function, docstring, and
result shape, so the wire surface does not change.
"""

import anyio

from arrowhead.authz.enforce import authorize_action, get_authorizer
from arrowhead.authz.policy import ACTION_READ, ACTION_SEARCH, Resource
from arrowhead.config import get_settings
from arrowhead.content.markdown_safe import sanitize_markdown
from arrowhead.content.provenance import UNTRUSTED_NOTICE
from arrowhead.content.text_safe import sanitize_text
from arrowhead.errors import ToolError
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


async def run_search(
    query: str,
    path_prefix: str,
    use_regex: bool,
    *,
    prefix_kind: str,
    point_kind: str,
    build_store,
    extensions,
    max_files,
    read,
    store_error: type[Exception],
) -> dict:
    """Validate, authorize, and run one bounded search.

    The callables carry what differs between the corpora: build_store
    makes the jailed store, extensions and max_files read the store's
    settings, and read fetches one file's content for sanitization. A
    store_error while reading skips that file, exactly as a file the
    caller may not read is skipped.
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
        ACTION_SEARCH, Resource(kind=prefix_kind, identifier=path_prefix)
    )

    try:
        return await anyio.to_thread.run_sync(
            _run_search,
            query,
            path_prefix,
            use_regex,
            subject,
            settings,
            point_kind,
            build_store,
            extensions,
            max_files,
            read,
            store_error,
        )
    except SearchError as exc:
        raise ToolError(str(exc)) from exc


def _run_search(
    query,
    path_prefix,
    use_regex,
    subject,
    settings,
    point_kind,
    build_store,
    extensions,
    max_files,
    read,
    store_error,
) -> dict:
    store = build_store(settings)
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

    # The store applies the path prefix while it walks, so hitting the file
    # cap before a match is reported as a truncated listing rather than as a
    # silent zero result.
    listing = store.list(
        extensions=extensions(settings),
        max_files=max_files(settings),
        path_prefix=path_prefix,
    )

    for info in listing.items:
        if not authorizer.authorize(
            subject, ACTION_READ, Resource(kind=point_kind, identifier=info.path)
        ).allowed:
            continue
        try:
            raw = read(store, info.path)
        except store_error:
            continue
        text = sanitize_text(raw)
        for line_match in find_line_matches(
            text,
            matcher,
            max_matches=limit,
            snippet_max_chars=settings.search_snippet_max_chars,
        ):
            # The snippet is a slice of the already-sanitized text, so only
            # the Markdown exfiltration vectors (image URLs, HTML) remain to
            # neutralize here.
            snippet = sanitize_markdown(line_match.snippet)
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
