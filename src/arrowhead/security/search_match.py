"""ReDoS-safe corpus matching primitive.

Literal substring matching is the default and cannot backtrack. Regex
matching is opt-in and runs through the third-party regex engine, which is
resistant to catastrophic backtracking and, as a hard backstop, accepts a
wall-clock timeout so any pattern that does backtrack is aborted rather
than hanging the server. Matching is line-oriented, so each regex
evaluation sees only one bounded line and snippets fall on line boundaries.
"""

from collections.abc import Callable
from dataclasses import dataclass

import regex


class SearchError(Exception):
    """The query is invalid or matching exceeded a safety bound."""


@dataclass(frozen=True)
class LineMatch:
    line: int
    snippet: str


def build_matcher(
    query: str,
    *,
    is_regex: bool,
    timeout_ms: int,
    ignore_case: bool = True,
) -> Callable[[str], bool]:
    """Build a per-line predicate for the query."""
    if is_regex:
        flags = regex.IGNORECASE if ignore_case else 0
        try:
            pattern = regex.compile(query, flags)
        except regex.error as exc:
            raise SearchError("invalid regex pattern") from exc
        timeout_seconds = max(timeout_ms, 1) / 1000.0

        def match(line: str) -> bool:
            try:
                return pattern.search(line, timeout=timeout_seconds) is not None
            except TimeoutError as exc:
                raise SearchError("search pattern timed out") from exc

        return match

    needle = query.lower() if ignore_case else query

    def match(line: str) -> bool:
        haystack = line.lower() if ignore_case else line
        return needle in haystack

    return match


def find_line_matches(
    text: str,
    matcher: Callable[[str], bool],
    *,
    max_matches: int,
    snippet_max_chars: int = 200,
) -> list[LineMatch]:
    """Return line matches for the matcher, bounded by max_matches."""
    matches: list[LineMatch] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if matcher(line):
            matches.append(
                LineMatch(line=lineno, snippet=line.strip()[:snippet_max_chars])
            )
            if len(matches) >= max_matches:
                break
    return matches
