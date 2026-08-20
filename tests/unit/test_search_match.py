"""The matching primitive behind both search tools: literal and regex
matchers, the invalid-pattern and timeout refusals, and the line and
snippet bounds."""

import pytest

from arrowhead.security.search_match import (
    SearchError,
    build_matcher,
    find_line_matches,
)


def test_literal_match_is_case_insensitive_by_default():
    match = build_matcher("Needle", is_regex=False, timeout_ms=100)
    assert match("a needle in a haystack")
    assert match("A NEEDLE")
    assert not match("thread")


def test_literal_match_can_be_case_sensitive():
    match = build_matcher(
        "Needle", is_regex=False, timeout_ms=100, ignore_case=False
    )
    assert match("a Needle")
    assert not match("a needle")


def test_regex_match_and_case_flag():
    match = build_matcher(r"nee+dle", is_regex=True, timeout_ms=100)
    assert match("a neeeedle")
    assert not match("a needl")
    exact = build_matcher(
        r"Needle", is_regex=True, timeout_ms=100, ignore_case=False
    )
    assert not exact("needle")


def test_invalid_regex_is_refused():
    with pytest.raises(SearchError, match="invalid regex"):
        build_matcher("(unclosed", is_regex=True, timeout_ms=100)


def test_backtracking_pattern_times_out_instead_of_hanging():
    # A classic catastrophic-backtracking pattern against a non-matching
    # line must abort within the wall-clock bound, not hang the worker.
    match = build_matcher(r"(a+)+$", is_regex=True, timeout_ms=1)
    with pytest.raises(SearchError, match="timed out"):
        match("a" * 5000 + "b")


def test_line_numbers_and_match_cap():
    text = "one target\nnothing\ntwo target\nthree target\n"
    match = build_matcher("target", is_regex=False, timeout_ms=100)
    matches = find_line_matches(text, match, max_matches=2)
    assert [m.line for m in matches] == [1, 3]
    assert matches[0].snippet == "one target"


def test_snippets_are_stripped_and_capped():
    text = "   " + "x" * 300 + " target\n"
    match = build_matcher("x", is_regex=False, timeout_ms=100)
    matches = find_line_matches(
        text, match, max_matches=5, snippet_max_chars=50
    )
    assert len(matches) == 1
    assert len(matches[0].snippet) == 50
    assert not matches[0].snippet.startswith(" ")
