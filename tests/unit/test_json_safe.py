import pytest

from arrowhead.content.json_safe import JSONSafetyError, parse_json


def test_valid_json_parses():
    assert parse_json('{"a": 1, "b": [2, 3]}') == {"a": 1, "b": [2, 3]}


def test_oversize_input_rejected():
    with pytest.raises(JSONSafetyError):
        parse_json('{"a": "' + "x" * 100 + '"}', max_bytes=16)


def test_deep_nesting_rejected():
    bomb = "[" * 200 + "]" * 200
    with pytest.raises(JSONSafetyError):
        parse_json(bomb, max_depth=64)


def test_nesting_within_limit_allowed():
    nested = "[" * 10 + "1" + "]" * 10
    assert parse_json(nested, max_depth=64) == [[[[[[[[[[1]]]]]]]]]]


def test_too_many_elements_rejected():
    with pytest.raises(JSONSafetyError):
        parse_json("[" + ",".join("1" for _ in range(50)) + "]", max_elements=10)


def test_duplicate_keys_rejected():
    with pytest.raises(JSONSafetyError):
        parse_json('{"a": 1, "a": 2}')


@pytest.mark.parametrize("payload", ["NaN", "Infinity", "-Infinity"])
def test_non_standard_constants_rejected(payload):
    with pytest.raises(JSONSafetyError):
        parse_json(payload)


def test_invalid_json_rejected():
    with pytest.raises(JSONSafetyError):
        parse_json("{not json")


def test_non_string_input_rejected():
    with pytest.raises(JSONSafetyError):
        parse_json(b"{}")
