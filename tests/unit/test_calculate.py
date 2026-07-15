import pytest
from fastmcp.exceptions import ToolError

from arrowhead.tools.calculate import calculate


def test_arithmetic_expression_evaluates():
    assert calculate("2 * (3 + 4)") == 14


def test_injection_rejected_before_evaluation():
    with pytest.raises(ToolError):
        calculate("1+1; import os")


def test_power_operator_rejected_by_second_layer():
    # Passes the character allowlist but must die in the AST interpreter.
    with pytest.raises(ToolError):
        calculate("2 ** 8")


def test_division_by_zero_is_a_clean_error():
    with pytest.raises(ToolError):
        calculate("1 / 0")


def test_configured_length_cap_applies(monkeypatch):
    from arrowhead.config import get_settings

    monkeypatch.setenv("ARROWHEAD_EXPRESSION_MAX_LENGTH", "5")
    get_settings.cache_clear()
    with pytest.raises(ToolError):
        calculate("1 + 2 + 3")
