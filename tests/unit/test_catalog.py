"""The tool catalog is the one place a tool's guard facts are declared.

These tests hold that contract: every declared tool carries a scope and a
rate-limit setting, the setting resolves to a real positive ceiling, the
implementation loads, and the views derived from the catalog (scopes and
rate limits) never drift from it.
"""

import inspect

import pytest

from arrowhead.auth.scopes import TOOL_SCOPES
from arrowhead.config import Settings
from arrowhead.tools.catalog import TOOL_SPECS, ToolSpec


def test_tool_names_are_unique():
    names = [spec.name for spec in TOOL_SPECS]
    assert len(names) == len(set(names))


def test_every_spec_declares_a_scope_and_a_rate_limit():
    for spec in TOOL_SPECS:
        assert spec.scope
        assert spec.rate_limit_attr


def test_rate_limit_attr_resolves_to_a_positive_ceiling():
    settings = Settings()
    for spec in TOOL_SPECS:
        ceiling = getattr(settings, spec.rate_limit_attr)
        assert isinstance(ceiling, int)
        assert ceiling > 0


def test_every_spec_loads_a_callable():
    for spec in TOOL_SPECS:
        assert callable(spec.load())


def test_io_bound_tool_implementations_are_async():
    for spec in TOOL_SPECS:
        if spec.name == "calculate":
            continue
        assert inspect.iscoroutinefunction(spec.load()), spec.name


def test_a_spec_without_a_scope_is_rejected():
    with pytest.raises(ValueError):
        ToolSpec(
            name="unguarded",
            import_path="arrowhead.tools.calculate:calculate",
            scope="",
            rate_limit_attr="calculate_per_minute",
            annotations={},
        )


def test_a_spec_without_a_rate_limit_setting_is_rejected():
    with pytest.raises(ValueError):
        ToolSpec(
            name="unlimited",
            import_path="arrowhead.tools.calculate:calculate",
            scope="tools:read",
            rate_limit_attr="",
            annotations={},
        )


def test_derived_scopes_match_the_catalog():
    assert TOOL_SCOPES == {spec.name: spec.scope for spec in TOOL_SPECS}


def test_derived_rate_limits_cover_every_catalog_tool():
    limits = Settings().rate_limits_per_minute()
    assert set(limits) == {spec.name for spec in TOOL_SPECS}
