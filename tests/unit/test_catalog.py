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
from arrowhead.tools.catalog import (
    PROMPT_SPECS,
    RESOURCE_SPECS,
    TOOL_SPECS,
    PromptSpec,
    ResourceSpec,
    ToolSpec,
)


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
            family="core",
            annotations={},
        )


def test_a_spec_without_a_rate_limit_setting_is_rejected():
    with pytest.raises(ValueError):
        ToolSpec(
            name="unlimited",
            import_path="arrowhead.tools.calculate:calculate",
            scope="tools:read",
            rate_limit_attr="",
            family="core",
            annotations={},
        )


def test_derived_scopes_match_the_catalog():
    assert TOOL_SCOPES == {spec.name: spec.scope for spec in TOOL_SPECS}


def test_derived_rate_limits_cover_every_catalog_tool():
    limits = Settings().rate_limits_per_minute()
    assert set(limits) == {spec.name for spec in TOOL_SPECS}


def test_every_resource_and_prompt_declares_a_scope_and_rate_limit():
    for spec in (*RESOURCE_SPECS, *PROMPT_SPECS):
        assert spec.scope
        assert spec.rate_limit_attr


def test_resource_and_prompt_rate_limits_resolve_to_positive_ceilings():
    settings = Settings()
    for spec in (*RESOURCE_SPECS, *PROMPT_SPECS):
        ceiling = getattr(settings, spec.rate_limit_attr)
        assert isinstance(ceiling, int)
        assert ceiling > 0


def test_every_resource_and_prompt_loads_a_callable():
    for spec in (*RESOURCE_SPECS, *PROMPT_SPECS):
        assert callable(spec.load())


def test_a_resource_without_a_scope_is_rejected():
    with pytest.raises(ValueError):
        ResourceSpec(
            uri="doc://{+path}",
            import_path="arrowhead.resources.documents:read_document_resource",
            scope="",
            rate_limit_attr="resource_read_per_minute",
            family="docs",
            description="x",
        )


def test_a_prompt_without_a_rate_limit_setting_is_rejected():
    with pytest.raises(ValueError):
        PromptSpec(
            name="p",
            import_path="arrowhead.prompts.library:summarize_document",
            scope="docs:read",
            rate_limit_attr="",
            family="docs",
            description="x",
        )


def test_a_spec_without_a_family_is_rejected():
    with pytest.raises(ValueError, match="family"):
        ToolSpec(
            name="familyless",
            import_path="arrowhead.tools.calculate:calculate",
            scope="tools:read",
            rate_limit_attr="calculate_per_minute",
            family="",
            annotations={},
        )


def test_every_catalog_family_is_in_a_profile():
    from arrowhead.tools.catalog import ALL_FAMILIES, PROFILES

    assert PROFILES["full"] == ALL_FAMILIES
    for spec in (*TOOL_SPECS, *RESOURCE_SPECS, *PROMPT_SPECS):
        assert spec.family in ALL_FAMILIES
