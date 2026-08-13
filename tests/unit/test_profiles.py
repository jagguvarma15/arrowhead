"""A profile exposes exactly its families, and nothing else exists.

An out-of-profile component is unregistered rather than hidden: it costs
no context in the tool list, and calling it is indistinguishable from
calling a tool that never existed.
"""

import pytest
from mcp import Client

from arrowhead.config import get_settings
from arrowhead.tools.catalog import (
    PROFILES,
    PROMPT_SPECS,
    RESOURCE_SPECS,
    TOOL_SPECS,
)


def expected_tools(profile: str, *, exec_enabled: bool = False) -> set[str]:
    families = set(PROFILES[profile])
    if not exec_enabled:
        # The exec family is gated a second time behind the enable flag.
        families.discard("exec")
    return {spec.name for spec in TOOL_SPECS if spec.family in families}


@pytest.mark.parametrize("profile", ["core", "docs", "coding", "full"])
async def test_each_profile_registers_exactly_its_families(
    profile, monkeypatch
):
    monkeypatch.setenv("ARROWHEAD_PROFILE", profile)
    get_settings.cache_clear()
    from arrowhead.server import create_server

    async with Client(create_server(), raise_exceptions=True) as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
    assert names == expected_tools(profile)


async def test_exec_tools_appear_only_when_enabled(monkeypatch):
    monkeypatch.setenv("ARROWHEAD_PROFILE", "coding")
    monkeypatch.setenv("ARROWHEAD_EXEC_ENABLED", "true")
    get_settings.cache_clear()
    from arrowhead.server import create_server

    async with Client(create_server(), raise_exceptions=True) as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
    assert {"run_snippet", "run_tests"} <= names
    assert names == expected_tools("coding", exec_enabled=True)


async def test_full_profile_with_exec_is_the_whole_catalog(monkeypatch):
    monkeypatch.setenv("ARROWHEAD_PROFILE", "full")
    get_settings.cache_clear()
    assert expected_tools("full", exec_enabled=True) == {
        spec.name for spec in TOOL_SPECS
    }


async def test_core_profile_keeps_the_utility_tools_only(monkeypatch):
    assert expected_tools("core") == {"safe_fetch", "calculate", "read_file"}


async def test_out_of_profile_tool_is_unknown_on_call(monkeypatch):
    monkeypatch.setenv("ARROWHEAD_PROFILE", "core")
    get_settings.cache_clear()
    from arrowhead.server import create_server

    async with Client(create_server()) as client:
        result = await client.call_tool("doc_read", {"path": "a.md"})
    assert result.is_error
    assert "Unknown tool" in result.content[0].text


async def test_out_of_profile_resources_and_prompts_are_absent(monkeypatch):
    monkeypatch.setenv("ARROWHEAD_PROFILE", "core")
    get_settings.cache_clear()
    from arrowhead.server import create_server

    async with Client(create_server(), raise_exceptions=True) as client:
        resources = {
            str(r.uri) for r in (await client.list_resources()).resources
        }
        prompts = {p.name for p in (await client.list_prompts()).prompts}
    assert resources == {"arrowhead://integrity"}
    assert prompts == set()


def test_unknown_profile_is_rejected_at_startup():
    from pydantic import ValidationError

    from arrowhead.config import Settings

    with pytest.raises(ValidationError):
        Settings(profile="everything")


def test_every_family_in_a_profile_map_is_a_known_shape():
    catalog_families = {
        spec.family
        for spec in (*TOOL_SPECS, *RESOURCE_SPECS, *PROMPT_SPECS)
    }
    # Profiles may name families a later stage ships; they must still be
    # from the documented set so a typo cannot silently empty a profile.
    documented = catalog_families | {"repo", "assist", "exec", "context"}
    for families in PROFILES.values():
        assert families <= documented
