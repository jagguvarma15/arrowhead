"""The integrity digest pins the enabled tool surface.

The digest must be stable across restarts for the same configuration,
change when anything a model sees changes, and be readable over the wire
by any caller who can list tools.
"""

import json

from mcp import Client

from arrowhead.config import get_settings
from arrowhead.tools.integrity import catalog_digest, enabled_tool_surface


async def test_digest_is_stable_for_a_configuration():
    first = catalog_digest(await enabled_tool_surface())
    second = catalog_digest(await enabled_tool_surface())
    assert first == second


async def test_digest_ignores_listing_order():
    surface = await enabled_tool_surface()
    assert catalog_digest(surface) == catalog_digest(list(reversed(surface)))


async def test_digest_changes_when_a_description_changes():
    surface = await enabled_tool_surface()
    baseline = catalog_digest(surface)
    mutated = [tool.model_copy(deep=True) for tool in surface]
    mutated[0].description = (mutated[0].description or "") + " and more"
    assert catalog_digest(mutated) != baseline


async def test_digest_changes_when_the_surface_shrinks(monkeypatch):
    baseline = catalog_digest(await enabled_tool_surface())
    monkeypatch.setenv("ARROWHEAD_DISABLED_TOOLS", "safe_fetch")
    get_settings.cache_clear()
    assert catalog_digest(await enabled_tool_surface()) != baseline


async def test_digest_differs_between_profiles(monkeypatch):
    monkeypatch.setenv("ARROWHEAD_PROFILE", "core")
    get_settings.cache_clear()
    core = catalog_digest(await enabled_tool_surface())
    monkeypatch.setenv("ARROWHEAD_PROFILE", "full")
    get_settings.cache_clear()
    full = catalog_digest(await enabled_tool_surface())
    assert core != full


async def test_report_is_readable_over_the_wire():
    from arrowhead.server import create_server

    async with Client(create_server(), raise_exceptions=True) as client:
        result = await client.read_resource("arrowhead://integrity")
    report = json.loads(result.contents[0].text)
    assert report["algorithm"] == "sha256"
    assert len(report["digest"]) == 64
    assert report["tool_count"] == 23
    assert report["profile"] == "full"
    # The wire report matches a locally computed digest of the same surface.
    assert report["digest"] == catalog_digest(await enabled_tool_surface())
