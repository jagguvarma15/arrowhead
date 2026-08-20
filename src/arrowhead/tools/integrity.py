"""A pinned digest of the tool catalog, for tool-mutation detection.

A malicious or compromised server can change a tool's description or
schema after a client consented to it (a rug pull). The digest gives a
client an anchor to pin: it hashes the semantic surface of every enabled
tool (name, description, input schema, output schema, annotations) in a
canonical form, so any mutation of what the model sees changes the value.
A client records the digest at consent time and compares it each session,
ideally against its own hash of the listing it received; the server also
logs the digest at startup so an operator can corroborate a report.

The digest covers the enabled tool surface, so it legitimately differs
between profiles and kill-switch states; a client pins the digest of the
deployment it consented to.
"""

import hashlib
import json
from typing import TypedDict

from arrowhead.config import get_settings


class IntegrityReport(TypedDict):
    """The pinned catalog digest and what it covers."""

    algorithm: str
    digest: str
    tool_count: int
    profile: str


# Registration and schema generation are a pure function of the profile
# and the exec flag, so the built surface is cached per key rather than
# rebuilding a server and regenerating every schema on each read. The
# kill-switch filter stays per call: it is cheap and can change without
# the surface changing.
_SURFACE_CACHE: dict[tuple[str, bool], list] = {}


def catalog_digest(tools) -> str:
    """The sha256 over the canonical serialization of the tool surface.

    Tools are sorted by name and serialized with sorted keys and no
    incidental whitespace, so the digest depends only on the semantic
    fields a client sees, never on listing order or emission details.
    """
    surface = [
        {
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema,
            "output_schema": tool.output_schema,
            "annotations": (
                tool.annotations.model_dump(by_alias=True, exclude_none=True)
                if tool.annotations is not None
                else None
            ),
        }
        for tool in sorted(tools, key=lambda tool: tool.name)
    ]
    canonical = json.dumps(
        surface, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def enabled_tool_surface():
    """The tool surface the current settings expose.

    Built from the catalog through the same registration and schema
    generation the serving process uses, then filtered by the kill
    switch, so the digest is deterministic for a configuration rather
    than tied to one server object.
    """
    settings = get_settings()
    key = (settings.profile, settings.exec_enabled)
    tools = _SURFACE_CACHE.get(key)
    if tools is None:
        from mcp.server import MCPServer

        from arrowhead.runtime.guards import Guards
        from arrowhead.tools.registry import register_tools

        surface = MCPServer("integrity-surface")
        register_tools(
            surface,
            guards=Guards(
                enforce_scopes=False, rate_limiter=None, disabled=frozenset()
            ),
        )
        tools = await surface.list_tools()
        _SURFACE_CACHE[key] = tools
    disabled = settings.disabled_tool_set()
    return [tool for tool in tools if tool.name not in disabled]


async def integrity_report() -> IntegrityReport:
    """The digest of the enabled tool surface, as a readable resource."""
    tools = await enabled_tool_surface()
    return {
        "algorithm": "sha256",
        "digest": catalog_digest(tools),
        "tool_count": len(tools),
        "profile": get_settings().profile,
    }
