"""Registers the components declared in the catalog with the server.

The catalog is the single source of each component's name or URI,
implementation, scope, and annotations, so this module does not restate any
of them: it walks the specs and wires each tool, resource, and prompt behind
its guard wrapper, then attaches the argument-completion handler.

Every registration goes through the guards, so a component cannot be
reached, on any transport or in process, without the tracing span, the
audit line, the kill switch, the rate limit, and the scope check. Scope
checks fire only when auth is enabled: with no authentication there is no
token to check them against.
"""

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from arrowhead.config import get_settings
from arrowhead.runtime.guards import (
    Guards,
    guard_prompt,
    guard_resource,
    guard_tool,
)
from arrowhead.tools.catalog import (
    PROFILES,
    PROMPT_SPECS,
    RESOURCE_SPECS,
    TOOL_SPECS,
)


def active_families() -> frozenset[str]:
    """The families the configured profile and feature flags expose.

    A component outside them is never registered: it costs no context,
    appears in no listing, and calling it reports it unknown, exactly
    like a tool that does not exist. The exec family is gated a second
    time behind exec_enabled, so a coding-profile deployment that has not
    turned execution on never exposes the run tools.
    """
    settings = get_settings()
    families = PROFILES[settings.profile]
    if not settings.exec_enabled:
        families = families - {"exec"}
    return families


def register_components(mcp: MCPServer, *, guards: Guards) -> None:
    """Register every in-profile tool, resource, and prompt, and the
    completion handler."""
    register_tools(mcp, guards=guards)
    register_resources(mcp, guards=guards)
    register_prompts(mcp, guards=guards)
    register_completions(mcp, guards=guards)


def register_tools(mcp: MCPServer, *, guards: Guards) -> None:
    families = active_families()
    for spec in TOOL_SPECS:
        if spec.family not in families:
            continue
        mcp.add_tool(
            guard_tool(spec, guards),
            name=spec.name,
            annotations=ToolAnnotations(**spec.annotations),
            icons=list(spec.icons) or None,
        )


def register_resources(mcp: MCPServer, *, guards: Guards) -> None:
    families = active_families()
    for spec in RESOURCE_SPECS:
        if spec.family not in families:
            continue
        mcp.resource(
            spec.uri,
            description=spec.description,
            mime_type=spec.mime_type,
            icons=list(spec.icons) or None,
        )(guard_resource(spec, guards))


def register_prompts(mcp: MCPServer, *, guards: Guards) -> None:
    families = active_families()
    for spec in PROMPT_SPECS:
        if spec.family not in families:
            continue
        mcp.prompt(
            name=spec.name,
            description=spec.description,
            icons=list(spec.icons) or None,
        )(guard_prompt(spec, guards))


def register_completions(mcp: MCPServer, *, guards: Guards) -> None:
    """Attach the guarded argument-completion handler.

    The completion path degrades gracefully rather than raising, so the
    handler carries its own kill-switch, rate-limit, and audit wiring
    instead of the component guard chain.
    """
    from arrowhead.completions.handlers import guarded_completion

    mcp.completion()(guarded_completion(guards.rate_limiter, guards.disabled))
