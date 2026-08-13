"""Per-component kill switch.

Setting ARROWHEAD_DISABLED_TOOLS (comma-separated names) takes a component
out of service without touching code or images: a disabled tool, prompt, or
resource disappears from its listing and a call to it is refused with a clear
message. The set matches tool names, prompt names, and concrete resource
URIs. Restarting the process with the variable set is the whole rollout.

The refusal runs inside the guard wrappers; the listing filter runs in the
list middleware, so a disabled component vanishes from both doors.
"""

from arrowhead.errors import ToolError


class ToolDisabledError(ToolError):
    """Refused because the operator disabled this component."""


def refuse_if_disabled(name: str, disabled: frozenset[str]) -> None:
    """Raise the refusal when the operator disabled this component."""
    if name in disabled:
        raise ToolDisabledError(f"{name} is temporarily disabled by the operator")


def filter_disabled(items, disabled: frozenset[str], key) -> list:
    """Drop disabled components from a listing, preserving order."""
    return [item for item in items if key(item) not in disabled]
