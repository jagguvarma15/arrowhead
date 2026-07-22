"""The single declarative record of every tool this server exposes.

Each tool is described exactly once, here, by a ToolSpec: the callable that
implements it, the OAuth scope a caller must hold to reach it, the settings
attribute that caps its call rate, and its behavior annotations. Registration,
scope wiring, and rate-limit ceilings all read from this one list, so a tool
cannot be added without declaring the controls that guard it; a spec with no
scope or no rate-limit setting is rejected at construction.

The callable is referenced by import path rather than imported here, so reading
this catalog stays cheap: nothing loads a tool body, a network client, or a
driver until the tool is actually registered.
"""

import importlib
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolSpec:
    """Everything the server needs to expose one tool safely.

    name: the tool name clients call.
    import_path: "module:attribute" locating the async implementation.
    scope: the OAuth scope required to call the tool over an authed transport.
    rate_limit_attr: the Settings attribute holding this tool's per-minute
        ceiling, so the limit stays configurable per deployment.
    annotations: MCP behavior hints (read-only, destructive, open-world).
    """

    name: str
    import_path: str
    scope: str
    rate_limit_attr: str
    annotations: dict = field(compare=False)

    def __post_init__(self) -> None:
        if not self.scope:
            raise ValueError(f"tool {self.name!r} must declare an OAuth scope")
        if not self.rate_limit_attr:
            raise ValueError(
                f"tool {self.name!r} must declare a rate-limit setting"
            )

    def load(self) -> Callable:
        """Import and return the tool's implementation callable."""
        module_name, _, attribute = self.import_path.partition(":")
        return getattr(importlib.import_module(module_name), attribute)


TOOL_SPECS: list[ToolSpec] = [
    ToolSpec(
        name="safe_fetch",
        import_path="arrowhead.tools.safe_fetch:safe_fetch",
        scope="tools:read",
        rate_limit_attr="safe_fetch_per_minute",
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": True,
        },
    ),
    ToolSpec(
        name="calculate",
        import_path="arrowhead.tools.calculate:calculate",
        scope="tools:read",
        rate_limit_attr="calculate_per_minute",
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    ),
    ToolSpec(
        name="read_file",
        import_path="arrowhead.tools.read_file:read_file",
        scope="tools:read",
        rate_limit_attr="read_file_per_minute",
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    ),
    ToolSpec(
        name="doc_search",
        import_path="arrowhead.tools.doc_search:doc_search",
        scope="docs:search",
        rate_limit_attr="doc_search_per_minute",
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    ),
    ToolSpec(
        name="doc_read",
        import_path="arrowhead.tools.doc_read:doc_read",
        scope="docs:read",
        rate_limit_attr="doc_read_per_minute",
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    ),
    ToolSpec(
        name="doc_retrieve",
        import_path="arrowhead.tools.doc_retrieve:doc_retrieve",
        scope="docs:read",
        rate_limit_attr="doc_retrieve_per_minute",
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": True,
        },
    ),
    ToolSpec(
        name="doc_scan",
        import_path="arrowhead.tools.doc_scan:doc_scan",
        scope="docs:scan",
        rate_limit_attr="doc_scan_per_minute",
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    ),
    ToolSpec(
        name="doc_write",
        import_path="arrowhead.tools.doc_write:doc_write",
        scope="docs:write",
        rate_limit_attr="doc_write_per_minute",
        annotations={
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    ),
    ToolSpec(
        name="sql_query",
        import_path="arrowhead.connectors.sql:sql_query",
        scope="sql:read",
        rate_limit_attr="sql_query_per_minute",
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    ),
]
