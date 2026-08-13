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
    icons: optional mcp.types.Icon entries for the tool. The built-in tools
        ship without icons so the tool list that rides in every model context
        stays lean; a deployment may attach its own.
    """

    name: str
    import_path: str
    scope: str
    rate_limit_attr: str
    annotations: dict = field(compare=False)
    icons: tuple = field(default=(), compare=False)

    def __post_init__(self) -> None:
        if not self.scope:
            raise ValueError(f"tool {self.name!r} must declare an OAuth scope")
        if not self.rate_limit_attr:
            raise ValueError(
                f"tool {self.name!r} must declare a rate-limit setting"
            )

    def load(self) -> Callable:
        """Import and return the tool's implementation callable."""
        return _load_callable(self.import_path)


def _load_callable(import_path: str) -> Callable:
    """Import and return the "module:attribute" callable named by import_path."""
    module_name, _, attribute = import_path.partition(":")
    return getattr(importlib.import_module(module_name), attribute)


@dataclass(frozen=True)
class ResourceSpec:
    """A resource or resource template the server exposes, and its guards.

    uri: the resource URI, a template when it contains a {param} such as
        "doc://{+path}".
    import_path: "module:attribute" locating the handler.
    scope: the OAuth scope a caller must hold to read the resource.
    rate_limit_attr: the Settings attribute holding its per-minute ceiling.
    description / mime_type / icons: presentation metadata.
    """

    uri: str
    import_path: str
    scope: str
    rate_limit_attr: str
    description: str
    mime_type: str | None = None
    icons: tuple = field(default=(), compare=False)

    def __post_init__(self) -> None:
        if not self.scope:
            raise ValueError(f"resource {self.uri!r} must declare an OAuth scope")
        if not self.rate_limit_attr:
            raise ValueError(
                f"resource {self.uri!r} must declare a rate-limit setting"
            )

    def load(self) -> Callable:
        return _load_callable(self.import_path)


@dataclass(frozen=True)
class PromptSpec:
    """A prompt the server exposes, and its guards.

    name: the prompt name clients request.
    import_path: "module:attribute" locating the handler.
    scope: the OAuth scope a caller must hold to get the prompt.
    rate_limit_attr: the Settings attribute holding its per-minute ceiling.
    """

    name: str
    import_path: str
    scope: str
    rate_limit_attr: str
    description: str
    icons: tuple = field(default=(), compare=False)

    def __post_init__(self) -> None:
        if not self.scope:
            raise ValueError(f"prompt {self.name!r} must declare an OAuth scope")
        if not self.rate_limit_attr:
            raise ValueError(
                f"prompt {self.name!r} must declare a rate-limit setting"
            )

    def load(self) -> Callable:
        return _load_callable(self.import_path)


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
    ToolSpec(
        name="vector_search",
        import_path="arrowhead.connectors.pgvector:vector_search",
        scope="vector:search",
        rate_limit_attr="vector_search_per_minute",
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    ),
    ToolSpec(
        name="vector_query",
        import_path="arrowhead.connectors.pgvector:vector_query",
        scope="vector:search",
        rate_limit_attr="vector_query_per_minute",
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    ),
    ToolSpec(
        name="doc_index",
        import_path="arrowhead.connectors.pgvector_index:doc_index",
        scope="vector:write",
        rate_limit_attr="vector_index_per_minute",
        annotations={
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    ToolSpec(
        name="scan_corpus_async",
        import_path="arrowhead.connectors.tasks:scan_corpus_async",
        scope="docs:scan",
        rate_limit_attr="task_start_per_minute",
        annotations={
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    ),
    ToolSpec(
        name="task_get",
        import_path="arrowhead.connectors.tasks:task_get",
        scope="tasks:read",
        rate_limit_attr="task_get_per_minute",
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    ),
    ToolSpec(
        name="task_update",
        import_path="arrowhead.connectors.tasks:task_update",
        scope="tasks:write",
        rate_limit_attr="task_update_per_minute",
        annotations={
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
]


RESOURCE_SPECS: list[ResourceSpec] = [
    ResourceSpec(
        uri="docs://index",
        import_path="arrowhead.resources.documents:corpus_index",
        scope="docs:search",
        rate_limit_attr="resource_read_per_minute",
        description="The corpus documents the caller is authorized to read.",
        mime_type="application/json",
    ),
    ResourceSpec(
        uri="doc://{+path}",
        import_path="arrowhead.resources.documents:read_document_resource",
        scope="docs:read",
        rate_limit_attr="resource_read_per_minute",
        description="One corpus document, sanitized for its format.",
    ),
]


PROMPT_SPECS: list[PromptSpec] = [
    PromptSpec(
        name="summarize_document",
        import_path="arrowhead.prompts.library:summarize_document",
        scope="docs:read",
        rate_limit_attr="prompt_get_per_minute",
        description="Summarize a corpus document, treating it as untrusted data.",
    ),
    PromptSpec(
        name="audit_corpus",
        import_path="arrowhead.prompts.library:audit_corpus",
        scope="docs:scan",
        rate_limit_attr="prompt_get_per_minute",
        description="Scan the corpus for secrets and PII and summarize findings.",
    ),
]
