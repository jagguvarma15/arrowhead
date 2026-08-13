"""The Python import graph of a repository subtree.

Authorized as a range over the repo namespace; the graph walks only files
the caller could read individually, so an edge never reveals a module the
per-file policy hides. The walk is bounded and reports truncation, and
module names are sanitized before they leave.
"""

from typing import TypedDict

import anyio

from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import ACTION_SEARCH, KIND_REPO_PREFIX, Resource
from arrowhead.config import get_settings
from arrowhead.content.provenance import UNTRUSTED_NOTICE
from arrowhead.content.text_safe import sanitize_text
from arrowhead.errors import ToolError
from arrowhead.repo.dependencies import DependencyEdge, build_dependency_graph
from arrowhead.repo.store import build_repo_store
from arrowhead.security.input_validation import (
    ValidationError,
    validate_relative_path,
)


class DependencyGraphResult(TypedDict):
    """The bounded import graph of a repository subtree."""

    notice: str
    edge_count: int
    truncated: bool
    edges: list[DependencyEdge]


async def dependency_graph(path_prefix: str = "") -> DependencyGraphResult:
    """Map the imports between the Python modules under a repository prefix,
    marking dependencies outside it as external.
    Example: dependency_graph(path_prefix="src/").
    """
    settings = get_settings()
    if path_prefix:
        try:
            validate_relative_path(path_prefix)
        except ValidationError as exc:
            raise ToolError(str(exc)) from exc

    authorize_action(
        ACTION_SEARCH, Resource(kind=KIND_REPO_PREFIX, identifier=path_prefix)
    )

    edges, truncated = await anyio.to_thread.run_sync(
        _run_graph, path_prefix, settings
    )
    return {
        "notice": UNTRUSTED_NOTICE,
        "edge_count": len(edges),
        "truncated": truncated,
        "edges": edges,
    }


def _run_graph(path_prefix, settings):
    store = build_repo_store(settings)
    edges, truncated = build_dependency_graph(
        store,
        path_prefix=path_prefix,
        max_files=settings.dependency_graph_max_files,
    )
    sanitized = [
        {
            "source": sanitize_text(edge["source"]),
            "target": sanitize_text(edge["target"]),
            "external": edge["external"],
        }
        for edge in edges
    ]
    return sanitized, truncated
