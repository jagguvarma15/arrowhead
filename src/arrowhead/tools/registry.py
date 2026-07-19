"""Registers the built-in tools with their behavior annotations.

All three tools are read-only. safe_fetch is marked open-world because it
reaches the public internet; the other two act only on server-local state.

Scope checks are attached only when auth is enabled. Scopes are an
authorization concept: with no authentication there is no token to check
them against, so on stdio and on unauthenticated local HTTP the tools are
registered without checks and remain callable.
"""

from fastmcp import FastMCP

from arrowhead.auth.scopes import scope_checks

_ANNOTATIONS = {
    "safe_fetch": {
        "readOnlyHint": True,
        "destructiveHint": False,
        "openWorldHint": True,
    },
    "calculate": {
        "readOnlyHint": True,
        "destructiveHint": False,
        "openWorldHint": False,
    },
    "read_file": {
        "readOnlyHint": True,
        "destructiveHint": False,
        "openWorldHint": False,
    },
    "doc_search": {
        "readOnlyHint": True,
        "destructiveHint": False,
        "openWorldHint": False,
    },
    "doc_read": {
        "readOnlyHint": True,
        "destructiveHint": False,
        "openWorldHint": False,
    },
}


def register_tools(mcp: FastMCP, *, enforce_scopes: bool = True) -> None:
    from arrowhead.tools.calculate import calculate
    from arrowhead.tools.doc_read import doc_read
    from arrowhead.tools.doc_search import doc_search
    from arrowhead.tools.read_file import read_file
    from arrowhead.tools.safe_fetch import safe_fetch

    functions = {
        "safe_fetch": safe_fetch,
        "calculate": calculate,
        "read_file": read_file,
        "doc_search": doc_search,
        "doc_read": doc_read,
    }
    for name, function in functions.items():
        mcp.tool(
            function,
            annotations=_ANNOTATIONS[name],
            auth=scope_checks(name) if enforce_scopes else None,
        )
