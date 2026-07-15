"""Registers the built-in tools with their behavior annotations.

All three tools are read-only. safe_fetch is marked open-world because it
reaches the public internet; the other two act only on server-local state.
"""

from fastmcp import FastMCP

from arrowhead.tools.calculate import calculate
from arrowhead.tools.read_file import read_file
from arrowhead.tools.safe_fetch import safe_fetch


def register_tools(mcp: FastMCP) -> None:
    mcp.tool(
        safe_fetch,
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": True,
        },
    )
    mcp.tool(
        calculate,
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    )
    mcp.tool(
        read_file,
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    )
