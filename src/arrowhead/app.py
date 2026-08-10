"""The Arrowhead application: one hardened path behind two front doors.

Arrowhead can be reached over HTTP as an MCP server or imported and called
directly from Python. Both go through the same dispatch, so a tool called from
an import runs the identical tracing, audit, kill-switch, rate-limit, input
validation, per-resource authorization, and content-provenance path as a tool
called over the wire.

    app = Arrowhead()
    with app.as_principal("service:etl", {"docs:read"}):
        result = await app.call("doc_read", {"path": "notes.md"})

A tool call that has no caller is anonymous and every scoped tool is denied, so
the guarded path is the default whichever door a call comes through.

Pass settings to run inside a host process with its own configuration rather
than the process environment:

    app = Arrowhead(settings=Settings(docs_root="/data/corpus"))
"""

from __future__ import annotations

from collections.abc import Iterable
from contextlib import AbstractContextManager, nullcontext
from typing import TYPE_CHECKING

from arrowhead.auth.principal import as_principal
from arrowhead.config import Settings, use_settings
from arrowhead.server import create_server

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from fastmcp.prompts.prompt import PromptResult
    from fastmcp.resources.resource import ResourceResult
    from fastmcp.tools.tool import ToolResult
    from mcp.types import Tool


class Arrowhead:
    """An importable handle on the hardened server.

    The underlying server is built once, on first use. When settings are
    supplied they are in effect both while the server is built and for every
    call made through this handle.
    """

    def __init__(self, *, settings: Settings | None = None) -> None:
        self._settings = settings
        self._server: FastMCP | None = None

    def _activate(self) -> AbstractContextManager:
        if self._settings is not None:
            return use_settings(self._settings)
        return nullcontext()

    @property
    def server(self) -> FastMCP:
        """The underlying FastMCP server, built on first access."""
        if self._server is None:
            with self._activate():
                self._server = create_server()
        return self._server

    def as_principal(
        self, subject: str, scopes: Iterable[str] = ()
    ) -> AbstractContextManager:
        """Run the enclosed calls as the given caller.

        Identity, the rate-limit key, per-resource authorization, and scope
        checks all resolve to this caller for the duration of the block.
        """
        return as_principal(subject, scopes)

    async def call(
        self, name: str, arguments: dict | None = None
    ) -> ToolResult:
        """Call a tool through the full hardened path and return its result.

        A tool that refuses or fails raises ToolError, exactly as it does over
        the wire.
        """
        with self._activate():
            return await self.server.call_tool(name, arguments or {})

    async def list_tools(self) -> list[Tool]:
        """List the tools visible to the current caller."""
        with self._activate():
            return list(await self.server.list_tools())

    async def read_resource(self, uri: str) -> ResourceResult:
        """Read a resource through the full hardened path.

        A read that is unauthorized or fails raises, exactly as it does over
        the wire; the same per-resource authorization and sanitization apply.
        """
        with self._activate():
            return await self.server.read_resource(uri)

    async def get_prompt(
        self, name: str, arguments: dict | None = None
    ) -> PromptResult:
        """Render a prompt through the full hardened path."""
        with self._activate():
            return await self.server.render_prompt(name, arguments or {})

    async def complete(self, argument_name: str, value: str = "") -> list[str]:
        """Return authorized completion values for an argument.

        Completions are filtered by the caller's authorization, so this never
        returns a resource the caller could not read.
        """
        from mcp.types import CompletionArgument

        from arrowhead.completions.handlers import complete_argument

        with self._activate():
            result = await complete_argument(
                None, CompletionArgument(name=argument_name, value=value), None
            )
        return list(result.values) if result is not None else []

    def http_app(self, **kwargs):
        """Return the ASGI application for serving the server over HTTP."""
        with self._activate():
            return self.server.http_app(**kwargs)
