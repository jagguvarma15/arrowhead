"""Per-tool kill switch.

Setting ARROWHEAD_DISABLED_TOOLS (comma-separated tool names) takes a
tool out of service without touching code or images: it disappears from
tools/list and calls to it are refused with a clear message. Restarting
the process with the variable set is the whole rollout.
"""

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext


class ToolDisabledError(ToolError):
    """Refused because the operator disabled this tool."""


class KillSwitchMiddleware(Middleware):
    def __init__(self, disabled_tools: set[str]) -> None:
        self._disabled = disabled_tools

    async def on_call_tool(
        self, context: MiddlewareContext, call_next: CallNext
    ):
        if context.message.name in self._disabled:
            raise ToolDisabledError(
                f"{context.message.name} is temporarily disabled by the operator"
            )
        return await call_next(context)

    async def on_list_tools(
        self, context: MiddlewareContext, call_next: CallNext
    ):
        tools = await call_next(context)
        return [tool for tool in tools if tool.name not in self._disabled]
