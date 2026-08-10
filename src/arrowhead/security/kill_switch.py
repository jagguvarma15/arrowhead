"""Per-component kill switch.

Setting ARROWHEAD_DISABLED_TOOLS (comma-separated names) takes a component
out of service without touching code or images: a disabled tool, prompt, or
resource disappears from its listing and a call to it is refused with a clear
message. The set matches tool names, prompt names, and concrete resource
URIs. Restarting the process with the variable set is the whole rollout.
"""

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext


class ToolDisabledError(ToolError):
    """Refused because the operator disabled this component."""


class KillSwitchMiddleware(Middleware):
    def __init__(self, disabled_tools: set[str]) -> None:
        self._disabled = disabled_tools

    def _refuse_if_disabled(self, name: str) -> None:
        if name in self._disabled:
            raise ToolDisabledError(
                f"{name} is temporarily disabled by the operator"
            )

    async def on_call_tool(
        self, context: MiddlewareContext, call_next: CallNext
    ):
        self._refuse_if_disabled(context.message.name)
        return await call_next(context)

    async def on_read_resource(
        self, context: MiddlewareContext, call_next: CallNext
    ):
        self._refuse_if_disabled(str(context.message.uri))
        return await call_next(context)

    async def on_get_prompt(
        self, context: MiddlewareContext, call_next: CallNext
    ):
        self._refuse_if_disabled(context.message.name)
        return await call_next(context)

    async def on_list_tools(
        self, context: MiddlewareContext, call_next: CallNext
    ):
        tools = await call_next(context)
        return [tool for tool in tools if tool.name not in self._disabled]

    async def on_list_prompts(
        self, context: MiddlewareContext, call_next: CallNext
    ):
        prompts = await call_next(context)
        return [p for p in prompts if p.name not in self._disabled]

    async def on_list_resources(
        self, context: MiddlewareContext, call_next: CallNext
    ):
        resources = await call_next(context)
        return [r for r in resources if str(r.uri) not in self._disabled]
