"""Per-component guard wrappers: the one hardened path behind every door.

Each tool, resource, and prompt is registered wrapped in a guard chain
that reproduces the order the middleware stack enforced before: the
tracing span wraps everything, the audit line records every outcome
including refusals, and only calls that survive the kill switch, the rate
limit, and the scope check reach the implementation. Because the chain
lives on the component itself rather than on the wire, an import-and-call
invocation runs it identically to an HTTP request.

The wrapper is also the masking boundary. A ToolError carries text
composed for the caller and passes through; any other exception is logged
server-side and replaced with a generic refusal, so a driver string, a
stack detail, or a database error never reaches a client. The SDK returns
whatever exception text it sees, which is why the boundary sits here.

Listings are filtered to match: a disabled component, or one whose scope
the caller does not hold while auth is enabled, is absent from its list
exactly as calling it reports it unknown.
"""

import functools
import inspect
import logging

import anyio.to_thread

from arrowhead.auth.scopes import has_scope, require_scope
from arrowhead.errors import ToolError
from arrowhead.observability.audit_log import (
    audited,
    describe_arguments,
    describe_resource,
)
from arrowhead.observability.tracing import tool_span
from arrowhead.security.kill_switch import refuse_if_disabled
from arrowhead.security.rate_limit import RateLimiter
from arrowhead.tools.catalog import PROMPT_SPECS, RESOURCE_SPECS, TOOL_SPECS

logger = logging.getLogger("arrowhead.server")

_MASKED_ERROR = "internal error"


class Guards:
    """The per-deployment guard state every wrapper closes over."""

    def __init__(
        self,
        *,
        enforce_scopes: bool,
        rate_limiter: RateLimiter | None,
        disabled: frozenset[str],
    ) -> None:
        self.enforce_scopes = enforce_scopes
        self.rate_limiter = rate_limiter
        self.disabled = disabled


def component_visible(name: str, scope: str | None, guards: Guards) -> bool:
    """Whether a component appears in listings for the current caller."""
    if name in guards.disabled:
        return False
    if guards.enforce_scopes and scope is not None and not has_scope(scope):
        return False
    return True


def _describe_wire_arguments(kwargs: dict) -> dict[str, str]:
    """Argument shapes for the audit line, excluding injected parameters.

    A framework-resolved value (an elicitation outcome) is not part of the
    wire arguments and its presence would drift the audit schema, so it is
    dropped from the shapes.
    """
    from mcp.server.elicitation import (
        AcceptedElicitation,
        CancelledElicitation,
        DeclinedElicitation,
    )

    injected = (AcceptedElicitation, DeclinedElicitation, CancelledElicitation)
    return describe_arguments(
        {k: v for k, v in kwargs.items() if not isinstance(v, injected)}
    )


async def _call(fn, args, kwargs):
    if inspect.iscoroutinefunction(fn):
        return await fn(*args, **kwargs)
    return await anyio.to_thread.run_sync(lambda: fn(*args, **kwargs))


def _masked(component: str):
    """Decorator applying the exception-masking boundary around a wrapper.

    A ToolError carries deliberate refusal text and passes through; the SDK
    turns it into an error result whose message is exactly that text.
    Anything else is logged server-side and replaced.
    """

    def apply(inner):
        @functools.wraps(inner)
        async def boundary(*args, **kwargs):
            try:
                return await inner(*args, **kwargs)
            except ToolError:
                raise
            except Exception:
                logger.exception("unhandled error in %s", component)
                raise ToolError(_MASKED_ERROR) from None

        return boundary

    return apply


def _masked_rpc(component: str):
    """The masking boundary for prompt and resource handlers.

    Their SDK paths rewrap ordinary exceptions into generic internal
    errors, so a refusal's text survives only as a protocol error: a
    ToolError is translated into an MCPError carrying the same message,
    and everything else is logged and replaced.
    """
    from mcp.shared.exceptions import MCPError
    from mcp.types import INTERNAL_ERROR

    def apply(inner):
        @functools.wraps(inner)
        async def boundary(*args, **kwargs):
            try:
                return await inner(*args, **kwargs)
            except MCPError:
                raise
            except ToolError as exc:
                raise MCPError(code=INTERNAL_ERROR, message=str(exc)) from None
            except Exception:
                logger.exception("unhandled error in %s", component)
                raise MCPError(
                    code=INTERNAL_ERROR, message=_MASKED_ERROR
                ) from None

        return boundary

    return apply


def guard_tool(spec, guards: Guards):
    """Wrap a tool implementation in the full guard chain.

    The wrapper preserves the implementation's signature, annotations, and
    docstring, so the SDK derives the identical input schema, output
    schema, and description it would from the bare function.
    """
    fn = spec.load()

    @functools.wraps(fn)
    async def guarded(*args, **kwargs):
        with tool_span("tools/call", spec.name):
            async with audited(
                {
                    "event": "tool_call",
                    "tool": spec.name,
                    "arguments": _describe_wire_arguments(kwargs),
                },
                spec.name,
            ):
                refuse_if_disabled(spec.name, guards.disabled)
                if guards.rate_limiter is not None:
                    await guards.rate_limiter.enforce(spec.name)
                if guards.enforce_scopes:
                    require_scope(spec.scope, spec.name, "tool")
                return await _call(fn, args, kwargs)

    # The docstring becomes the wire description; dedent it so the schema a
    # client sees is the deliberate text, not indentation.
    if fn.__doc__:
        guarded.__doc__ = inspect.cleandoc(fn.__doc__)
    return _masked(spec.name)(guarded)


def guard_resource(spec, guards: Guards):
    """Wrap a resource handler; the kill switch keys on the template and
    on the concrete URI, so disabling a template blocks every read it
    expands to as well as hiding it from listings."""
    fn = spec.load()

    @functools.wraps(fn)
    async def guarded(*args, **kwargs):
        uri = _expand_uri(spec.uri, kwargs)
        async with audited(
            {"event": "read_resource", "resource": describe_resource(uri)},
            "resource:read",
        ):
            refuse_if_disabled(spec.uri, guards.disabled)
            refuse_if_disabled(uri, guards.disabled)
            if guards.rate_limiter is not None:
                await guards.rate_limiter.enforce("resource:read")
            if guards.enforce_scopes:
                require_scope(spec.scope, uri, "resource")
            return await _call(fn, args, kwargs)

    return _masked_rpc(spec.uri)(guarded)


def guard_prompt(spec, guards: Guards):
    """Wrap a prompt handler in the guard chain."""
    fn = spec.load()

    @functools.wraps(fn)
    async def guarded(*args, **kwargs):
        async with audited(
            {
                "event": "get_prompt",
                "prompt": spec.name,
                "arguments": describe_arguments(kwargs),
            },
            "prompt:get",
        ):
            refuse_if_disabled(spec.name, guards.disabled)
            if guards.rate_limiter is not None:
                await guards.rate_limiter.enforce("prompt:get")
            if guards.enforce_scopes:
                require_scope(spec.scope, spec.name, "prompt")
            return await _call(fn, args, kwargs)

    return _masked_rpc(spec.name)(guarded)


def _expand_uri(template: str, kwargs: dict) -> str:
    """The concrete URI for a template read, from the handler's arguments."""
    if "{" not in template:
        return template
    uri = template
    for name, value in kwargs.items():
        for form in (f"{{+{name}}}", f"{{{name}*}}", f"{{{name}}}"):
            uri = uri.replace(form, str(value))
    return uri


def visible_tools(tools, guards: Guards) -> list:
    """Filter a tool listing to what the current caller may see."""
    scopes = {spec.name: spec.scope for spec in TOOL_SPECS}
    return [
        tool
        for tool in tools
        if component_visible(tool.name, scopes.get(tool.name), guards)
    ]


def listing_middleware(guards: Guards):
    """A server middleware filtering listings by kill switch and scope.

    It observes list results only; every refusal on a call path lives in
    the component wrappers, so nothing here can diverge between doors. The
    dispatcher hands middleware the serialized wire result, so the filter
    works on the camelCase dict shape.
    """
    tool_scopes = {spec.name: spec.scope for spec in TOOL_SPECS}
    resource_scopes = {spec.uri: spec.scope for spec in RESOURCE_SPECS}
    prompt_scopes = {spec.name: spec.scope for spec in PROMPT_SPECS}

    # method -> (result key, item identity key, scope map)
    listings = {
        "tools/list": ("tools", "name", tool_scopes),
        "prompts/list": ("prompts", "name", prompt_scopes),
        "resources/list": ("resources", "uri", resource_scopes),
        "resources/templates/list": (
            "resourceTemplates",
            "uriTemplate",
            resource_scopes,
        ),
    }

    async def middleware(context, call_next):
        result = await call_next(context)
        route = listings.get(context.method)
        if route is None or not isinstance(result, dict):
            return result
        key, identity, scopes = route
        items = result.get(key)
        if not isinstance(items, list):
            return result
        kept = [
            item
            for item in items
            if component_visible(
                str(item.get(identity, "")),
                scopes.get(str(item.get(identity, ""))),
                guards,
            )
        ]
        return {**result, key: kept}

    return middleware
