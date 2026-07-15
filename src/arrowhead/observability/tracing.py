"""OpenTelemetry span per tool call with W3C Trace Context propagation.

Clients that participate in distributed tracing pass traceparent (and
optionally tracestate) inside the request's _meta object; the span
created here joins that trace. Without an OpenTelemetry SDK configured
the spans are no-ops, so this middleware costs nothing in deployments
that do not collect traces.
"""

from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from opentelemetry import trace
from opentelemetry.trace import SpanKind, Status, StatusCode
from opentelemetry.trace.propagation.tracecontext import (
    TraceContextTextMapPropagator,
)

_tracer = trace.get_tracer("arrowhead")
_propagator = TraceContextTextMapPropagator()


def _meta_carrier(context: MiddlewareContext) -> dict[str, str]:
    """Collect traceparent/tracestate from the request's _meta object.

    The client-supplied _meta rides on the request context, not on the
    tool-call params the middleware receives as its message.
    """
    meta = None
    if context.fastmcp_context is not None:
        try:
            meta = context.fastmcp_context.request_context.meta
        except (LookupError, AttributeError):
            meta = None
    if meta is None:
        meta = getattr(context.message, "meta", None)
    if meta is None:
        return {}
    if not isinstance(meta, dict):
        meta = meta.model_dump(exclude_none=True)
    carrier = {}
    for key in ("traceparent", "tracestate"):
        value = meta.get(key)
        if isinstance(value, str):
            carrier[key] = value
    return carrier


class TracingMiddleware(Middleware):
    async def on_call_tool(
        self, context: MiddlewareContext, call_next: CallNext
    ):
        message = context.message
        carrier = _meta_carrier(context)
        parent = _propagator.extract(carrier) if carrier else None
        with _tracer.start_as_current_span(
            f"tools/call {message.name}",
            context=parent,
            kind=SpanKind.SERVER,
            attributes={"mcp.tool.name": message.name},
        ) as span:
            try:
                result = await call_next(context)
            except Exception as exc:
                span.set_status(Status(StatusCode.ERROR, type(exc).__name__))
                raise
            span.set_status(Status(StatusCode.OK))
            return result
