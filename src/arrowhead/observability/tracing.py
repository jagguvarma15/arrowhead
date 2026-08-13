"""OpenTelemetry span per component call with W3C Trace Context propagation.

Clients that participate in distributed tracing pass traceparent (and
optionally tracestate) inside the request's _meta object. A thin
observe-only server middleware records that _meta for the duration of the
request; the guard wrappers open a span through tool_span, which joins the
recorded trace context. Without an OpenTelemetry SDK configured the spans
are no-ops, so tracing costs nothing in deployments that do not collect
traces. An in-process call has no wire _meta and simply starts a new trace.
"""

from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar

from opentelemetry import trace
from opentelemetry.trace import SpanKind, Status, StatusCode
from opentelemetry.trace.propagation.tracecontext import (
    TraceContextTextMapPropagator,
)

_tracer = trace.get_tracer("arrowhead")
_propagator = TraceContextTextMapPropagator()

# The current wire request's _meta, recorded by capture_meta_middleware. The
# guards run inside the handler, so a ContextVar is the channel between the
# transport layer and the span they open.
request_meta_var: ContextVar[Mapping | None] = ContextVar(
    "arrowhead_request_meta", default=None
)


def capture_meta_middleware():
    """A server middleware that only records the request's _meta.

    It never refuses, rewrites, or reorders anything; every guard that acts
    on a request lives in the per-component wrappers so the import door runs
    the identical chain.
    """

    async def capture(context, call_next):
        token = request_meta_var.set(context.meta)
        try:
            return await call_next(context)
        finally:
            request_meta_var.reset(token)

    return capture


def _meta_carrier() -> dict[str, str]:
    """Collect traceparent/tracestate from the recorded request _meta."""
    meta = request_meta_var.get()
    if meta is None:
        return {}
    if not isinstance(meta, Mapping):
        meta = meta.model_dump(exclude_none=True)
    carrier = {}
    for key in ("traceparent", "tracestate"):
        value = meta.get(key)
        if isinstance(value, str):
            carrier[key] = value
    return carrier


@contextmanager
def tool_span(operation: str, component: str):
    """Open one server span for a component call and set its status.

    The span joins the caller's trace when the request _meta carried W3C
    trace context; an exception marks the span as an error and propagates.
    """
    carrier = _meta_carrier()
    parent = _propagator.extract(carrier) if carrier else None
    with _tracer.start_as_current_span(
        f"{operation} {component}",
        context=parent,
        kind=SpanKind.SERVER,
        attributes={"mcp.tool.name": component},
    ) as span:
        try:
            yield span
        except Exception as exc:
            span.set_status(Status(StatusCode.ERROR, type(exc).__name__))
            raise
        span.set_status(Status(StatusCode.OK))
