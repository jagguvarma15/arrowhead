import pytest
from mcp import Client
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)


@pytest.fixture(scope="module")
def exporter():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return exporter


def arrowhead_spans(exporter):
    """The SDK emits its own spans; ours carry the arrowhead scope."""
    return [
        span
        for span in exporter.get_finished_spans()
        if span.instrumentation_scope.name == "arrowhead"
    ]


async def test_span_per_tool_call(exporter):
    exporter.clear()
    from arrowhead.server import create_server

    async with Client(create_server(), raise_exceptions=True) as client:
        await client.call_tool("calculate", {"expression": "1 + 1"})

    spans = arrowhead_spans(exporter)
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "tools/call calculate"
    assert span.attributes["mcp.tool.name"] == "calculate"
    assert span.status.is_ok


async def test_traceparent_in_meta_joins_the_callers_trace(exporter):
    exporter.clear()
    trace_id = "0af7651916cd43dd8448eb211c80319c"
    parent_span_id = "b7ad6b7169203331"

    from arrowhead.observability.tracing import request_meta_var, tool_span

    token = request_meta_var.set(
        {"traceparent": f"00-{trace_id}-{parent_span_id}-01"}
    )
    try:
        with tool_span("tools/call", "calculate"):
            pass
    finally:
        request_meta_var.reset(token)

    spans = arrowhead_spans(exporter)
    assert len(spans) == 1
    span = spans[0]
    assert format(span.context.trace_id, "032x") == trace_id
    assert format(span.parent.span_id, "016x") == parent_span_id
    assert span.parent.is_remote


async def test_client_trace_context_flows_through_the_server(exporter):
    """A caller that sends W3C trace context in _meta sees the server-side
    span join its trace rather than start a new one."""
    exporter.clear()
    trace_id = "1af7651916cd43dd8448eb211c80319c"
    parent_span_id = "c7ad6b7169203331"
    from arrowhead.server import create_server

    async with Client(create_server(), raise_exceptions=True) as client:
        await client.call_tool(
            "calculate",
            {"expression": "1 + 1"},
            meta={"traceparent": f"00-{trace_id}-{parent_span_id}-01"},
        )

    spans = arrowhead_spans(exporter)
    assert len(spans) == 1
    span = spans[0]
    assert format(span.context.trace_id, "032x") == trace_id
    assert span.parent.is_remote


async def test_error_status_recorded_on_refusal(exporter, jail):
    exporter.clear()
    from arrowhead.server import create_server

    async with Client(create_server()) as client:
        await client.call_tool("read_file", {"path": "../../etc/passwd"})

    spans = arrowhead_spans(exporter)
    assert len(spans) == 1
    assert not spans[0].status.is_ok
