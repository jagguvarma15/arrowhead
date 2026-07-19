"""Application metrics.

The instruments bind to whatever meter provider is active. Until one is
configured (see telemetry.configure_telemetry), the OpenTelemetry API
supplies a no-op provider, so recording costs nothing. Once a provider is
installed the same instruments begin exporting, so emission points do not
need to know whether telemetry is on.
"""

from opentelemetry import metrics

_meter = metrics.get_meter("arrowhead")

_tool_calls = _meter.create_counter(
    "arrowhead.tool.calls",
    unit="1",
    description="Tool calls, labeled by tool and outcome status.",
)
_tool_duration = _meter.create_histogram(
    "arrowhead.tool.duration",
    unit="ms",
    description="Tool call duration in milliseconds.",
)


def record_tool_call(tool: str, status: str, duration_ms: float) -> None:
    """Record one tool call for the metrics pipeline."""
    attributes = {"tool": tool, "status": status}
    _tool_calls.add(1, attributes)
    _tool_duration.record(duration_ms, attributes)
