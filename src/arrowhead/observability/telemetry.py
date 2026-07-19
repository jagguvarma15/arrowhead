"""Wire OpenTelemetry span and metric export.

Spans and metrics are no-ops unless an OTLP endpoint is configured, so the
server carries no telemetry cost until an operator points it at a
collector. When ARROWHEAD_OTEL_EXPORTER_OTLP_ENDPOINT is set, this installs
a tracer provider and a meter provider that export over OTLP/HTTP, and the
tracing middleware and metric instruments begin emitting automatically.
"""

import logging

from arrowhead.config import Settings

logger = logging.getLogger("arrowhead")

_configured = False


def configure_telemetry(settings: Settings) -> bool:
    """Install OTLP tracer and meter providers if an endpoint is set.

    Returns True when telemetry was configured, False when no endpoint is
    set or it was already configured. Idempotent within a process.
    """
    global _configured
    if _configured or not settings.otel_exporter_otlp_endpoint:
        return False

    from opentelemetry import metrics, trace
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
        OTLPMetricExporter,
    )
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter,
    )
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    endpoint = settings.otel_exporter_otlp_endpoint.rstrip("/")
    headers = _parse_headers(settings.otel_exporter_otlp_headers)
    resource = Resource.create({"service.name": settings.otel_service_name})

    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(
        BatchSpanProcessor(
            OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces", headers=headers)
        )
    )
    trace.set_tracer_provider(tracer_provider)

    reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(endpoint=f"{endpoint}/v1/metrics", headers=headers)
    )
    metrics.set_meter_provider(
        MeterProvider(resource=resource, metric_readers=[reader])
    )

    _configured = True
    logger.info("telemetry configured: exporting OTLP to %s", endpoint)
    return True


def _parse_headers(raw: str | None) -> dict[str, str] | None:
    if not raw:
        return None
    headers = {}
    for pair in raw.split(","):
        if "=" in pair:
            key, value = pair.split("=", 1)
            headers[key.strip()] = value.strip()
    return headers or None
