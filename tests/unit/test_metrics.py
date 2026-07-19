"""Metrics emission.

Installs an in-memory meter provider once for this module, so the
module-level instruments forward to a reader we can inspect. Assertions
check for specific labeled data points rather than exact totals, since
other tests in the session also record through the same global provider.
"""

import pytest
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from arrowhead.observability.metrics import record_tool_call


@pytest.fixture(scope="module")
def reader():
    reader = InMemoryMetricReader()
    metrics.set_meter_provider(MeterProvider(metric_readers=[reader]))
    return reader


def points_for(reader, metric_name):
    result = []
    data = reader.get_metrics_data()
    for resource_metric in data.resource_metrics:
        for scope_metric in resource_metric.scope_metrics:
            for metric in scope_metric.metrics:
                if metric.name == metric_name:
                    result.extend(metric.data.data_points)
    return result


def test_tool_call_counter_records_labeled_points(reader):
    record_tool_call("metrics_probe_tool", "ok", 7.5)
    points = points_for(reader, "arrowhead.tool.calls")
    labels = {
        (p.attributes["tool"], p.attributes["status"]): p.value for p in points
    }
    assert labels.get(("metrics_probe_tool", "ok"), 0) >= 1


def test_tool_call_duration_histogram_records(reader):
    record_tool_call("metrics_probe_duration", "ok", 12.0)
    points = points_for(reader, "arrowhead.tool.duration")
    probe = [p for p in points if p.attributes.get("tool") == "metrics_probe_duration"]
    assert probe and probe[0].count >= 1
