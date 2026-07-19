from arrowhead.config import Settings
from arrowhead.observability.telemetry import _parse_headers, configure_telemetry


def test_no_op_without_endpoint():
    assert configure_telemetry(Settings()) is False


def test_idempotent_after_configured(monkeypatch):
    # Simulate an already-configured process: a second call is a no-op even
    # with an endpoint set, so providers are never installed twice.
    monkeypatch.setattr(
        "arrowhead.observability.telemetry._configured", True
    )
    settings = Settings(otel_exporter_otlp_endpoint="http://collector:4318")
    assert configure_telemetry(settings) is False


def test_header_parsing():
    assert _parse_headers(None) is None
    assert _parse_headers("") is None
    assert _parse_headers("authorization=Bearer x, x-key=y") == {
        "authorization": "Bearer x",
        "x-key": "y",
    }
