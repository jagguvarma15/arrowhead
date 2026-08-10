"""The server refuses to serve HTTP with authentication disabled unless a
deployment opts in explicitly, closing the fully-open-over-the-network footgun.
"""

import pytest


def test_http_without_auth_refuses_to_start(monkeypatch):
    monkeypatch.setenv("ARROWHEAD_TRANSPORT", "http")
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "false")
    monkeypatch.delenv("ARROWHEAD_ALLOW_INSECURE_HTTP", raising=False)
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    from arrowhead.server import main

    with pytest.raises(SystemExit):
        main()
    get_settings.cache_clear()


def test_insecure_http_opt_in_is_available(monkeypatch):
    monkeypatch.setenv("ARROWHEAD_TRANSPORT", "http")
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "false")
    monkeypatch.setenv("ARROWHEAD_ALLOW_INSECURE_HTTP", "true")
    from arrowhead.config import get_settings

    get_settings.cache_clear()
    settings = get_settings()
    assert settings.allow_insecure_http and not settings.auth_enabled
    get_settings.cache_clear()
