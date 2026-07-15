import socket

import pytest

from arrowhead.config import get_settings


@pytest.fixture(autouse=True)
def fresh_settings():
    """Settings are cached per process; tests must not leak overrides."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def jail(tmp_path, monkeypatch):
    """Point the read_file jail at a temporary directory."""
    monkeypatch.setenv("ARROWHEAD_JAIL_ROOT", str(tmp_path))
    get_settings.cache_clear()
    return tmp_path


@pytest.fixture
def make_resolver():
    """Factory for getaddrinfo stand-ins returning fixed addresses."""

    def factory(*ips: str):
        async def getaddrinfo(host, port, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))
                for ip in ips
            ]

        return getaddrinfo

    return factory
