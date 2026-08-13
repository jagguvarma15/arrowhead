import json

import httpx
import pytest

from arrowhead.config import Settings
from arrowhead.embeddings.base import EmbeddingError
from arrowhead.embeddings.http import HTTPEmbeddingProvider

PUBLIC_IP = "93.184.216.34"


def _settings(**overrides) -> Settings:
    base = {
        "embedding_endpoint": "https://api.example/v1/embeddings",
        "embedding_dimensions": 4,
        "embedding_model": "m",
        "embedding_api_key": "secret",
    }
    base.update(overrides)
    return Settings(**base)


def _ok_handler(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    return httpx.Response(
        200,
        json={
            "data": [
                {"index": i, "embedding": [0.1, 0.2, 0.3, 0.4]}
                for i in range(len(body["input"]))
            ]
        },
    )


async def test_embeds_and_pins_the_address_with_the_key(make_resolver):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["host"] = request.url.host
        seen["host_header"] = request.headers.get("host")
        seen["auth"] = request.headers.get("authorization")
        return _ok_handler(request)

    provider = HTTPEmbeddingProvider(
        _settings(),
        transport=httpx.MockTransport(handler),
        getaddrinfo=make_resolver(PUBLIC_IP),
    )
    vectors = await provider.embed(["a", "b"])
    assert len(vectors) == 2
    assert len(vectors[0]) == 4
    assert seen["host"] == PUBLIC_IP
    assert seen["host_header"] == "api.example"
    assert seen["auth"] == "Bearer secret"


async def test_endpoint_not_on_egress_allowlist_refused(make_resolver):
    provider = HTTPEmbeddingProvider(
        _settings(egress_allowed_hosts="allowed.example"),
        transport=httpx.MockTransport(_ok_handler),
        getaddrinfo=make_resolver(PUBLIC_IP),
    )
    with pytest.raises(EmbeddingError):
        await provider.embed(["x"])


async def test_private_address_refused(make_resolver):
    provider = HTTPEmbeddingProvider(
        _settings(),
        transport=httpx.MockTransport(_ok_handler),
        getaddrinfo=make_resolver("10.0.0.5"),
    )
    with pytest.raises(EmbeddingError):
        await provider.embed(["x"])


async def test_redirect_is_refused_so_the_key_never_follows(make_resolver):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/"})

    provider = HTTPEmbeddingProvider(
        _settings(),
        transport=httpx.MockTransport(handler),
        getaddrinfo=make_resolver(PUBLIC_IP),
    )
    with pytest.raises(EmbeddingError):
        await provider.embed(["x"])


async def test_dimension_mismatch_refused(make_resolver):
    provider = HTTPEmbeddingProvider(
        _settings(embedding_dimensions=8),
        transport=httpx.MockTransport(_ok_handler),
        getaddrinfo=make_resolver(PUBLIC_IP),
    )
    with pytest.raises(EmbeddingError):
        await provider.embed(["x"])


def test_missing_endpoint_refused():
    with pytest.raises(EmbeddingError):
        HTTPEmbeddingProvider(_settings(embedding_endpoint=""))
