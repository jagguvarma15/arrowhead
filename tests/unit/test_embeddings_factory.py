from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from arrowhead.config import Settings
from arrowhead.embeddings.base import EmbeddingError
from arrowhead.embeddings.deterministic import DeterministicEmbeddingProvider
from arrowhead.embeddings.factory import build_embedding_provider
from arrowhead.embeddings.http import HTTPEmbeddingProvider


def test_deterministic_is_the_default():
    provider = build_embedding_provider(Settings())
    assert isinstance(provider, DeterministicEmbeddingProvider)
    assert provider.dimensions == Settings().embedding_dimensions


def test_http_selected_by_config():
    provider = build_embedding_provider(
        Settings(
            embedding_provider="http",
            embedding_endpoint="https://api.example/v1/embeddings",
        )
    )
    assert isinstance(provider, HTTPEmbeddingProvider)


def test_unknown_provider_raises():
    with pytest.raises(EmbeddingError):
        build_embedding_provider(SimpleNamespace(embedding_provider="nope"))


def test_settings_reject_an_unknown_provider():
    with pytest.raises(ValidationError):
        Settings(embedding_provider="bogus")
