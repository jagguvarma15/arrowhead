import math

import pytest

from arrowhead.embeddings.base import EmbeddingError
from arrowhead.embeddings.deterministic import DeterministicEmbeddingProvider


async def test_dimension_and_normalization():
    provider = DeterministicEmbeddingProvider(16)
    [vector] = await provider.embed(["hello"])
    assert len(vector) == 16
    assert provider.dimensions == 16
    assert math.isclose(math.sqrt(sum(v * v for v in vector)), 1.0, rel_tol=1e-9)


async def test_same_text_maps_to_the_same_vector():
    provider = DeterministicEmbeddingProvider(8)
    vectors = await provider.embed(["a", "b", "a"])
    assert vectors[0] == vectors[2]
    assert vectors[0] != vectors[1]


async def test_batch_maps_one_to_one():
    provider = DeterministicEmbeddingProvider(4)
    assert await provider.embed([]) == []
    assert len(await provider.embed(["x", "y", "z"])) == 3


def test_dimensions_must_be_positive():
    with pytest.raises(EmbeddingError):
        DeterministicEmbeddingProvider(0)
