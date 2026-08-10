"""Validation for vector_search that needs no database.

The collection allowlist, the embedding shape, the identifier guard, and the k
bound are all enforced before a connection is opened, so these run in the plain
unit suite. The query behavior against a real database is covered by the
Postgres integration tests.
"""

import pytest
from fastmcp.exceptions import ToolError

from arrowhead.config import Settings, use_settings
from arrowhead.connectors.pgvector import (
    _bounded_k,
    _safe_identifier,
    _validate_collection,
    _validate_embedding,
    vector_search,
)


def _settings(**kw):
    base = dict(sql_dsn="postgresql+asyncpg://u@h/db", pgvector_collections="docs")
    base.update(kw)
    return Settings(**base)


async def test_unconfigured_connector_refuses():
    with use_settings(Settings(sql_dsn="")):
        with pytest.raises(ToolError, match="not configured"):
            await vector_search("docs", [0.1, 0.2])


async def test_unknown_collection_refused():
    with use_settings(_settings()):
        with pytest.raises(ToolError, match="unknown vector collection"):
            await vector_search("secrets", [0.1, 0.2])


def test_collection_must_be_allowlisted():
    settings = _settings(pgvector_collections="docs, notes")
    assert _validate_collection("notes", settings) == "notes"
    with pytest.raises(ToolError):
        _validate_collection("evil", settings)


def test_no_collections_configured_refuses():
    with pytest.raises(ToolError, match="no vector collections"):
        _validate_collection("docs", _settings(pgvector_collections=""))


def test_embedding_validation():
    settings = _settings(pgvector_max_dimensions=4)
    assert _validate_embedding([1, 2.5, 3], settings) == "[1.0,2.5,3.0]"
    with pytest.raises(ToolError):
        _validate_embedding([], settings)
    with pytest.raises(ToolError):
        _validate_embedding("nope", settings)
    with pytest.raises(ToolError):
        _validate_embedding([1, 2, 3, 4, 5], settings)
    with pytest.raises(ToolError):
        _validate_embedding([1, "x"], settings)


def test_k_is_bounded():
    settings = _settings(pgvector_max_k=50)
    assert _bounded_k(5, settings) == 5
    assert _bounded_k(9999, settings) == 50
    assert _bounded_k(0, settings) == 1


def test_identifier_guard_rejects_injection():
    assert _safe_identifier("public.docs") == "public.docs"
    for bad in ["docs; DROP TABLE x", "docs--", "1docs", "do cs"]:
        with pytest.raises(ToolError):
            _safe_identifier(bad)
