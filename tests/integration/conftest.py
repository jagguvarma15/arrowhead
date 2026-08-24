"""Fixtures for the Postgres and pgvector integration tests.

These run only when ARROWHEAD_POSTGRES_TEST_URL names a reachable Postgres with
the pgvector extension available (CI provides one). Without it every test in
this directory is skipped, so the plain unit suite stays database-free.
"""

import os

import pytest

from arrowhead.authz.enforce import get_authorizer
from arrowhead.config import get_settings


@pytest.fixture
def configure_vector_stack(monkeypatch):
    """Point the whole vector stack at the test database in one step.

    Sets both DSNs, the collection allowlist, the deterministic embedder,
    and the docs root, then clears the settings and authorizer caches.
    """

    def configure(docs_root, url):
        monkeypatch.setenv("ARROWHEAD_SQL_DSN", url)
        monkeypatch.setenv("ARROWHEAD_VECTOR_WRITE_DSN", url)
        monkeypatch.setenv("ARROWHEAD_PGVECTOR_COLLECTIONS", "doc_chunks")
        monkeypatch.setenv("ARROWHEAD_EMBEDDING_PROVIDER", "deterministic")
        monkeypatch.setenv("ARROWHEAD_EMBEDDING_DIMENSIONS", "8")
        monkeypatch.setenv("ARROWHEAD_DOCS_ROOT", str(docs_root))
        get_settings.cache_clear()
        get_authorizer.cache_clear()

    return configure


@pytest.fixture
def postgres_url():
    url = os.environ.get("ARROWHEAD_POSTGRES_TEST_URL")
    if not url:
        pytest.skip("ARROWHEAD_POSTGRES_TEST_URL not set")
    return url


@pytest.fixture
def run_ddl(postgres_url):
    """Return an async callable that runs DDL/DML against the test database."""

    async def _run(statements: list[str]) -> None:
        from sqlalchemy import text
        from sqlalchemy.ext.asyncio import create_async_engine

        engine = create_async_engine(postgres_url)
        try:
            async with engine.begin() as conn:
                for statement in statements:
                    await conn.execute(text(statement))
        finally:
            await engine.dispose()

    return _run
