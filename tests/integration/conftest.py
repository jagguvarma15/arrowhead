"""Fixtures for the Postgres and pgvector integration tests.

These run only when ARROWHEAD_POSTGRES_TEST_URL names a reachable Postgres with
the pgvector extension available (CI provides one). Without it every test in
this directory is skipped, so the plain unit suite stays database-free.
"""

import os

import pytest


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
