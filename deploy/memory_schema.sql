-- Schema for the Postgres memory backend behind the memory and kv tools.
-- Apply it once per database before setting ARROWHEAD_MEMORY_DSN. The DSN
-- needs INSERT, UPDATE, DELETE, and SELECT on these two tables only, so
-- give it its own role rather than reusing the read-only ARROWHEAD_SQL_DSN
-- role.
--
-- The embedding column is nullable: rows are embedded only when the real
-- embedding provider is configured, and keyword (full-text) recall covers
-- the rest. The vector width must equal ARROWHEAD_EMBEDDING_DIMENSIONS
-- (1536 here is a placeholder). The unique constraint on the content hash
-- is what makes memory_store's dedup race-free.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS arrowhead_memory (
    owner        text NOT NULL,
    namespace    text NOT NULL,
    id           text NOT NULL,
    content      text NOT NULL,
    metadata     jsonb NOT NULL DEFAULT '{}',
    content_hash text NOT NULL,
    embedding    vector(1536),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (owner, namespace, id),
    UNIQUE (owner, namespace, content_hash)
);

CREATE INDEX IF NOT EXISTS arrowhead_memory_ann
    ON arrowhead_memory USING hnsw (embedding vector_cosine_ops);

CREATE TABLE IF NOT EXISTS arrowhead_memory_kv (
    owner      text NOT NULL,
    key        text NOT NULL,
    value      text NOT NULL,
    expires_at timestamptz,
    PRIMARY KEY (owner, key)
);
