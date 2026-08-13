-- Schema for the pgvector retrieval store that doc_index writes and
-- vector_query, hybrid_query read. Apply it once per database before
-- indexing. The column names match the ARROWHEAD_PGVECTOR_*_COLUMN settings,
-- and the vector width must equal ARROWHEAD_EMBEDDING_DIMENSIONS (1536 here
-- is a placeholder).
--
-- The read tools connect with a read-only role via ARROWHEAD_SQL_DSN. Give
-- doc_index a separate write role via ARROWHEAD_VECTOR_WRITE_DSN, limited to
-- INSERT, UPDATE, DELETE, and SELECT on this one table, so the read path
-- stays least privilege.
--
-- content_hash lets a re-index skip unchanged chunks without re-embedding
-- them; content_tsv powers the full-text branch of hybrid_query. The text
-- search configuration in the generated column should match
-- ARROWHEAD_FTS_LANGUAGE.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS doc_chunks (
    id           text PRIMARY KEY,
    tenant       text NOT NULL,
    source       text NOT NULL,
    chunk_index  integer NOT NULL,
    content      text NOT NULL,
    embedding    vector(1536) NOT NULL,
    content_hash text NOT NULL DEFAULT '',
    content_tsv  tsvector GENERATED ALWAYS AS
                     (to_tsvector('english', content)) STORED,
    UNIQUE (tenant, source, chunk_index)
);

CREATE INDEX IF NOT EXISTS doc_chunks_ann
    ON doc_chunks USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS doc_chunks_owner
    ON doc_chunks (tenant, source);
CREATE INDEX IF NOT EXISTS doc_chunks_fts
    ON doc_chunks USING gin (content_tsv);

-- Migration for a table created before content_hash and content_tsv existed.
-- Run these once; the first doc_index after the migration rewrites each
-- chunk's hash as it re-embeds. Until then every chunk hashes as changed,
-- which is correct and merely forgoes reuse on the first pass. Alternatively
-- set ARROWHEAD_INDEX_REUSE_UNCHANGED=false to keep the wholesale-replace
-- behavior on an unmigrated table.
--
-- ALTER TABLE doc_chunks
--     ADD COLUMN content_hash text NOT NULL DEFAULT '';
-- ALTER TABLE doc_chunks
--     ADD COLUMN content_tsv tsvector GENERATED ALWAYS AS
--         (to_tsvector('english', content)) STORED;
-- CREATE INDEX doc_chunks_fts ON doc_chunks USING gin (content_tsv);
