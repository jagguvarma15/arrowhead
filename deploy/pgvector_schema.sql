-- Schema for the pgvector retrieval store that doc_index writes and
-- vector_query reads. Apply it once per database before indexing. The column
-- names match the ARROWHEAD_PGVECTOR_*_COLUMN settings, and the vector width
-- must equal ARROWHEAD_EMBEDDING_DIMENSIONS (1536 here is a placeholder).
--
-- The read tools connect with a read-only role via ARROWHEAD_SQL_DSN. Give
-- doc_index a separate write role via ARROWHEAD_VECTOR_WRITE_DSN, limited to
-- INSERT, DELETE, and SELECT on this one table, so the read path stays least
-- privilege.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS doc_chunks (
    id          text PRIMARY KEY,
    tenant      text NOT NULL,
    source      text NOT NULL,
    chunk_index integer NOT NULL,
    content     text NOT NULL,
    embedding   vector(1536) NOT NULL,
    UNIQUE (tenant, source, chunk_index)
);

CREATE INDEX IF NOT EXISTS doc_chunks_ann
    ON doc_chunks USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS doc_chunks_owner
    ON doc_chunks (tenant, source);
