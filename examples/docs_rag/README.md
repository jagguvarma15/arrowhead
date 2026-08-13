# Docs RAG example

Two ways to see the retrieval loop: chunk documents, embed them, and answer a
query with cited chunks.

## Offline (no server, no database)

```bash
uv run python examples/docs_rag/run_offline.py
```

This chunks the `corpus/` documents, embeds them with the deterministic
provider, and prints the chunks most similar to a query, each with its source
and chunk index. The deterministic embedder is not semantic, so treat the
ranking as illustrative of the shape, not the quality.

## Real (Postgres and a real embedder)

1. Apply the schema once (the vector width must match
   `ARROWHEAD_EMBEDDING_DIMENSIONS`):

   ```bash
   psql "$WRITE_DSN" -f deploy/pgvector_schema.sql
   ```

2. Configure a real embedding provider and the read and write credentials:

   ```bash
   export ARROWHEAD_AUTH_ENABLED=true
   export ARROWHEAD_SQL_DSN=postgresql+asyncpg://reader@host/db
   export ARROWHEAD_VECTOR_WRITE_DSN=postgresql+asyncpg://writer@host/db
   export ARROWHEAD_PGVECTOR_COLLECTIONS=doc_chunks
   export ARROWHEAD_EMBEDDING_PROVIDER=http
   export ARROWHEAD_EMBEDDING_ENDPOINT=https://api.example/v1/embeddings
   export ARROWHEAD_EMBEDDING_API_KEY=...
   export ARROWHEAD_EMBEDDING_DIMENSIONS=1536
   export ARROWHEAD_EGRESS_ALLOWED_HOSTS=api.example
   ```

3. Grant the caller the `ingest` action, which the default policy denies, via
   `ARROWHEAD_AUTHZ_POLICY`:

   ```json
   {"grants": [{"subject": "*", "actions": ["ingest", "query"],
                "kinds": ["table"], "prefix": "doc_chunks"}]}
   ```

4. Call `doc_index(collection="doc_chunks")` to index the corpus, then
   `vector_query(collection="doc_chunks", query="how long do refunds take?")`.
   Each result carries the source document and chunk index it came from.

The write role should be limited to `INSERT`, `DELETE`, and `SELECT` on the
chunks table; the read tools use the read-only `ARROWHEAD_SQL_DSN`.
