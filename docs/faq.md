# FAQ

## A tool I expect is not in the tool list

Four gates decide what registers, in order: the profile (`ARROWHEAD_PROFILE` — a
tool outside the active profile is never registered), the family gates (`exec` needs
`ARROWHEAD_EXEC_ENABLED=true`, `notify` needs a non-empty
`ARROWHEAD_NOTIFY_ALLOWLIST`), and the kill switch (`ARROWHEAD_DISABLED_TOOLS` takes
named tools out of service without a redeploy). `arrowhead list-tools` prints
exactly what your configuration serves.

## I granted the scope but calls are still denied

A scope is necessary but not sufficient. Every call also passes a server-side
per-resource check that is default-deny: the small JSON grant list in
`ARROWHEAD_AUTHZ_POLICY` (or the safe default policy when it is empty) must allow
the action on that resource. Two actions are deliberately absent from the default
grants — `execute` and `notify` — so those families need an explicit grant on top of
their family gates. The default memory grant is restricted to memory resources, so
it can never widen document access.

## Calls fail with a rate-limit error

Every tool has a per-caller per-minute ceiling, configurable per tool (the
`*_PER_MINUTE` variables). Without Redis the buckets are per process; set
`ARROWHEAD_REDIS_URL` to share them across replicas so a caller cannot multiply its
budget by the replica count.

## memory_search labels its recall "keyword" when I expected semantic

The label is honest by design. Semantic recall needs both `ARROWHEAD_MEMORY_DSN`
pointing at Postgres (with `deploy/memory_schema.sql` applied) and
`ARROWHEAD_EMBEDDING_PROVIDER=http` with a real endpoint. The file backend, and the
Postgres backend under the deterministic embedder, search by keyword and say so
rather than fake a similarity ranking.

## My scheduled timers vanished after a restart

Timers share the in-process task registry and do not survive a restart — the
`task_schedule` description states this. Durable schedules need external state and
are out of scope for the in-process registry; treat timers as best-effort reminders
within one server lifetime.

## The server refuses to start over HTTP

That is the safe default, not a bug. HTTP with `ARROWHEAD_AUTH_ENABLED=false`
exposes every tool with no check, so startup refuses unless
`ARROWHEAD_ALLOW_INSECURE_HTTP=true` opts in for a trusted-network test. With auth
enabled, the OAuth settings must be complete (issuer, audience, the server's public
URL, and a JWKS URI or public key). A malformed `ARROWHEAD_NOTIFY_ALLOWLIST` entry
also fails startup by design, so a typo cannot silently widen egress.

## sql_query or vector_search says the connector is not configured

Empty DSNs leave a connector unconfigured and its tool refuses to run. Reads use
`ARROWHEAD_SQL_DSN` (a read-only role is the recommended credential); vector
ingestion needs the separate write-capable `ARROWHEAD_VECTOR_WRITE_DSN`; vector
search also needs `ARROWHEAD_PGVECTOR_COLLECTIONS` to name the searchable tables.
The connectors need the packaging extras: `uv sync --extra sql --extra postgres`.

## Why is the package not on PyPI

The `arrowhead` name on PyPI belongs to an unrelated project. Install from a
checkout or a git URL, or run the container image a release tag publishes to
`ghcr.io/jagguvarma15/arrowhead`.

## What is arrowhead://integrity for

It is a resource carrying a digest of the tool surface a client consented to. A
client pins it and can detect any later change — a renamed tool, an edited
description, a schema change — before trusting the surface again.
