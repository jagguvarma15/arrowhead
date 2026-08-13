"""Runtime configuration loaded from environment variables.

All settings use the ARROWHEAD_ prefix, so the jail root is set with
ARROWHEAD_JAIL_ROOT, the fetch timeout with ARROWHEAD_FETCH_TIMEOUT_SECONDS,
and so on. A local .env file is honored for development.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


@lru_cache(maxsize=128)
def _csv_frozenset(raw: str, lower: bool) -> frozenset[str]:
    """A comma-separated setting parsed into a set, memoized by its raw value.

    Building the set is cheap but happens on hot paths (every document call
    reads the allowed-extension set), so caching by the raw string avoids
    re-splitting it on each call. Keying on the value keeps this correct under
    a use_settings override: a different settings block with the same string
    reuses the set, a different string computes its own.
    """
    parts = (item.strip() for item in raw.split(","))
    if lower:
        return frozenset(item.lower() for item in parts if item)
    return frozenset(item for item in parts if item)


@lru_cache(maxsize=128)
def _csv_int_frozenset(raw: str) -> frozenset[int]:
    """A comma-separated integer setting parsed into a set, memoized by value."""
    return frozenset(int(item.strip()) for item in raw.split(",") if item.strip())


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ARROWHEAD_",
        env_file=".env",
        extra="ignore",
    )

    # transport: stdio for local development, http for deployment.
    # Stateless HTTP keeps no per-session server state, so any replica
    # can serve any request.
    transport: Literal["stdio", "http"] = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000
    stateless_http: bool = True

    # Host/Origin allowlists defend against DNS rebinding of the local
    # endpoint. Comma-separated; set these to the public hostname when
    # deploying behind a proxy. Empty leaves the check off, matching the
    # documented platform-proxy posture.
    allowed_hosts: str = ""
    allowed_origins: str = ""

    # Which tool families this deployment exposes. Every connected model
    # pays context for each listed tool, so a deployment serving one job
    # should expose one profile, not everything: core is the three
    # utility tools, docs adds the document suite with its data and task
    # tools, coding is the code-focused surface, and full (the default)
    # is every family the catalog declares.
    profile: Literal["core", "docs", "coding", "full"] = "full"

    def allowed_hosts_list(self) -> list[str] | None:
        hosts = [h.strip() for h in self.allowed_hosts.split(",") if h.strip()]
        return hosts or None

    def allowed_origins_list(self) -> list[str] | None:
        origins = [o.strip() for o in self.allowed_origins.split(",") if o.strip()]
        return origins or None

    # auth: OAuth 2.1 resource server. Off only for local stdio use.
    # TLS is terminated by the hosting platform or reverse proxy.
    auth_enabled: bool = False
    # Serving HTTP with auth disabled exposes every tool with no scope or
    # per-resource check over the network. Refuse that combination at startup
    # unless a deployment opts in explicitly (for a trusted-network test).
    allow_insecure_http: bool = False
    # "jwt" verifies against any issuer's key material (bring-your-own-IdP);
    # "workos" wires WorkOS AuthKit, which is purpose-built for MCP.
    oauth_provider: Literal["jwt", "workos"] = "jwt"
    oauth_issuer: str | None = None
    oauth_audience: str | None = None
    oauth_jwks_uri: str | None = None
    oauth_public_key: str | None = None
    oauth_authkit_domain: str | None = None
    server_public_url: str | None = None

    # per-resource authorization policy for the document tools, as a JSON
    # document: {"grants": [{"subject": "*", "actions": ["read"],
    # "prefix": ""}]}. Empty uses a safe default (any caller may search,
    # read, and scan the corpus, but write only under its own subject
    # namespace). Ignored when auth is disabled.
    authz_policy: str = ""

    # read_file: the only directory the tool may read from
    jail_root: Path = Path("sandbox")
    read_file_max_bytes: int = 1_000_000

    # documents corpus: the jailed root the doc_* tools operate on. It is
    # write-capable, so it is kept separate from the read-only read_file
    # sandbox. Only these extensions are treated as documents.
    docs_root: Path = Path("documents")
    doc_max_bytes: int = 1_000_000
    doc_allowed_extensions: str = ".json,.md,.txt"

    # doc_write limits: per-document size and a total-corpus quota.
    doc_write_max_bytes: int = 1_000_000
    doc_write_quota_bytes: int = 50_000_000
    # Overwriting an existing document requests human confirmation via
    # elicitation. When the client cannot elicit, the caller's explicit
    # overwrite flag stands in as the opt-in.
    require_write_confirmation: bool = True

    # content hardening caps applied to returned document content
    content_max_bytes: int = 1_000_000
    json_max_depth: int = 64
    json_max_elements: int = 100_000

    # doc_search. Regex is off by default because it is a denial-of-service
    # surface; when enabled it runs through a ReDoS-resistant engine with a
    # hard timeout. Results and aggregate snippet bytes are bounded.
    search_query_max_length: int = 200
    search_regex_enabled: bool = False
    search_regex_timeout_ms: int = 250
    search_max_files: int = 2000
    search_max_results: int = 50
    search_max_total_bytes: int = 200_000
    search_snippet_max_chars: int = 200

    # doc_scan: secrets and PII detection. Findings report a type and a
    # redacted placeholder, never the raw value. Traversal is bounded and
    # large files are skipped.
    scan_max_files: int = 2000
    scan_per_file_max_bytes: int = 1_000_000
    scan_timeout_seconds: float = 10.0
    scan_max_findings: int = 200

    # safe_fetch
    fetch_timeout_seconds: float = 10.0
    fetch_max_response_bytes: int = 1_000_000
    fetch_max_redirects: int = 3

    # Outbound destination allowlist shared by the URL-fetching tools. When set
    # (comma-separated hostnames), only these hosts may be reached and every
    # other host is refused on every redirect hop, closing the gap where a
    # genuinely public but attacker-chosen host is otherwise fetchable. Empty
    # allows any public host; the SSRF guard still blocks private ranges.
    egress_allowed_hosts: str = ""
    # Extra outbound ports permitted beyond 80 and 443 (comma-separated). Empty
    # allows only the two web ports, so a public host cannot be used to reach an
    # internal service listening on a non-web port.
    egress_allowed_ports: str = ""

    # calculate
    expression_max_length: int = 200

    # SQL connector (sql extra). The read tool runs a single vetted read-only
    # statement against this database. The DSN is a SQLAlchemy async URL, e.g.
    # sqlite+aiosqlite:///data/app.db or postgresql+asyncpg://user@host/db.
    # Empty leaves the connector unconfigured and the tool refuses to run.
    sql_dsn: str = ""
    # The SQL dialect the guard parses against; empty lets it infer. Set it to
    # the database's dialect (e.g. postgres, sqlite) for the most accurate
    # parse of dialect-specific syntax.
    sql_dialect: str = ""
    sql_query_max_length: int = 2000
    # Result budget that keeps a wide or large result from overrunning the
    # model's context window.
    sql_max_rows: int = 1000
    sql_max_bytes: int = 1_000_000
    sql_max_columns: int = 100
    # Best-effort per-call time budget; a server-side statement timeout is set
    # in addition where the database supports it.
    sql_timeout_seconds: float = 10.0

    # pgvector collection search (postgres extra), over the sql_dsn database.
    # Only these collections (comma-separated table names) may be searched; the
    # tenant filter is the authenticated caller, not an argument. The column
    # names default to a common convention and are overridable per deployment.
    pgvector_collections: str = ""
    pgvector_tenant_column: str = "tenant"
    pgvector_id_column: str = "id"
    pgvector_content_column: str = "content"
    pgvector_embedding_column: str = "embedding"
    # Provenance columns written by doc_index and returned by vector_query so a
    # retrieved chunk carries its source document and position as a citation.
    pgvector_source_column: str = "source"
    pgvector_chunk_index_column: str = "chunk_index"
    pgvector_content_hash_column: str = "content_hash"
    pgvector_tsvector_column: str = "content_tsv"
    pgvector_max_k: int = 50
    pgvector_max_dimensions: int = 2000

    # Embeddings. doc_index and vector_query turn text into vectors through a
    # pluggable provider. "deterministic" is a stdlib, offline, non-semantic
    # provider for tests and local development; "http" posts to an
    # OpenAI-compatible endpoint through the SSRF guard and the egress
    # allowlist, with the key supplied out of band.
    embedding_provider: Literal["deterministic", "http"] = "deterministic"
    embedding_dimensions: int = 1536
    embedding_endpoint: str = ""
    embedding_model: str = ""
    embedding_api_key: str = ""
    embedding_batch_size: int = 64
    embedding_timeout_seconds: float = 30.0
    embedding_max_texts: int = 10000

    # Vector ingestion (doc_index). Writing chunks needs a write-capable
    # credential, kept separate from the read-only sql_dsn so the read tools
    # keep least privilege; ingestion refuses to run until it is set. The caps
    # bound how much one call may index.
    vector_write_dsn: str = ""
    vector_index_max_files: int = 500
    vector_index_max_chunks: int = 5000
    vector_index_chunk_max_chars: int = 1500
    vector_index_chunk_overlap: int = 200
    vector_index_timeout_seconds: float = 30.0
    # Code files chunk along their structure (a Python file splits at its
    # top-level definitions) with a wider window than prose, so a function
    # is less likely to be cut mid-body.
    code_chunk_max_chars: int = 2000
    # A re-index skips chunks whose content hash is unchanged, so only
    # edited chunks are re-embedded and rewritten. Requires the
    # content_hash column from the schema file; set false to restore the
    # full delete-and-insert on a schema without it.
    index_reuse_unchanged: bool = True

    # Repo intelligence. The code tools read a jailed repository tree,
    # separate from the document corpus: read-only by construction, with
    # version-control and dependency directories pruned from every walk,
    # binary files refused by content sniff, and per-file and per-walk
    # caps. Extensions are the text and source formats worth serving.
    repo_root: Path = Path("repo")
    repo_max_file_bytes: int = 500_000
    repo_allowed_extensions: str = (
        ".c,.cpp,.cs,.go,.h,.hpp,.java,.js,.json,.jsx,.kt,.md,.php,.py,"
        ".pyi,.rb,.rs,.scala,.sh,.sql,.swift,.toml,.ts,.tsx,.txt,.yaml,.yml"
    )
    repo_excluded_dirs: str = (
        ".git,.hg,.svn,.venv,node_modules,__pycache__,dist,build,target"
    )
    repo_search_max_files: int = 5000
    symbol_map_max_files: int = 500
    symbol_map_max_symbols: int = 5000
    dependency_graph_max_files: int = 500

    def repo_allowed_extension_set(self) -> frozenset[str]:
        return _csv_frozenset(self.repo_allowed_extensions, True)

    def repo_excluded_dir_set(self) -> frozenset[str]:
        return _csv_frozenset(self.repo_excluded_dirs, False)

    # Hybrid retrieval (hybrid_query) fuses vector similarity with
    # Postgres full-text rank via reciprocal rank fusion. The candidate
    # multiplier sizes each branch's pool as a multiple of k; the text
    # search configuration must name an installed Postgres regconfig and
    # is always bound as a parameter, never interpolated.
    hybrid_rrf_k: int = 60
    hybrid_candidate_multiplier: int = 4
    fts_language: str = "english"

    # abuse controls. Ceilings are calls per caller per minute; network-
    # bound safe_fetch gets a low ceiling, cheap calculate a high one.
    # With ARROWHEAD_REDIS_URL set, buckets live in Redis and the limits
    # hold across replicas; otherwise they apply per process.
    rate_limit_enabled: bool = True
    safe_fetch_per_minute: int = 30
    calculate_per_minute: int = 120
    read_file_per_minute: int = 60
    doc_search_per_minute: int = 60
    doc_read_per_minute: int = 60
    hybrid_query_per_minute: int = 30
    code_search_per_minute: int = 60
    code_read_per_minute: int = 60
    symbol_map_per_minute: int = 20
    dependency_graph_per_minute: int = 10
    doc_retrieve_per_minute: int = 30
    doc_scan_per_minute: int = 20
    doc_write_per_minute: int = 30
    sql_query_per_minute: int = 60
    vector_search_per_minute: int = 30
    vector_query_per_minute: int = 30
    vector_index_per_minute: int = 6
    # Handle-based async tasks: starting one is expensive (a full background
    # scan), polling is cheap, cancelling is in between.
    task_start_per_minute: int = 10
    task_get_per_minute: int = 120
    task_update_per_minute: int = 30
    # Ceilings for the non-tool components. Reading a resource, getting a
    # prompt, and completing an argument are each rate-limited per caller just
    # as a tool call is, so no request path is left unmetered.
    resource_read_per_minute: int = 60
    prompt_get_per_minute: int = 60
    completion_per_minute: int = 60
    # ceiling for any tool without an explicit limit above, so a new tool
    # is never silently unlimited
    default_tool_per_minute: int = 60
    redis_url: str | None = None

    # kill switch: comma-separated tool names to take out of service
    # without a code change, e.g. ARROWHEAD_DISABLED_TOOLS=safe_fetch
    disabled_tools: str = ""

    # how long clients may cache a list result (tools, resources, resource
    # templates, prompts); a list only changes on deploy or when the kill
    # switch flips, both of which restart the process anyway
    tool_list_ttl_ms: int = 3_600_000
    # how long clients may cache a single resource read; a document changes
    # only on a write, so this is shorter than the list TTL
    resource_read_ttl_ms: int = 60_000

    # OpenTelemetry export. Spans and metrics are no-ops unless an OTLP
    # endpoint is set, so telemetry costs nothing until it is configured.
    # Headers are comma-separated key=value pairs (e.g. for a collector API
    # key). Audit logs are always emitted as JSON to stdout regardless.
    otel_exporter_otlp_endpoint: str | None = None
    otel_exporter_otlp_headers: str | None = None
    otel_service_name: str = "arrowhead"

    def rate_limits_per_minute(self) -> dict[str, int]:
        """Per-tool ceilings, one entry per catalog tool.

        The catalog names which setting caps each tool, and the value is read
        from that setting so the limit stays configurable per deployment. A
        tool absent here falls back to default_tool_per_minute in the
        rate-limit middleware, so no tool is ever accidentally left unlimited.
        """
        from arrowhead.tools.catalog import TOOL_SPECS

        return {
            spec.name: getattr(self, spec.rate_limit_attr) for spec in TOOL_SPECS
        }

    def disabled_tool_set(self) -> set[str]:
        return {
            name.strip()
            for name in self.disabled_tools.split(",")
            if name.strip()
        }

    def doc_allowed_extension_set(self) -> frozenset[str]:
        return _csv_frozenset(self.doc_allowed_extensions, True)

    def egress_allowed_hosts_set(self) -> frozenset[str]:
        """Lowercased set of hosts the fetch tools may reach; empty allows any
        public host."""
        return _csv_frozenset(self.egress_allowed_hosts, True)

    def pgvector_collection_set(self) -> frozenset[str]:
        """The vector collections a caller may search; empty allows none."""
        return _csv_frozenset(self.pgvector_collections, False)

    @field_validator("egress_allowed_ports")
    @classmethod
    def _validate_egress_ports(cls, value: str) -> str:
        """Reject a non-numeric or out-of-range extra port at startup rather
        than raising on the first fetch."""
        for entry in value.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                port = int(entry)
            except ValueError:
                raise ValueError(
                    f"egress_allowed_ports has a non-numeric port: {entry!r}"
                ) from None
            if not 1 <= port <= 65535:
                raise ValueError(
                    f"egress_allowed_ports has an out-of-range port: {port}"
                )
        return value

    @field_validator("fts_language")
    @classmethod
    def _validate_fts_language(cls, value: str) -> str:
        """Constrain the text-search configuration to a plain lowercase name.

        The value is always bound as a query parameter, so this is defense
        in depth against a config value shaped like SQL rather than a
        Postgres regconfig name.
        """
        cleaned = value.strip()
        if not cleaned or not all(
            ch.isalpha() and ch.islower() or ch == "_" for ch in cleaned
        ):
            raise ValueError(
                "fts_language must be a lowercase Postgres text search "
                f"configuration name (got {value!r})"
            )
        return cleaned

    @field_validator("sql_dialect")
    @classmethod
    def _validate_sql_dialect(cls, value: str) -> str:
        """Canonicalize the SQL dialect and reject an unknown one at startup.

        The natural value "postgresql" is not a sqlglot dialect and would
        otherwise raise at first query and silently disable the read-only
        session guards, which key on the exact string "postgres".
        """
        if not value.strip():
            return ""
        aliases = {
            "postgresql": "postgres",
            "postgres": "postgres",
            "sqlite": "sqlite",
            "mysql": "mysql",
            "mariadb": "mysql",
        }
        canonical = aliases.get(value.strip().lower())
        if canonical is None:
            raise ValueError(
                "sql_dialect must be one of postgres, sqlite, mysql "
                f"(got {value!r})"
            )
        return canonical

    def egress_allowed_ports_set(self) -> frozenset[int]:
        """Extra ports the fetch tools may reach beyond 80 and 443; empty
        allows only the two web ports."""
        return _csv_int_frozenset(self.egress_allowed_ports)


# An embedding host can supply its own settings for a block rather than
# relying on process-wide environment state. When no override is active, the
# settings loaded once from the environment are used.
_settings_override: ContextVar[Settings | None] = ContextVar(
    "arrowhead_settings", default=None
)


@lru_cache
def _env_settings() -> Settings:
    return Settings()


def get_settings() -> Settings:
    """Return the settings in effect for the current call.

    Inside a use_settings block the injected settings are returned; otherwise
    the process-wide settings loaded from the environment are returned.
    """
    override = _settings_override.get()
    return override if override is not None else _env_settings()


# Keep the clear-the-cache affordance the environment-driven path relies on.
get_settings.cache_clear = _env_settings.cache_clear


def current_settings_override() -> Settings | None:
    """Return the injected settings if a use_settings block is active."""
    return _settings_override.get()


@contextmanager
def use_settings(settings: Settings) -> Iterator[Settings]:
    """Use the given settings for the duration of the block.

    This lets the server run inside a host process that has its own
    configuration, without depending on process-wide environment variables.
    """
    reset = _settings_override.set(settings)
    try:
        yield settings
    finally:
        _settings_override.reset(reset)
