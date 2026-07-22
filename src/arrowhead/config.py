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

from pydantic_settings import BaseSettings, SettingsConfigDict


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
    # deploying behind a proxy. Empty leaves FastMCP's localhost defaults.
    allowed_hosts: str = ""
    allowed_origins: str = ""

    def allowed_hosts_list(self) -> list[str] | None:
        hosts = [h.strip() for h in self.allowed_hosts.split(",") if h.strip()]
        return hosts or None

    def allowed_origins_list(self) -> list[str] | None:
        origins = [o.strip() for o in self.allowed_origins.split(",") if o.strip()]
        return origins or None

    # auth: OAuth 2.1 resource server. Off only for local stdio use.
    # TLS is terminated by the hosting platform or reverse proxy.
    auth_enabled: bool = False
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

    # calculate
    expression_max_length: int = 200

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
    doc_retrieve_per_minute: int = 30
    doc_scan_per_minute: int = 20
    doc_write_per_minute: int = 30
    # ceiling for any tool without an explicit limit above, so a new tool
    # is never silently unlimited
    default_tool_per_minute: int = 60
    redis_url: str | None = None

    # kill switch: comma-separated tool names to take out of service
    # without a code change, e.g. ARROWHEAD_DISABLED_TOOLS=safe_fetch
    disabled_tools: str = ""

    # how long clients may cache the tool list; it only changes on
    # deploy or when the kill switch flips, both of which restart the
    # process anyway
    tool_list_ttl_ms: int = 3_600_000

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
        return frozenset(
            ext.strip().lower()
            for ext in self.doc_allowed_extensions.split(",")
            if ext.strip()
        )


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
