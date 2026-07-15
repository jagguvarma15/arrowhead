"""Runtime configuration loaded from environment variables.

All settings use the ARROWHEAD_ prefix, so the jail root is set with
ARROWHEAD_JAIL_ROOT, the fetch timeout with ARROWHEAD_FETCH_TIMEOUT_SECONDS,
and so on. A local .env file is honored for development.
"""

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

    # auth: OAuth 2.1 resource server. Off only for local stdio use.
    # TLS is terminated by the hosting platform or reverse proxy.
    auth_enabled: bool = False
    oauth_issuer: str | None = None
    oauth_audience: str | None = None
    oauth_jwks_uri: str | None = None
    oauth_public_key: str | None = None
    server_public_url: str | None = None

    # read_file: the only directory the tool may read from
    jail_root: Path = Path("sandbox")
    read_file_max_bytes: int = 1_000_000

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
    redis_url: str | None = None

    # kill switch: comma-separated tool names to take out of service
    # without a code change, e.g. ARROWHEAD_DISABLED_TOOLS=safe_fetch
    disabled_tools: str = ""

    # how long clients may cache the tool list; it only changes on
    # deploy or when the kill switch flips, both of which restart the
    # process anyway
    tool_list_ttl_ms: int = 3_600_000

    def rate_limits_per_minute(self) -> dict[str, int]:
        return {
            "safe_fetch": self.safe_fetch_per_minute,
            "calculate": self.calculate_per_minute,
            "read_file": self.read_file_per_minute,
        }

    def disabled_tool_set(self) -> set[str]:
        return {
            name.strip()
            for name in self.disabled_tools.split(",")
            if name.strip()
        }


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings, loading them on first use."""
    return Settings()
