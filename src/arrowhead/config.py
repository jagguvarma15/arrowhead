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


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings, loading them on first use."""
    return Settings()
