"""Runtime configuration loaded from environment variables.

All settings use the ARROWHEAD_ prefix, so the jail root is set with
ARROWHEAD_JAIL_ROOT, the fetch timeout with ARROWHEAD_FETCH_TIMEOUT_SECONDS,
and so on. A local .env file is honored for development.
"""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ARROWHEAD_",
        env_file=".env",
        extra="ignore",
    )

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
