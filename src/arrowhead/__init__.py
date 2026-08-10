"""Arrowhead: the hardened, importable data plane for AI agents.

The public names are resolved on first access so that importing the package
stays light and does not pull in the server, its middleware, or any connector
driver until something is actually used.
"""

from importlib.metadata import PackageNotFoundError, version as _installed_version
from typing import TYPE_CHECKING

try:
    __version__ = _installed_version("arrowhead")
except PackageNotFoundError:  # pragma: no cover - running from a tree with no metadata
    __version__ = "0.0.0"

__all__ = [
    "Arrowhead",
    "Settings",
    "__version__",
    "as_principal",
    "use_settings",
]

if TYPE_CHECKING:
    from arrowhead.app import Arrowhead
    from arrowhead.auth.principal import as_principal
    from arrowhead.config import Settings, use_settings


def __getattr__(name: str):
    if name == "Arrowhead":
        from arrowhead.app import Arrowhead

        return Arrowhead
    if name in ("Settings", "use_settings"):
        from arrowhead import config

        return getattr(config, name)
    if name == "as_principal":
        from arrowhead.auth.principal import as_principal

        return as_principal
    raise AttributeError(f"module 'arrowhead' has no attribute {name!r}")
