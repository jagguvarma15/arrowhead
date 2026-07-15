"""File reader jailed to one configured directory.

The requested path must be relative and free of parent-directory
components, and the fully resolved path, after following any symlinks,
must still sit inside the jail root. A symlink inside the jail that points
outside it fails the containment check and is refused. Error messages
never echo the requested path, so a probing caller learns nothing about
the filesystem layout from them.
"""

from pathlib import Path

import anyio
from fastmcp.exceptions import ToolError

from arrowhead.config import get_settings
from arrowhead.security.input_validation import (
    ValidationError,
    validate_relative_path,
)


class PathJailError(Exception):
    """The path cannot be read from the jail."""


async def read_file(path: str) -> str:
    """Read a text file from the server's sandbox directory by relative
    path. Example: read_file(path="notes/readme.txt").
    """
    try:
        return await read_jailed_file(path)
    except (ValidationError, PathJailError) as exc:
        raise ToolError(str(exc)) from exc


async def read_jailed_file(path: str) -> str:
    settings = get_settings()
    validate_relative_path(path)
    return await anyio.to_thread.run_sync(
        _read_inside_jail,
        settings.jail_root,
        path,
        settings.read_file_max_bytes,
    )


def _read_inside_jail(jail_root: Path, path: str, max_bytes: int) -> str:
    root = jail_root.resolve()
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root):
        raise PathJailError("path resolves outside the allowed directory")
    if not resolved.is_file():
        raise PathJailError("file not found in the allowed directory")
    with resolved.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise PathJailError(f"file exceeds {max_bytes} bytes")
    return data.decode("utf-8", errors="replace")
