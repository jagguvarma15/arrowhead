"""Jailed, read-only repository store.

The containment rule is the document store's, applied to a source tree:
every path joins the configured root and fully resolves (following
symlinks), and the result must stay inside the root, so parent traversal
and symlink escapes are refused regardless of what a caller validated
first. On top of containment the store is read-only by construction,
prunes version-control and dependency directories from every walk so
.git internals and vendored trees are unreachable, refuses binary files
by content sniff rather than extension trust, and caps how much of any
file may be read.
"""

import os
from dataclasses import dataclass
from pathlib import Path

from arrowhead.config import Settings

# How much of a file the binary sniff inspects. A NUL byte in this window
# marks the file binary; source code never legitimately contains one.
_SNIFF_BYTES = 8192


class RepoStoreError(Exception):
    """A repository operation could not be completed safely."""


class RepoFileNotFoundError(RepoStoreError):
    """No file exists at the requested path."""


class RepoFileTooLargeError(RepoStoreError):
    """The file exceeds the configured per-file byte cap."""


class BinaryFileError(RepoStoreError):
    """The file is binary and has no readable text form."""


@dataclass(frozen=True)
class RepoFileInfo:
    """Metadata about one file, identified by its repo-relative path."""

    path: str
    size: int
    extension: str


@dataclass(frozen=True)
class RepoListing:
    """A bounded listing and whether the cap cut it short."""

    items: list[RepoFileInfo]
    truncated: bool


class RepoStore:
    """Read-only source tree confined to a single root."""

    def __init__(
        self,
        root: Path,
        *,
        max_file_bytes: int,
        excluded_dirs: frozenset[str],
    ) -> None:
        self._root = root.resolve()
        self._max_file_bytes = max_file_bytes
        self._excluded = excluded_dirs

    def _resolve(self, relative_path: str) -> Path:
        """Resolve a repo-relative path and require it to stay inside."""
        resolved = (self._root / relative_path).resolve()
        if not resolved.is_relative_to(self._root):
            raise RepoStoreError("path resolves outside the repository")
        return resolved

    def _excluded_path(self, relative: str) -> bool:
        return any(part in self._excluded for part in Path(relative).parts)

    def list(
        self,
        *,
        extensions: frozenset[str] | None = None,
        max_files: int | None = None,
        path_prefix: str = "",
    ) -> RepoListing:
        """List files, bounded, prefix-filtered, pruned, symlink-safe.

        Excluded directories are pruned from the walk itself, so nothing
        under them is ever visited. Directory symlinks are not followed;
        a file symlink whose target escapes the repository is skipped.
        """
        if not self._root.is_dir():
            return RepoListing(items=[], truncated=False)
        results: list[RepoFileInfo] = []
        for dirpath, dirnames, filenames in os.walk(
            self._root, followlinks=False
        ):
            dirnames[:] = sorted(
                name for name in dirnames if name not in self._excluded
            )
            for name in sorted(filenames):
                full = Path(dirpath) / name
                if full.is_symlink() and not full.resolve().is_relative_to(
                    self._root
                ):
                    continue
                if not full.is_file():
                    continue
                extension = full.suffix.lower()
                if extensions is not None and extension not in extensions:
                    continue
                relative = str(full.relative_to(self._root))
                if self._excluded_path(relative):
                    continue
                if path_prefix and not relative.startswith(path_prefix):
                    continue
                results.append(
                    RepoFileInfo(
                        path=relative,
                        size=full.stat().st_size,
                        extension=extension,
                    )
                )
                if max_files is not None and len(results) >= max_files:
                    return RepoListing(items=results, truncated=True)
        return RepoListing(items=results, truncated=False)

    def read_text(self, relative_path: str) -> str:
        """Read a text file, jailed, size-capped, and binary-refusing."""
        resolved = self._resolve(relative_path)
        if self._excluded_path(relative_path):
            raise RepoFileNotFoundError("file not found in the repository")
        if not resolved.is_file():
            raise RepoFileNotFoundError("file not found in the repository")
        with resolved.open("rb") as handle:
            data = handle.read(self._max_file_bytes + 1)
        if len(data) > self._max_file_bytes:
            raise RepoFileTooLargeError(
                f"file exceeds {self._max_file_bytes} bytes"
            )
        if b"\x00" in data[:_SNIFF_BYTES]:
            raise BinaryFileError("file is binary")
        return data.decode("utf-8", errors="replace")


def build_repo_store(settings: Settings) -> RepoStore:
    """Construct the repository store from settings."""
    return RepoStore(
        settings.repo_root,
        max_file_bytes=settings.repo_max_file_bytes,
        excluded_dirs=settings.repo_excluded_dir_set(),
    )
