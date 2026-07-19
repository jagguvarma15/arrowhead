"""Jailed document store.

Generalizes the read_file containment logic into read, list, stat, and
atomic-write operations over the documents corpus. Every path is joined to
the configured root and fully resolved (following symlinks); the result
must stay inside the root, so parent traversal and symlink escapes are
refused. Callers are expected to have validated the path shape already
(relative, no parent components, allowed extension); the store enforces
containment regardless, because containment is the security boundary.
"""

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from arrowhead.config import Settings


class DocumentStoreError(Exception):
    """A document operation could not be completed safely."""


class DocumentNotFoundError(DocumentStoreError):
    """No document exists at the requested path."""


class DocumentExistsError(DocumentStoreError):
    """A document already exists and overwrite was not permitted."""


class DocumentTooLargeError(DocumentStoreError):
    """The document exceeds the configured per-document byte cap."""


class QuotaExceededError(DocumentStoreError):
    """Writing the document would exceed the corpus quota."""


@dataclass(frozen=True)
class DocumentInfo:
    """Metadata about one document, identified by its corpus-relative path."""

    path: str
    size: int
    extension: str


class DocumentStore:
    """Filesystem-backed document corpus confined to a single root."""

    def __init__(
        self,
        root: Path,
        *,
        read_max_bytes: int,
        write_max_bytes: int,
        quota_bytes: int,
    ) -> None:
        # Resolve the root once. It may not exist yet; resolve() still
        # returns an absolute, symlink-free path for containment checks.
        self._root = root.resolve()
        self._read_max_bytes = read_max_bytes
        self._write_max_bytes = write_max_bytes
        self._quota_bytes = quota_bytes

    def _resolve(self, relative_path: str) -> Path:
        """Resolve a corpus-relative path and require it to stay inside."""
        resolved = (self._root / relative_path).resolve()
        if not resolved.is_relative_to(self._root):
            raise DocumentStoreError("path resolves outside the corpus")
        return resolved

    def read_bytes(self, relative_path: str) -> bytes:
        """Read a document, enforcing the per-document byte cap."""
        resolved = self._resolve(relative_path)
        if not resolved.is_file():
            raise DocumentNotFoundError("document not found in the corpus")
        with resolved.open("rb") as handle:
            data = handle.read(self._read_max_bytes + 1)
        if len(data) > self._read_max_bytes:
            raise DocumentTooLargeError(
                f"document exceeds {self._read_max_bytes} bytes"
            )
        return data

    def stat(self, relative_path: str) -> DocumentInfo:
        """Return metadata for a document without reading its contents."""
        resolved = self._resolve(relative_path)
        if not resolved.is_file():
            raise DocumentNotFoundError("document not found in the corpus")
        return DocumentInfo(
            path=relative_path,
            size=resolved.stat().st_size,
            extension=resolved.suffix.lower(),
        )

    def list(
        self,
        *,
        extensions: frozenset[str] | None = None,
        max_files: int | None = None,
    ) -> list[DocumentInfo]:
        """List documents in the corpus, bounded and symlink-safe.

        Directory symlinks are not followed. A file symlink whose target
        escapes the corpus is skipped rather than listed.
        """
        if not self._root.is_dir():
            return []
        results: list[DocumentInfo] = []
        for dirpath, dirnames, filenames in os.walk(self._root, followlinks=False):
            dirnames.sort()
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
                results.append(
                    DocumentInfo(
                        path=str(full.relative_to(self._root)),
                        size=full.stat().st_size,
                        extension=extension,
                    )
                )
                if max_files is not None and len(results) >= max_files:
                    return results
        return results

    def total_size(self) -> int:
        """Total size of all documents currently in the corpus."""
        return sum(info.size for info in self.list())

    def write_atomic(
        self, relative_path: str, data: bytes, *, overwrite: bool = False
    ) -> DocumentInfo:
        """Write a document atomically, jailed, quota-bounded, no-clobber.

        The bytes are written to a temporary file in the destination
        directory, flushed and fsynced, then moved into place. Without
        overwrite the move is a hard link that fails if the target already
        exists (race-free), so a concurrent writer cannot be clobbered.
        """
        if len(data) > self._write_max_bytes:
            raise DocumentTooLargeError(
                f"document exceeds {self._write_max_bytes} bytes"
            )
        resolved = self._resolve(relative_path)
        parent = resolved.parent
        if not parent.is_relative_to(self._root):
            raise DocumentStoreError("path resolves outside the corpus")

        exists = resolved.exists()
        if exists and not overwrite:
            raise DocumentExistsError(
                "document already exists; overwrite not permitted"
            )

        prior = resolved.stat().st_size if exists else 0
        if self.total_size() - prior + len(data) > self._quota_bytes:
            raise QuotaExceededError("write would exceed the corpus quota")

        parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            dir=parent, prefix=".arrowhead-tmp-", suffix=resolved.suffix
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            if overwrite:
                os.replace(tmp, resolved)
            else:
                try:
                    os.link(tmp, resolved)
                except FileExistsError as exc:
                    raise DocumentExistsError(
                        "document already exists; overwrite not permitted"
                    ) from exc
                finally:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        return self.stat(relative_path)


def build_document_store(settings: Settings) -> DocumentStore:
    """Construct the corpus store from settings."""
    return DocumentStore(
        settings.docs_root,
        read_max_bytes=settings.doc_max_bytes,
        write_max_bytes=settings.doc_write_max_bytes,
        quota_bytes=settings.doc_write_quota_bytes,
    )
