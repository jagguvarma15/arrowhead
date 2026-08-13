"""Scan the corpus for secrets and PII, returning redacted findings.

Validates the optional path prefix, authorizes the scan, then walks the
corpus in a worker thread. Traversal is bounded by file count and a
wall-clock timeout, large files are skipped, and each candidate is
filtered by the caller's per-document scan authorization. Findings report
a type and a redacted placeholder only; the raw secret value is never
returned or logged.
"""

import time
from typing import TypedDict

import anyio
from arrowhead.errors import ToolError

from arrowhead.authz.enforce import authorize_action, get_authorizer
from arrowhead.authz.policy import ACTION_SCAN, KIND_DOCUMENT, KIND_PREFIX, Resource
from arrowhead.config import get_settings
from arrowhead.content.provenance import UNTRUSTED_NOTICE
from arrowhead.content.text_safe import sanitize_text
from arrowhead.security.input_validation import ValidationError, validate_relative_path
from arrowhead.security.secret_scan import scan_text
from arrowhead.store.document_store import DocumentStoreError, build_document_store


class ScanFinding(TypedDict):
    """One redacted finding: the document, the line, the type, and a placeholder."""

    path: str
    line: int
    type: str
    match: str


class ScanResult(TypedDict):
    """The redacted result of a corpus secrets-and-PII scan."""

    notice: str
    path_prefix: str
    files_scanned: int
    finding_count: int
    truncated: bool
    findings: list[ScanFinding]


async def doc_scan(path_prefix: str = "") -> ScanResult:
    """Scan corpus documents for secrets and PII and return redacted
    findings (type, location, and a hashed placeholder, never the raw
    value). Example: doc_scan(path_prefix="exports/").
    """
    settings = get_settings()
    try:
        if path_prefix:
            validate_relative_path(path_prefix)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc

    subject = authorize_action(
        ACTION_SCAN, Resource(kind=KIND_PREFIX, identifier=path_prefix)
    )
    return await anyio.to_thread.run_sync(_run_scan, path_prefix, subject, settings)


def _run_scan(path_prefix, subject, settings) -> dict:
    store = build_document_store(settings)
    authorizer = get_authorizer()
    findings: list[dict] = []
    files_scanned = 0
    deadline = time.monotonic() + settings.scan_timeout_seconds

    # The store applies the path prefix while it walks, so hitting the file
    # cap before a match is reported as a truncated listing rather than as a
    # silent zero result.
    listing = store.list(
        extensions=settings.doc_allowed_extension_set(),
        max_files=settings.scan_max_files,
        path_prefix=path_prefix,
    )
    truncated = listing.truncated

    for info in listing.items:
        if not authorizer.authorize(
            subject, ACTION_SCAN, Resource(kind=KIND_DOCUMENT, identifier=info.path)
        ).allowed:
            continue
        if info.size > settings.scan_per_file_max_bytes:
            continue
        if time.monotonic() > deadline:
            truncated = True
            break
        try:
            data = store.read_bytes(info.path)
        except DocumentStoreError:
            continue
        files_scanned += 1
        for finding in scan_text(
            sanitize_text(data),
            max_findings=settings.scan_max_findings - len(findings),
        ):
            findings.append(
                {
                    "path": info.path,
                    "line": finding.line,
                    "type": finding.type,
                    "match": finding.redacted,
                }
            )
        if len(findings) >= settings.scan_max_findings:
            truncated = True
            break

    return {
        "notice": UNTRUSTED_NOTICE,
        "path_prefix": path_prefix,
        "files_scanned": files_scanned,
        "finding_count": len(findings),
        "truncated": truncated,
        "findings": findings,
    }
