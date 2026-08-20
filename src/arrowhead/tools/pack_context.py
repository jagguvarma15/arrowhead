"""Assemble a token-budgeted, secret-scanned, provenance-stamped context bundle.

pack_context is the guarded context packer: one call that returns a bundle
an agent can drop into a model's context with confidence. It resolves a
working set's pinned items first, retrieves the rest for the query, ranks
pinned-before-retrieved, and greedily packs snippets under a token budget.
Before anything leaves, every snippet is secret-scanned and redacted, so a
key that sits in retrieved code or a pinned file never reaches the model,
and each snippet carries provenance (source, kind, span, a content hash,
and when it was retrieved) inside the untrusted framing.

The pack is authorized at the boundary as a search over the corpus
namespace, every source of content is reached through the same internal
functions the standalone tools use, and every pinned item is
re-authorized at pack time, so the packer can never surface content a
caller could not read directly. No content bypasses the scan or the
framing.
"""

import hashlib
from datetime import UTC, datetime
from typing import TypedDict

import anyio

from arrowhead.authz.enforce import authorize_action, get_authorizer
from arrowhead.authz.policy import (
    ACTION_READ,
    ACTION_SEARCH,
    KIND_DOCUMENT,
    KIND_PREFIX,
    KIND_REPO_FILE,
    Resource,
)
from arrowhead.config import get_settings
from arrowhead.content.provenance import UNTRUSTED_NOTICE
from arrowhead.content.render import render_document
from arrowhead.content.text_safe import sanitize_text
from arrowhead.errors import ToolError
from arrowhead.security.input_validation import (
    ValidationError,
    validate_search_query,
)
from arrowhead.security.secret_scan import redact_text
from arrowhead.store.document_store import DocumentStoreError, build_document_store
from arrowhead.workingsets import KIND_DOC

# The estimator test_context_cost uses: one token per four characters.
_CHARS_PER_TOKEN = 4


class PackedSnippet(TypedDict):
    """One packed snippet with its provenance."""

    source: str
    kind: str
    span: str
    sha256: str
    retrieved_at: str
    content: str


class PackedContext(TypedDict):
    """The bundle: framed snippets plus what was packed and redacted."""

    notice: str
    token_estimate: int
    truncated: bool
    redactions: int
    snippets: list[PackedSnippet]


async def pack_context(
    query: str, working_set: str = "", token_budget: int = 4000
) -> PackedContext:
    """Assemble a token-budgeted context bundle for a query: a working set's
    pinned items first, then retrieved snippets, each secret-scanned,
    provenance-stamped, and framed as untrusted data. Example:
    pack_context(query="how are refunds issued?", working_set="refunds").
    """
    settings = get_settings()
    try:
        validate_search_query(query, max_length=settings.search_query_max_length)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc
    budget = _bounded_budget(token_budget, settings)

    subject = authorize_action(
        ACTION_SEARCH, Resource(kind=KIND_PREFIX, identifier="")
    )
    candidates: list[dict] = []
    if working_set:
        candidates.extend(await _resolve_pinned(working_set, subject, settings))
    candidates.extend(await _retrieve(query, subject, settings))

    return _pack(candidates, budget, settings)


def _bounded_budget(token_budget, settings) -> int:
    try:
        budget = int(token_budget)
    except (TypeError, ValueError) as exc:
        raise ToolError("token_budget must be an integer") from exc
    if budget < 1:
        raise ToolError("token_budget must be at least 1")
    return min(budget, settings.pack_max_tokens)


async def _resolve_pinned(name: str, subject: str, settings) -> list[dict]:
    """The working set's pinned items, each re-authorized and rendered.

    An item the caller can no longer read, or that no longer exists, is
    skipped with a note rather than aborting the pack, so a stale pin never
    leaks and never fails the whole call.
    """
    from arrowhead.tools.workingset import _validate_name
    from arrowhead.workingsets import get_registry

    _validate_name(name)
    entry = get_registry().get(subject, name)
    if entry is None:
        return []
    authorizer = get_authorizer()
    resolved: list[dict] = []
    for item in entry.items.values():
        rendered = await anyio.to_thread.run_sync(
            _render_pinned, item, subject, authorizer, settings
        )
        if rendered is not None:
            resolved.append(rendered)
    return resolved


def _render_pinned(item, subject, authorizer, settings) -> dict | None:
    kind = KIND_DOCUMENT if item.kind == KIND_DOC else KIND_REPO_FILE
    if not authorizer.authorize(
        subject, ACTION_READ, Resource(kind=kind, identifier=item.identifier)
    ).allowed:
        return None
    from arrowhead.content.json_safe import JSONSafetyError
    from arrowhead.content.text_safe import TextSafetyError
    from arrowhead.repo.store import RepoStoreError, build_repo_store

    try:
        if item.kind == KIND_DOC:
            store = build_document_store(settings)
            data = store.read_bytes(item.identifier)
            content, _fmt = render_document(item.identifier, data, settings)
        else:
            content = build_repo_store(settings).read_text(item.identifier)
    except (
        DocumentStoreError,
        RepoStoreError,
        JSONSafetyError,
        TextSafetyError,
    ):
        # A stale pin (gone, too large, now binary, or unreadable) is
        # skipped rather than failing the whole pack.
        return None
    return {
        "source": item.identifier,
        "kind": f"pinned:{item.kind}",
        "span": "full",
        "content": sanitize_text(content),
        "pinned": True,
    }


async def _retrieve(query: str, subject: str, settings) -> list[dict]:
    """Retrieved snippets for the query, through the standalone search path.

    doc_search already authorizes per document and sanitizes each snippet,
    so the packer reuses it rather than opening a new read path. Its
    refusals become an empty contribution, so a corpus the caller cannot
    search simply adds nothing to the bundle.
    """
    from arrowhead.tools.doc_search import doc_search

    try:
        result = await doc_search(query)
    except ToolError:
        return []
    retrieved: list[dict] = []
    for match in result["matches"]:
        retrieved.append(
            {
                "source": match["path"],
                "kind": "retrieved:doc",
                "span": f"line {match['line']}",
                "content": match["snippet"],
                "pinned": False,
            }
        )
    return retrieved


def _pack(candidates: list[dict], budget: int, settings) -> PackedContext:
    """Rank pinned-first, greedily pack under the budget, scan, and stamp."""
    ordered = sorted(candidates, key=lambda c: not c["pinned"])
    retrieved_at = datetime.now(UTC).isoformat()
    snippets: list[PackedSnippet] = []
    seen: set[tuple[str, str]] = set()
    used_tokens = 0
    redactions = 0
    truncated = False
    for candidate in ordered:
        key = (candidate["source"], candidate["span"])
        if key in seen:
            continue
        seen.add(key)
        redacted, hits = redact_text(
            candidate["content"], max_findings=settings.scan_max_findings
        )
        tokens = _estimate_tokens(redacted)
        if used_tokens + tokens > budget:
            truncated = True
            continue
        used_tokens += tokens
        redactions += hits
        marker = _framed(redacted)
        snippets.append(
            {
                "source": sanitize_text(candidate["source"]),
                "kind": candidate["kind"],
                "span": candidate["span"],
                "sha256": hashlib.sha256(
                    redacted.encode("utf-8")
                ).hexdigest(),
                "retrieved_at": retrieved_at,
                "content": marker,
            }
        )
    return {
        "notice": UNTRUSTED_NOTICE,
        "token_estimate": used_tokens,
        "truncated": truncated,
        "redactions": redactions,
        "snippets": snippets,
    }


def _estimate_tokens(text: str) -> int:
    return -(-len(text) // _CHARS_PER_TOKEN)


def _framed(content: str) -> str:
    import secrets

    marker = secrets.token_hex(8)
    return f"<<UNTRUSTED-{marker}>>\n{content}\n<<END-UNTRUSTED-{marker}>>"
