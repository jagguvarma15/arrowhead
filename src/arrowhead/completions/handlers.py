"""The completion handler wired into the low-level server.

MCP delivers a completion request for one argument of a prompt or resource
template. This handler completes the path-shaped arguments with corpus
document paths the current caller is authorized to read, bounded in count.
Arguments it does not recognize return no completion.
"""

import time

import anyio
from mcp.types import Completion

from arrowhead.auth.identity import caller_identity
from arrowhead.authz.enforce import get_authorizer
from arrowhead.authz.policy import ACTION_READ, KIND_DOCUMENT, Resource
from arrowhead.config import get_settings
from arrowhead.observability.audit_log import audit_event
from arrowhead.store.document_store import build_document_store

# The arguments worth completing with a document path. Other argument names
# (a query string, a URL) have no useful corpus completion.
_PATH_ARGUMENTS = frozenset({"path", "path_prefix"})
_MAX_COMPLETIONS = 50


def guarded_completion(rate_limiter, disabled):
    """Wrap the completion handler with the kill switch, rate limit, and audit
    line a tool call gets, because the low-level completion path bypasses the
    middleware chain. A disabled or rate-limited completion returns no values
    (never runs the corpus walk) rather than raising, so an as-you-type client
    degrades gracefully instead of erroring.
    """

    async def guarded(ref, argument, context=None) -> Completion | None:
        started = time.perf_counter()
        status = "ok"
        try:
            if "completion" in disabled:
                status = "refused"
                return Completion(values=[], total=0, hasMore=False)
            if rate_limiter is not None and not await rate_limiter.allow(
                "completion"
            ):
                status = "refused"
                return Completion(values=[], total=0, hasMore=False)
            return await complete_argument(ref, argument, context)
        except Exception:
            status = "error"
            raise
        finally:
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            audit_event(
                "complete",
                status=status,
                duration_ms=duration_ms,
                metric_label="completion",
            )

    return guarded


async def complete_argument(ref, argument, context=None) -> Completion | None:
    """Complete a path argument with authorized corpus paths, or return None."""
    if getattr(argument, "name", None) not in _PATH_ARGUMENTS:
        return None
    subject = caller_identity()
    partial = getattr(argument, "value", "") or ""
    matches = await anyio.to_thread.run_sync(_matching_paths, subject, partial)
    return Completion(
        values=matches[:_MAX_COMPLETIONS],
        total=len(matches),
        hasMore=len(matches) > _MAX_COMPLETIONS,
    )


def _matching_paths(subject: str, partial: str) -> list[str]:
    settings = get_settings()
    store = build_document_store(settings)
    authorizer = get_authorizer()
    listing = store.list(
        extensions=settings.doc_allowed_extension_set(),
        max_files=settings.search_max_files,
    )
    matches = [
        info.path
        for info in listing.items
        if info.path.startswith(partial)
        and authorizer.authorize(
            subject, ACTION_READ, Resource(kind=KIND_DOCUMENT, identifier=info.path)
        ).allowed
    ]
    return sorted(matches)
