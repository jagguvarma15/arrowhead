"""The completion handler wired into the low-level server.

MCP delivers a completion request for one argument of a prompt or resource
template. This handler completes the path-shaped arguments with corpus
document paths the current caller is authorized to read, bounded in count.
Arguments it does not recognize return no completion.
"""

import anyio
from mcp.types import Completion

from arrowhead.auth.identity import caller_identity
from arrowhead.authz.enforce import get_authorizer
from arrowhead.authz.policy import ACTION_READ, KIND_DOCUMENT, Resource
from arrowhead.config import get_settings
from arrowhead.store.document_store import build_document_store

# The arguments worth completing with a document path. Other argument names
# (a query string, a URL) have no useful corpus completion.
_PATH_ARGUMENTS = frozenset({"path", "path_prefix"})
_MAX_COMPLETIONS = 50


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
