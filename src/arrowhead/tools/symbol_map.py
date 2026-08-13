"""Map the named definitions under a repository prefix.

Authorized as a range over the repo namespace and filtered per file, so
the map never names a symbol from a file the caller could not read
directly. Extraction is best effort per file and bounded in files and
symbols, with a truncated flag instead of silent loss. Symbol names come
from source code, so each is sanitized before it leaves.
"""

from typing import TypedDict

import anyio

from arrowhead.authz.enforce import authorize_action, get_authorizer
from arrowhead.authz.policy import (
    ACTION_READ,
    ACTION_SEARCH,
    KIND_REPO_FILE,
    KIND_REPO_PREFIX,
    Resource,
)
from arrowhead.config import get_settings
from arrowhead.content.text_safe import sanitize_text
from arrowhead.errors import ToolError
from arrowhead.repo.store import RepoStoreError, build_repo_store
from arrowhead.repo.symbols import Symbol, extract_symbols
from arrowhead.security.input_validation import (
    ValidationError,
    validate_relative_path,
)


class SymbolMapResult(TypedDict):
    """The bounded symbol map of a repository subtree."""

    notice: str
    file_count: int
    symbol_count: int
    truncated: bool
    symbols: list[Symbol]


async def symbol_map(path_prefix: str = "") -> SymbolMapResult:
    """List the functions, classes, and types defined under a repository
    prefix, with their line spans. Example: symbol_map(path_prefix="src/").
    """
    settings = get_settings()
    if path_prefix:
        try:
            validate_relative_path(path_prefix)
        except ValidationError as exc:
            raise ToolError(str(exc)) from exc

    subject = authorize_action(
        ACTION_SEARCH, Resource(kind=KIND_REPO_PREFIX, identifier=path_prefix)
    )

    return await anyio.to_thread.run_sync(
        _run_map, path_prefix, subject, settings
    )


def _run_map(path_prefix, subject, settings) -> dict:
    from arrowhead.content.provenance import UNTRUSTED_NOTICE

    store = build_repo_store(settings)
    authorizer = get_authorizer()
    listing = store.list(
        extensions=settings.repo_allowed_extension_set(),
        max_files=settings.symbol_map_max_files,
        path_prefix=path_prefix,
    )
    truncated = listing.truncated
    symbols: list[Symbol] = []
    files = 0
    for info in listing.items:
        if not authorizer.authorize(
            subject,
            ACTION_READ,
            Resource(kind=KIND_REPO_FILE, identifier=info.path),
        ).allowed:
            continue
        try:
            text = store.read_text(info.path)
        except RepoStoreError:
            continue
        extracted = extract_symbols(info.path, text)
        if not extracted:
            continue
        files += 1
        remaining = settings.symbol_map_max_symbols - len(symbols)
        if len(extracted) > remaining:
            extracted = extracted[:remaining]
            truncated = True
        for symbol in extracted:
            symbols.append({**symbol, "name": sanitize_text(symbol["name"])})
        if len(symbols) >= settings.symbol_map_max_symbols:
            truncated = True
            break
    return {
        "notice": UNTRUSTED_NOTICE,
        "file_count": files,
        "symbol_count": len(symbols),
        "truncated": truncated,
        "symbols": symbols,
    }
