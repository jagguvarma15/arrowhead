"""Curate and read owner-scoped working sets.

workingset_update pins, unpins, or clears references in a named set;
workingset_get reads one back. Ownership is the caller's verified
identity, so a caller only ever touches its own sets and a set it does
not own reads as not found. Each pinned item is authorized at pin time
against the resource it names, so a caller cannot stash a reference to
something it may not read; the packer authorizes again at resolve time,
because a grant can change between pinning and use.
"""

from typing import TypedDict

from arrowhead.auth.identity import caller_identity
from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import (
    ACTION_READ,
    KIND_DOCUMENT,
    KIND_REPO_FILE,
    Resource,
)
from arrowhead.config import get_settings
from arrowhead.content.text_safe import sanitize_text
from arrowhead.errors import ToolError
from arrowhead.security.input_validation import (
    ValidationError,
    validate_document_path,
    validate_relative_path,
)
from arrowhead.workingsets import (
    KIND_DOC,
    WorkingSetError,
    WorkingSetItem,
    get_registry,
    valid_kind,
)
from arrowhead.workingsets import KIND_REPO_FILE as WS_REPO_FILE

_ACTIONS = frozenset({"pin", "unpin", "clear"})
_MAX_NOTE = 200
_AUTHZ_KIND = {KIND_DOC: KIND_DOCUMENT, WS_REPO_FILE: KIND_REPO_FILE}


class WorkingSetView(TypedDict):
    """A working set's current contents."""

    name: str
    item_count: int
    items: list[dict]


async def workingset_update(
    name: str, action: str, items: list[dict] | None = None
) -> WorkingSetView:
    """Pin, unpin, or clear references in a named working set. Each item is
    {"kind": "doc"|"repo_file", "identifier": ..., "note": ...}; pinned items
    are authorized as you pin them. Example:
    workingset_update(name="bug", action="pin",
    items=[{"kind": "repo_file", "identifier": "src/app.py"}]).
    """
    _validate_name(name)
    if action not in _ACTIONS:
        raise ToolError("action must be one of pin, unpin, clear")
    owner = caller_identity()
    registry = get_registry()

    if action == "clear":
        registry.clear(owner, name)
        return {"name": name, "item_count": 0, "items": []}

    parsed = _parse_items(items or [], authorize=action == "pin")
    try:
        if action == "pin":
            entry = registry.pin(owner, name, parsed)
        else:
            entry = registry.unpin(owner, name, parsed)
    except WorkingSetError as exc:
        raise ToolError(str(exc)) from exc
    return _view(name, entry)


async def workingset_get(name: str) -> WorkingSetView:
    """Read the contents of a named working set you own. A set you do not
    own is reported as not found. Example: workingset_get(name="bug").
    """
    _validate_name(name)
    entry = get_registry().get(caller_identity(), name)
    if entry is None:
        raise ToolError("working set not found")
    return _view(name, entry)


def _validate_name(name: str) -> None:
    if not isinstance(name, str) or not name.strip():
        raise ToolError("name must be a non-empty string")
    if len(name) > 128 or not all(
        ch.isalnum() or ch in "-_./" for ch in name
    ):
        raise ToolError("name has invalid characters")


def _parse_items(items, *, authorize: bool) -> list[WorkingSetItem]:
    if not isinstance(items, list):
        raise ToolError("items must be a list")
    settings = get_settings()
    parsed: list[WorkingSetItem] = []
    for raw in items:
        if not isinstance(raw, dict):
            raise ToolError("each item must be an object")
        kind = raw.get("kind")
        identifier = raw.get("identifier")
        note = raw.get("note", "")
        if not valid_kind(kind):
            raise ToolError("item kind must be doc or repo_file")
        if not isinstance(identifier, str) or not identifier:
            raise ToolError("item identifier must be a non-empty string")
        if not isinstance(note, str) or len(note) > _MAX_NOTE:
            raise ToolError(f"item note must be a string under {_MAX_NOTE} chars")
        _validate_identifier(kind, identifier, settings)
        if authorize:
            authorize_action(
                ACTION_READ,
                Resource(kind=_AUTHZ_KIND[kind], identifier=identifier),
            )
        parsed.append(
            WorkingSetItem(
                kind=kind,
                identifier=identifier,
                note=sanitize_text(note),
            )
        )
    return parsed


def _validate_identifier(kind: str, identifier: str, settings) -> None:
    try:
        if kind == KIND_DOC:
            validate_document_path(
                identifier,
                allowed_extensions=settings.doc_allowed_extension_set(),
            )
        else:
            validate_relative_path(identifier)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc


def _view(name: str, entry) -> WorkingSetView:
    items = [
        {"kind": item.kind, "identifier": item.identifier, "note": item.note}
        for item in entry.items.values()
    ]
    return {"name": name, "item_count": len(items), "items": items}
