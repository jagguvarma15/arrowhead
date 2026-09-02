"""Exact-key scratchpad tools.

A lightweight owner-scoped key-value store for run state, checkpoints,
and idempotency keys: exact keys, plain string values, optional expiry.
The owner is resolved from the verified caller identity through the
authorization step, and the backend keys every value by it, so no caller
can reach another's keys. Values come back through the same
sanitize-on-read, provenance-wrapped envelope document reads use.
"""

from typing import TypedDict

from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import ACTION_READ, ACTION_WRITE, KIND_MEMORY, Resource
from arrowhead.config import Settings, get_settings
from arrowhead.content.provenance import ProvenancedResult, wrap_content
from arrowhead.content.text_safe import sanitize_text
from arrowhead.errors import ToolError
from arrowhead.memory.base import MemoryBackendError, MemoryEntryNotFoundError
from arrowhead.memory.factory import build_memory_backend
from arrowhead.security.input_validation import ValidationError, validate_kv_key


class KvSetResult(TypedDict):
    """Confirmation of a stored value and its expiry, if any."""

    key: str
    expires_at: str | None


class KvDeleteResult(TypedDict):
    """Confirmation of one deleted key."""

    key: str
    deleted: bool


async def kv_set(
    key: str, value: str, ttl_seconds: int | None = None
) -> KvSetResult:
    """Set a scratchpad value for an exact key, replacing any prior value.
    ttl_seconds expires it; keys use letters, digits, and . _ : - only.
    Example: kv_set(key="run:42:state", value="phase2", ttl_seconds=600).
    """
    settings = get_settings()
    try:
        validate_kv_key(key)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc
    if not isinstance(value, str):
        raise ToolError("value must be a string")
    if "\x00" in value:
        raise ToolError("value contains a null byte")
    if len(value.encode("utf-8")) > settings.kv_max_value_bytes:
        raise ToolError(f"value exceeds {settings.kv_max_value_bytes} bytes")
    ttl = _validated_ttl(ttl_seconds, settings)

    owner = authorize_action(
        ACTION_WRITE, Resource(kind=KIND_MEMORY, identifier=f"kv/{key}")
    )
    backend = _backend(settings)
    try:
        expires_at = await backend.kv_set(owner, key, value, ttl)
    except MemoryBackendError as exc:
        raise ToolError(str(exc)) from exc
    return {"key": key, "expires_at": expires_at}


async def kv_get(key: str) -> ProvenancedResult:
    """Get the scratchpad value stored for an exact key you own. An expired
    or missing key is reported as not found. Example:
    kv_get(key="run:42:state").
    """
    settings = get_settings()
    try:
        validate_kv_key(key)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc

    owner = authorize_action(
        ACTION_READ, Resource(kind=KIND_MEMORY, identifier=f"kv/{key}")
    )
    backend = _backend(settings)
    try:
        value, _expires = await backend.kv_get(owner, key)
    except MemoryEntryNotFoundError as exc:
        raise ToolError(str(exc)) from exc
    except MemoryBackendError as exc:
        raise ToolError(str(exc)) from exc
    return wrap_content(
        sanitize_text(value), source=f"kv:{key}", content_format="text"
    )


async def kv_delete(key: str) -> KvDeleteResult:
    """Delete the scratchpad value stored for an exact key you own.
    Example: kv_delete(key="run:42:state").
    """
    settings = get_settings()
    try:
        validate_kv_key(key)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc

    owner = authorize_action(
        ACTION_WRITE, Resource(kind=KIND_MEMORY, identifier=f"kv/{key}")
    )
    backend = _backend(settings)
    try:
        await backend.kv_delete(owner, key)
    except MemoryEntryNotFoundError as exc:
        raise ToolError(str(exc)) from exc
    except MemoryBackendError as exc:
        raise ToolError(str(exc)) from exc
    return {"key": key, "deleted": True}


def _backend(settings: Settings):
    try:
        return build_memory_backend(settings)
    except MemoryBackendError as exc:
        raise ToolError(str(exc)) from exc


def _validated_ttl(ttl_seconds, settings: Settings) -> int | None:
    if ttl_seconds is None:
        return None
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise ToolError("ttl_seconds must be an integer")
    if ttl_seconds < 1:
        raise ToolError("ttl_seconds must be at least 1")
    if ttl_seconds > settings.kv_max_ttl_seconds:
        raise ToolError(
            f"ttl_seconds must be at most {settings.kv_max_ttl_seconds}"
        )
    return ttl_seconds
