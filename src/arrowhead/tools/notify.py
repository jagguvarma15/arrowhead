"""Outbound webhook notifier, allowlisted and SSRF-guarded.

A deliberate, narrow egress channel: POST one JSON payload to a URL the
operator has allowlisted. The family only registers when the allowlist is
non-empty (the exec_enabled pattern) and the body re-checks it, and even
an allowlisted target is still vetted by the SSRF guard and pinned to the
resolved address, so a DNS rebind or a private-range entry cannot reach
internal services. Redirects are refused outright: a redirect is a
different destination than the operator approved. Responses are bounded
and sanitized; the caller's MCP credentials are never attached.

Holding the tool's scope is necessary but not sufficient: the post is
authorized under its own `notify` action, absent from the default grants,
so a deployment opts in twice (allowlist plus grant).
"""

import json
from typing import TypedDict
from urllib.parse import urlsplit

import httpx

from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import ACTION_NOTIFY, KIND_URL, Resource
from arrowhead.config import Settings, get_settings
from arrowhead.content.provenance import UNTRUSTED_NOTICE
from arrowhead.content.text_safe import sanitize_text
from arrowhead.errors import ToolError
from arrowhead.security.input_validation import ValidationError, validate_url
from arrowhead.security.ssrf_guard import BlockedURLError, resolve_pinned

_DEFAULT_PORTS = {"http": 80, "https": 443}


class NotifyResult(TypedDict):
    """The webhook's status and its bounded, sanitized response body."""

    notice: str
    status: int
    response: str
    truncated: bool


async def notify_webhook(url: str, payload: dict) -> NotifyResult:
    """POST a JSON payload to a webhook URL on the operator allowlist and
    return the bounded response status. Example:
    notify_webhook(url="https://hooks.example.com/ci", payload={"text": "done"}).
    """
    settings = get_settings()
    try:
        validate_url(url)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc
    if not isinstance(payload, dict):
        raise ToolError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ToolError("payload must be JSON-serializable") from exc
    body = encoded.encode("utf-8")
    if len(body) > settings.notify_max_payload_bytes:
        raise ToolError(
            f"payload exceeds {settings.notify_max_payload_bytes} bytes"
        )

    entries = settings.notify_allowlist_entries()
    if not entries:
        # The registration gate normally keeps this tool out entirely; the
        # re-check covers a stale registration or an embedding host.
        raise ToolError("the notify allowlist is not configured")
    if not _allowlisted(url, entries):
        raise ToolError("url is not on the notify allowlist")

    authorize_action(ACTION_NOTIFY, Resource(kind=KIND_URL, identifier=url))
    try:
        return await post_webhook(url, body, settings)
    except (ValidationError, BlockedURLError) as exc:
        raise ToolError(str(exc)) from exc
    except httpx.HTTPError as exc:
        raise ToolError(f"notify failed: {type(exc).__name__}") from exc


async def post_webhook(
    url: str,
    body: bytes,
    settings: Settings,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    getaddrinfo=None,
) -> NotifyResult:
    """One pinned POST with no redirects and a capped response.

    transport and getaddrinfo exist so tests can substitute a mock
    transport and resolver; production callers pass only the target.
    """
    target = await resolve_pinned(
        url,
        getaddrinfo=getaddrinfo,
        allowed_hosts=settings.egress_allowed_hosts_set(),
        allowed_ports=settings.egress_allowed_ports_set(),
    )
    extensions = {}
    if target.scheme == "https":
        extensions["sni_hostname"] = target.host
    async with httpx.AsyncClient(
        transport=transport,
        timeout=settings.notify_timeout_seconds,
        follow_redirects=False,
    ) as client:
        request = client.build_request(
            "POST",
            target.request_url,
            content=body,
            headers={
                "Host": target.host_header,
                "Content-Type": "application/json",
            },
            extensions=extensions,
        )
        response = await client.send(request, stream=True)
        try:
            if response.is_redirect:
                raise BlockedURLError(
                    "the webhook redirected; redirects are not followed"
                )
            captured, truncated = await _read_bounded(
                response, settings.notify_max_response_bytes
            )
        finally:
            await response.aclose()
    return {
        "notice": UNTRUSTED_NOTICE,
        "status": response.status_code,
        "response": sanitize_text(captured.decode("utf-8", errors="replace")),
        "truncated": truncated,
    }


async def _read_bounded(
    response: httpx.Response, limit: int
) -> tuple[bytes, bool]:
    """Read up to limit bytes; a longer body is truncated, not an error.

    The response is informational (a delivery receipt), so an oversized
    body is cut rather than failing a post that already happened.
    """
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > limit:
            return bytes(body[:limit]), True
    return bytes(body), False


def _allowlisted(url: str, entries: tuple[str, ...]) -> bool:
    """Whether the target matches an allowlist entry, parsed not prefixed.

    Both sides are parsed and compared on scheme, lowercased host, resolved
    port, and path boundary, so `https://hooks.example.com@evil.net/` and
    `hooks.example.com.evil.net` fail on host equality rather than slipping
    past a string prefix check.
    """
    target = urlsplit(url)
    scheme = target.scheme.lower()
    host = (target.hostname or "").lower()
    port = target.port or _DEFAULT_PORTS.get(scheme)
    path = target.path or "/"
    for entry in entries:
        allowed = urlsplit(entry)
        allowed_scheme = allowed.scheme.lower()
        if allowed_scheme != scheme:
            continue
        if (allowed.hostname or "").lower() != host:
            continue
        if (allowed.port or _DEFAULT_PORTS.get(allowed_scheme)) != port:
            continue
        allowed_path = allowed.path or "/"
        if path == allowed_path:
            return True
        prefix = (
            allowed_path if allowed_path.endswith("/") else allowed_path + "/"
        )
        if path.startswith(prefix):
            return True
    return False
