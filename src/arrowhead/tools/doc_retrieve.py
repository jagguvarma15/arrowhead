"""Retrieve an external document, SSRF-guarded and content-sanitized.

Fetches an http or https URL through the same SSRF guard as safe_fetch,
which refuses private, loopback, link-local, and cloud-metadata targets,
pins the vetted address, and never forwards the caller's credentials. The
decompressed response is size-capped by the fetch layer, which bounds
decompression bombs. The body is then sanitized for its content type and
wrapped in provenance so the caller treats it as untrusted data.
"""

import json
from datetime import UTC, datetime

import httpx
from fastmcp.exceptions import ToolError

from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import ACTION_READ, KIND_URL, Resource
from arrowhead.config import get_settings
from arrowhead.content.json_safe import JSONSafetyError, parse_json
from arrowhead.content.markdown_safe import sanitize_markdown
from arrowhead.content.provenance import wrap_content
from arrowhead.content.text_safe import sanitize_text
from arrowhead.security.input_validation import ValidationError, validate_url
from arrowhead.security.ssrf_guard import BlockedURLError
from arrowhead.tools.safe_fetch import FetchTooLargeError, fetch_url


async def doc_retrieve(url: str) -> dict:
    """Retrieve a JSON, Markdown, or text document from a public URL,
    SSRF-guarded and sanitized. Returns wrapped, untrusted content.
    Example: doc_retrieve(url="https://example.com/data.json").
    """
    settings = get_settings()
    try:
        validate_url(url)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc

    authorize_action(ACTION_READ, Resource(kind=KIND_URL, identifier=url))

    try:
        response = await fetch_url(url)
    except (ValidationError, BlockedURLError, FetchTooLargeError) as exc:
        raise ToolError(str(exc)) from exc
    except httpx.HTTPError as exc:
        raise ToolError(f"retrieve failed: {type(exc).__name__}") from exc

    content, content_format = _sanitize(
        response["body"], response["content_type"], settings
    )
    wrapped = wrap_content(
        content,
        source=url,
        content_format=content_format,
        retrieved_at=datetime.now(UTC).isoformat(),
    )
    wrapped["metadata"]["status"] = response["status"]
    return wrapped


def _sanitize(body: str, content_type: str | None, settings) -> tuple[str, str]:
    kind = (content_type or "").split(";", 1)[0].strip().lower()
    if kind == "application/json" or kind.endswith("+json"):
        try:
            parsed = parse_json(
                body,
                max_bytes=settings.content_max_bytes,
                max_depth=settings.json_max_depth,
                max_elements=settings.json_max_elements,
            )
        except JSONSafetyError as exc:
            raise ToolError(str(exc)) from exc
        return json.dumps(parsed, ensure_ascii=False, sort_keys=True, indent=2), "json"
    content_format = "md" if kind == "text/markdown" else "txt"
    # Sanitize every non-JSON body as Markdown-over-text so embedded HTML
    # and image-exfiltration vectors are neutralized regardless of type.
    return sanitize_markdown(sanitize_text(body)), content_format
