"""The one hardened HTTP path every completion provider posts through.

The endpoint comes from configuration, never from a caller, and the
request runs under the embedding client's discipline: the URL is
validated, the host is resolved once through the SSRF guard and the
connection goes to the pinned address with the original hostname carried
in the Host header and the TLS server name, redirects are refused rather
than followed so credentials never travel to another host, and every
failure is reduced to an exception type name or a status code so a key or
a response body never reaches a caller. A local model server is reachable
only when its exact host:port pair is named in llm_internal_hosts.
"""

import httpx

from arrowhead.config import Settings
from arrowhead.llm.base import CompletionError
from arrowhead.security.input_validation import ValidationError, validate_url
from arrowhead.security.ssrf_guard import BlockedURLError, resolve_pinned


async def post_json(
    settings: Settings,
    *,
    url: str,
    headers: dict[str, str],
    payload: dict,
    transport=None,
    getaddrinfo=None,
) -> dict:
    """POST a JSON payload to a configuration-addressed endpoint."""
    try:
        validate_url(url)
        target = await resolve_pinned(
            url,
            getaddrinfo=getaddrinfo,
            allowed_hosts=settings.egress_allowed_hosts_set(),
            allowed_ports=settings.egress_allowed_ports_set(),
            trusted_internal=settings.llm_internal_host_set(),
        )
    except (ValidationError, BlockedURLError) as exc:
        raise CompletionError(f"completion endpoint refused: {exc}") from exc

    request_headers = {
        "Host": target.host_header,
        "Content-Type": "application/json",
        **headers,
    }
    extensions = {}
    if target.scheme == "https":
        extensions["sni_hostname"] = target.host

    async with httpx.AsyncClient(
        transport=transport,
        timeout=settings.llm_timeout_seconds,
        follow_redirects=False,
    ) as client:
        request = client.build_request(
            "POST",
            target.request_url,
            headers=request_headers,
            json=payload,
            extensions=extensions,
        )
        try:
            response = await client.send(request)
        except httpx.HTTPError as exc:
            raise CompletionError(
                f"completion request failed: {type(exc).__name__}"
            ) from exc
        try:
            if response.is_redirect:
                raise CompletionError(
                    "completion endpoint attempted a redirect"
                )
            if response.status_code >= 400:
                raise CompletionError(
                    f"completion endpoint returned {response.status_code}"
                )
            document = response.json()
        except ValueError as exc:
            raise CompletionError(
                "completion response was not valid JSON"
            ) from exc
        finally:
            await response.aclose()
    if not isinstance(document, dict):
        raise CompletionError("completion response had an unexpected shape")
    return document
