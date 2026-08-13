"""An embedding provider that calls an OpenAI-compatible HTTP endpoint.

The request is vetted by the same SSRF guard as safe_fetch: the endpoint host
is resolved and refused if it is private, loopback, link-local, or cloud
metadata, and the connection goes to the pinned address the guard approved. The
endpoint host must be on the egress allowlist. A redirect is refused rather than
followed, so the Authorization bearer key never travels to another host. The key
is read from configuration and never appears in an error returned to a caller.
"""

import httpx

from arrowhead.config import Settings
from arrowhead.embeddings.base import EmbeddingError
from arrowhead.security.input_validation import ValidationError, validate_url
from arrowhead.security.ssrf_guard import BlockedURLError, resolve_pinned


class HTTPEmbeddingProvider:
    """Embeds text by posting batches to an OpenAI-compatible endpoint.

    transport and getaddrinfo exist so tests can substitute a mock transport
    and resolver; production callers construct it from settings alone.
    """

    def __init__(
        self, settings: Settings, *, transport=None, getaddrinfo=None
    ) -> None:
        if not settings.embedding_endpoint:
            raise EmbeddingError("the http embedding provider needs an endpoint")
        self._settings = settings
        self._transport = transport
        self._getaddrinfo = getaddrinfo

    @property
    def dimensions(self) -> int:
        return self._settings.embedding_dimensions

    async def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        batch_size = max(1, self._settings.embedding_batch_size)
        vectors: list[list[float]] = []
        async with httpx.AsyncClient(
            transport=self._transport,
            timeout=self._settings.embedding_timeout_seconds,
            follow_redirects=False,
        ) as client:
            for start in range(0, len(texts), batch_size):
                batch = texts[start : start + batch_size]
                vectors.extend(await self._embed_batch(client, batch))
        return vectors

    async def _embed_batch(
        self, client: httpx.AsyncClient, batch: list[str]
    ) -> list[list[float]]:
        settings = self._settings
        try:
            validate_url(settings.embedding_endpoint)
            target = await resolve_pinned(
                settings.embedding_endpoint,
                getaddrinfo=self._getaddrinfo,
                allowed_hosts=settings.egress_allowed_hosts_set(),
                allowed_ports=settings.egress_allowed_ports_set(),
            )
        except (ValidationError, BlockedURLError) as exc:
            raise EmbeddingError(f"embedding endpoint refused: {exc}") from exc
        headers = {"Host": target.host_header, "Content-Type": "application/json"}
        if settings.embedding_api_key:
            headers["Authorization"] = f"Bearer {settings.embedding_api_key}"
        extensions = {}
        if target.scheme == "https":
            extensions["sni_hostname"] = target.host
        request = client.build_request(
            "POST",
            target.request_url,
            headers=headers,
            json={"model": settings.embedding_model, "input": batch},
            extensions=extensions,
        )
        try:
            response = await client.send(request)
        except httpx.HTTPError as exc:
            raise EmbeddingError(
                f"embedding request failed: {type(exc).__name__}"
            ) from exc
        try:
            if response.is_redirect:
                raise EmbeddingError("embedding endpoint attempted a redirect")
            if response.status_code >= 400:
                raise EmbeddingError(
                    f"embedding endpoint returned {response.status_code}"
                )
            payload = response.json()
        finally:
            await response.aclose()
        return self._vectors_from(payload, len(batch))

    def _vectors_from(self, payload, expected: int) -> list[list[float]]:
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list) or len(data) != expected:
            raise EmbeddingError("embedding response had an unexpected shape")

        def _index(item):
            return item.get("index", 0) if isinstance(item, dict) else 0

        vectors: list[list[float]] = []
        for item in sorted(data, key=_index):
            vector = item.get("embedding") if isinstance(item, dict) else None
            if not isinstance(vector, list) or len(vector) != self.dimensions:
                raise EmbeddingError(
                    "embedding response vectors must have "
                    f"{self.dimensions} dimensions"
                )
            try:
                vectors.append([float(value) for value in vector])
            except (TypeError, ValueError) as exc:
                raise EmbeddingError(
                    "embedding response had a non-numeric value"
                ) from exc
        return vectors
