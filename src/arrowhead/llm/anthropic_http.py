"""A completion provider for the Anthropic Messages API.

Speaks the Messages wire shape directly over the hardened transport, so
the base install carries no vendor SDK. The key rides the x-api-key
header, is read from configuration, and never appears in an error.
"""

from arrowhead.config import Settings
from arrowhead.llm.base import CompletionError
from arrowhead.llm.transport import post_json

_DEFAULT_ENDPOINT = "https://api.anthropic.com/v1/messages"
_API_VERSION = "2023-06-01"


class AnthropicProvider:
    """Completes prompts through the Anthropic Messages API."""

    def __init__(
        self, settings: Settings, *, transport=None, getaddrinfo=None
    ) -> None:
        if not settings.llm_model:
            raise CompletionError("the anthropic provider needs a model name")
        if not settings.llm_api_key:
            raise CompletionError("the anthropic provider needs an api key")
        self._settings = settings
        self._transport = transport
        self._getaddrinfo = getaddrinfo

    async def complete(
        self, prompt: str, *, system: str | None = None, max_tokens: int
    ) -> str:
        settings = self._settings
        payload: dict = {
            "model": settings.llm_model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system
        document = await post_json(
            settings,
            url=settings.llm_endpoint or _DEFAULT_ENDPOINT,
            headers={
                "x-api-key": settings.llm_api_key,
                "anthropic-version": _API_VERSION,
            },
            payload=payload,
            transport=self._transport,
            getaddrinfo=self._getaddrinfo,
        )
        blocks = document.get("content")
        if not isinstance(blocks, list):
            raise CompletionError(
                "completion response had an unexpected shape"
            )
        texts = [
            block.get("text")
            for block in blocks
            if isinstance(block, dict) and block.get("type") == "text"
        ]
        if not texts or any(not isinstance(text, str) for text in texts):
            raise CompletionError("completion response carried no text")
        return "".join(texts)
