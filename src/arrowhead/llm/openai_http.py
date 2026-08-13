"""A completion provider for any OpenAI-compatible chat endpoint.

One base URL covers Ollama, vLLM, LM Studio, and most cloud deployments:
the endpoint is the full chat-completions URL (for a local Ollama,
http://127.0.0.1:11434/v1/chat/completions, with that host:port pair
named in llm_internal_hosts). The bearer key is optional because local
servers rarely need one, is read from configuration, and never appears
in an error.
"""

from arrowhead.config import Settings
from arrowhead.llm.base import CompletionError
from arrowhead.llm.transport import post_json


class OpenAICompatibleProvider:
    """Completes prompts through an OpenAI-compatible chat endpoint."""

    def __init__(
        self, settings: Settings, *, transport=None, getaddrinfo=None
    ) -> None:
        if not settings.llm_endpoint:
            raise CompletionError("the openai provider needs an endpoint")
        if not settings.llm_model:
            raise CompletionError("the openai provider needs a model name")
        self._settings = settings
        self._transport = transport
        self._getaddrinfo = getaddrinfo

    async def complete(
        self, prompt: str, *, system: str | None = None, max_tokens: int
    ) -> str:
        settings = self._settings
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        headers = {}
        if settings.llm_api_key:
            headers["Authorization"] = f"Bearer {settings.llm_api_key}"
        document = await post_json(
            settings,
            url=settings.llm_endpoint,
            headers=headers,
            payload={
                "model": settings.llm_model,
                "max_tokens": max_tokens,
                "messages": messages,
            },
            transport=self._transport,
            getaddrinfo=self._getaddrinfo,
        )
        choices = document.get("choices")
        if not isinstance(choices, list) or not choices:
            raise CompletionError(
                "completion response had an unexpected shape"
            )
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        text = message.get("content") if isinstance(message, dict) else None
        if not isinstance(text, str) or not text:
            raise CompletionError("completion response carried no text")
        return text
