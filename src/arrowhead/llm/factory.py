"""Build the configured completion provider.

Providers are imported lazily so reading configuration loads no HTTP
client, and the default of "none" raises a clear refusal instead of
guessing at a backend.
"""

from arrowhead.config import Settings
from arrowhead.llm.base import CompletionError, CompletionProvider


def build_completion_provider(settings: Settings) -> CompletionProvider:
    if settings.llm_provider == "anthropic":
        from arrowhead.llm.anthropic_http import AnthropicProvider

        return AnthropicProvider(settings)
    if settings.llm_provider == "openai":
        from arrowhead.llm.openai_http import OpenAICompatibleProvider

        return OpenAICompatibleProvider(settings)
    raise CompletionError(
        "no completion backend is configured; set ARROWHEAD_LLM_PROVIDER"
    )
