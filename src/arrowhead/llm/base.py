"""The completion provider seam.

Mirrors the embeddings seam: a small protocol, concrete providers chosen
by configuration, and one error type whose message is always safe to show
a caller. Anything that could carry a key, a body, or a driver detail is
reduced to a type name or a status code before it becomes an error.
"""

from typing import Protocol


class CompletionError(Exception):
    """The completion could not be produced; the message is caller-safe."""


class CompletionProvider(Protocol):
    """Produces one completion for a prompt."""

    async def complete(
        self, prompt: str, *, system: str | None = None, max_tokens: int
    ) -> str: ...
