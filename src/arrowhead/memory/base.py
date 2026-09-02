"""The memory backend seam.

A backend persists owner-scoped memories (namespaced records with
content-hash dedup) and an exact-key scratchpad. The interface is
deliberately small so a deployment can substitute its own store without
touching the tools. Every operation takes the owner explicitly: it is the
verified caller identity, resolved by the tool layer, never an argument a
caller controls.
"""

from dataclasses import dataclass
from typing import Protocol


class MemoryBackendError(Exception):
    """A memory operation could not be completed safely."""


class MemoryEntryNotFoundError(MemoryBackendError):
    """No entry exists for the requested namespace and id, or key."""


@dataclass(frozen=True)
class MemorySummary:
    """Metadata about one stored memory, without its content."""

    id: str
    size: int
    created_at: str
    updated_at: str
    metadata: dict


@dataclass(frozen=True)
class MemoryHit:
    """One recall result: the entry, its content, and a relevance score.

    Scores order results within a single response; they are comparable
    across hits of one search, not across backends.
    """

    id: str
    content: str
    score: float
    metadata: dict


class MemoryBackend(Protocol):
    """Persists memories and scratchpad values for verified owners.

    recall names the search this backend actually performs ("keyword" or
    "semantic"), so results are labeled honestly rather than implying
    semantics a backend does not have.
    """

    recall: str

    async def store(
        self,
        owner: str,
        namespace: str,
        content: str,
        metadata: dict,
        entry_id: str | None,
    ) -> tuple[str, str]:
        """Upsert a memory; return (id, "created"|"updated"|"unchanged").

        Content already present in the namespace (by content hash) returns
        the existing id as "unchanged". An entry_id updates that entry in
        place or raises MemoryEntryNotFoundError; ids are server-minted,
        never caller-created.
        """
        ...

    async def search(
        self, owner: str, namespace: str, query: str, k: int
    ) -> list[MemoryHit]:
        """The k entries most relevant to the query, best first."""
        ...

    async def list(self, owner: str, namespace: str) -> list[MemorySummary]:
        """Summaries of the namespace's entries, most recently updated first."""
        ...

    async def delete(self, owner: str, namespace: str, entry_id: str) -> None:
        """Delete one entry; raise MemoryEntryNotFoundError if absent."""
        ...

    async def kv_set(
        self, owner: str, key: str, value: str, ttl_seconds: int | None
    ) -> str | None:
        """Set a scratchpad value; return its expiry timestamp, if any."""
        ...

    async def kv_get(self, owner: str, key: str) -> tuple[str, str | None]:
        """Return (value, expiry timestamp or None); an expired or missing
        key raises MemoryEntryNotFoundError. Expiry is lazy: an expired
        record is removed on read."""
        ...

    async def kv_delete(self, owner: str, key: str) -> None:
        """Delete a scratchpad value; raise MemoryEntryNotFoundError if
        absent."""
        ...
