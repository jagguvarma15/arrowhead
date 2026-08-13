"""Owner-scoped working sets an agent curates across calls.

A working set is a named collection of pinned references (a corpus
document or a repository file) an agent builds up over a session and
later resolves cheaply, for example through the context packer. Following
the task registry's contract exactly: the store lives in process, every
set is keyed by its owner's verified identity so a caller only ever sees
its own, a set another owner holds reads as simply not found, and the
store is LRU-bounded so one caller cannot grow it without limit. A shared
backend can hold this state for a multi-instance deployment later, the
same seam the tasks and rate-limit stores leave open.
"""

from collections import OrderedDict
from dataclasses import dataclass, field

# The reference kinds a working set may pin. Each maps to a validator and,
# at resolve time, to the authorization kind that governs reading it.
KIND_DOC = "doc"
KIND_REPO_FILE = "repo_file"
_KINDS = frozenset({KIND_DOC, KIND_REPO_FILE})


@dataclass(frozen=True)
class WorkingSetItem:
    """One pinned reference: what kind, which identifier, and a note."""

    kind: str
    identifier: str
    note: str = ""


@dataclass
class WorkingSet:
    """A named set of pinned items, ordered by insertion."""

    name: str
    items: "OrderedDict[tuple[str, str], WorkingSetItem]" = field(
        default_factory=OrderedDict
    )


class WorkingSetError(Exception):
    """A working set operation could not be completed."""


class WorkingSetRegistry:
    """In-process, owner-keyed, bounded working set store."""

    def __init__(self, *, max_sets: int, max_items: int) -> None:
        self._max_sets = max_sets
        self._max_items = max_items
        self._sets: OrderedDict[tuple[str, str], WorkingSet] = OrderedDict()

    def get(self, owner: str, name: str) -> WorkingSet | None:
        """The named set for this owner, or None (also for a foreign set)."""
        entry = self._sets.get((owner, name))
        if entry is not None:
            self._sets.move_to_end((owner, name))
        return entry

    def clear(self, owner: str, name: str) -> None:
        """Remove the named set, if the owner has one."""
        self._sets.pop((owner, name), None)

    def pin(
        self, owner: str, name: str, items: list[WorkingSetItem]
    ) -> WorkingSet:
        """Add items to the owner's named set, creating it if needed."""
        key = (owner, name)
        entry = self._sets.get(key)
        if entry is None:
            if len([k for k in self._sets if k[0] == owner]) >= self._max_sets:
                raise WorkingSetError(
                    f"at most {self._max_sets} working sets per owner"
                )
            entry = WorkingSet(name=name)
            self._sets[key] = entry
        for item in items:
            if len(entry.items) >= self._max_items and (
                (item.kind, item.identifier) not in entry.items
            ):
                raise WorkingSetError(
                    f"at most {self._max_items} items per working set"
                )
            entry.items[(item.kind, item.identifier)] = item
        self._sets.move_to_end(key)
        self._evict()
        return entry

    def unpin(
        self, owner: str, name: str, items: list[WorkingSetItem]
    ) -> WorkingSet | None:
        """Remove items from the owner's named set, if it exists."""
        entry = self._sets.get((owner, name))
        if entry is None:
            return None
        for item in items:
            entry.items.pop((item.kind, item.identifier), None)
        return entry

    def _evict(self) -> None:
        while len(self._sets) > self._max_sets * max(
            1, len({owner for owner, _ in self._sets})
        ):
            self._sets.popitem(last=False)


def valid_kind(kind: str) -> bool:
    return kind in _KINDS


_registry: WorkingSetRegistry | None = None


def get_registry() -> WorkingSetRegistry:
    """The process-wide working set registry, built on first use."""
    global _registry
    if _registry is None:
        from arrowhead.config import get_settings

        settings = get_settings()
        _registry = WorkingSetRegistry(
            max_sets=settings.workingset_max_sets,
            max_items=settings.workingset_max_items,
        )
    return _registry


def reset_registry() -> None:
    """Drop the registry so a test starts from an empty store."""
    global _registry
    _registry = None
