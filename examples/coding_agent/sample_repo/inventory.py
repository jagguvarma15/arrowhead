"""A tiny module the coding-agent walkthrough reads, maps, and runs."""


def restock(counts: dict[str, int], item: str, amount: int) -> dict[str, int]:
    """Return counts with amount added to item, never going below zero."""
    updated = dict(counts)
    updated[item] = max(0, updated.get(item, 0) + amount)
    return updated


def total(counts: dict[str, int]) -> int:
    """The sum of all item counts."""
    return sum(counts.values())
