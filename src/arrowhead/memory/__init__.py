"""Agent memory and scratchpad backends.

The memory tools store owner-scoped records behind a small backend seam:
a jailed file tree by default, Postgres when a memory DSN is configured.
"""
