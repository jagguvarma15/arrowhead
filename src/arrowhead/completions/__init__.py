"""Argument completions for prompts and resource templates.

Completions suggest corpus document paths as a caller types a prompt or
resource-template argument. Every suggestion passes the same per-document read
authorization as a search, so completion never reveals a path the caller could
not read, and the list is bounded.
"""
