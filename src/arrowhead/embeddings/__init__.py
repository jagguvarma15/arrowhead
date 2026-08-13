"""Pluggable embedding providers for the retrieval tools.

doc_index and vector_query turn text into vectors through a provider selected
by configuration. The package stays inert on import: callers import the
submodule they need (base, deterministic, http, factory) so adding a provider
never widens what importing arrowhead pulls in.
"""
