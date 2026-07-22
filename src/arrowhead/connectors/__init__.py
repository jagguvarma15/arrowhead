"""Connectors expose a data source to an agent through the hardened path.

Each connector is a self-contained package: a framework-agnostic client that
can be imported and called directly, and a thin tool adapter that validates,
authorizes, bounds, sanitizes, and provenance-wraps every call. Drivers are
optional extras, so the base install carries only the connectors a deployment
actually uses.
"""
