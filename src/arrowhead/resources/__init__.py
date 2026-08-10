"""MCP resources exposed by Arrowhead.

A resource is addressable, cacheable data a client can read directly. Every
resource here runs the same intrinsic guards as the tools do: the requested
path is validated, the read is authorized per resource against the policy,
and the content is sanitized before it leaves the process, so a resource read
is as safe as the equivalent tool call however it is reached.
"""
