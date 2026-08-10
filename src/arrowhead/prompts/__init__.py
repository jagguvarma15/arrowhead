"""MCP prompts exposed by Arrowhead.

A prompt is a reusable, server-provided instruction a client can list and
fill. These prompts reference documents by their resource URI or by a tool
call rather than inlining document content, so untrusted corpus text never
rides inside the prompt template itself. The caller-supplied arguments are
sanitized before they are placed in the message.
"""
