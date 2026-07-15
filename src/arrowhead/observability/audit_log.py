"""Structured audit log: one line per tool call.

Redaction happens at the source. The record carries the shape of each
argument (type and size), never the value, so a secret in a URL or a
probed filesystem path cannot leak into log storage no matter what any
downstream handler or shipper does with the line.
"""

import json
import logging
import time

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from arrowhead.auth.identity import caller_identity

logger = logging.getLogger("arrowhead.audit")


def describe_arguments(arguments: dict | None) -> dict[str, str]:
    """Argument shapes only: names, types, and sizes. Never values."""
    shapes: dict[str, str] = {}
    for name, value in (arguments or {}).items():
        kind = type(value).__name__
        if isinstance(value, str):
            shapes[name] = f"str[{len(value)}]"
        elif isinstance(value, (list, dict)):
            shapes[name] = f"{kind}[{len(value)}]"
        else:
            shapes[name] = kind
    return shapes


class AuditLogMiddleware(Middleware):
    async def on_call_tool(
        self, context: MiddlewareContext, call_next: CallNext
    ):
        message = context.message
        started = time.perf_counter()
        status = "ok"
        error_type = None
        try:
            result = await call_next(context)
        except ToolError as exc:
            status = "refused"
            error_type = type(exc).__name__
            raise
        except Exception as exc:
            status = "error"
            error_type = type(exc).__name__
            raise
        else:
            return result
        finally:
            record = {
                "event": "tool_call",
                "caller": caller_identity(),
                "tool": message.name,
                "arguments": describe_arguments(message.arguments),
                "status": status,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            }
            if error_type is not None:
                record["error_type"] = error_type
            logger.info(json.dumps(record, sort_keys=True))
