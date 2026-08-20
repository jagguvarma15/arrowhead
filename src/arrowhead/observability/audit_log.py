"""Structured audit log: one line per component call.

Redaction happens at the source. The record carries the shape of each
argument (type and size), never the value, so a secret in a URL or a
probed filesystem path cannot leak into log storage no matter what any
downstream handler or shipper does with the line.

The audited context manager is entered by the guard wrappers around every
tool call, resource read, and prompt render, so the import door and the
wire emit identical lines. A ToolError is recorded as a refusal; any other
exception is recorded as an error.
"""

import json
import logging
import time
from contextlib import asynccontextmanager

from arrowhead.auth.identity import caller_identity
from arrowhead.errors import ToolError
from arrowhead.observability.metrics import record_tool_call

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


def describe_resource(uri) -> str:
    """A resource's scheme and the shape of its path, never the path itself.

    A doc:// URI carries a caller-supplied document path; logging it verbatim
    would leak exactly the path value the rest of the log is careful to hide.
    """
    text = str(uri)
    scheme, separator, rest = text.partition("://")
    if not separator:
        return f"str[{len(text)}]"
    return f"{scheme}://str[{len(rest)}]"


def _emit(
    record: dict, metric_label: str, status: str, duration_ms: float
) -> None:
    """Serialize one audit line and record its metric, the same way for
    every path that produces one."""
    logger.info(json.dumps(record, sort_keys=True))
    record_tool_call(metric_label, status, duration_ms)


def audit_event(
    event: str, *, status: str, duration_ms: float, metric_label: str, **fields
) -> None:
    """Emit one audit line for a request path outside the guarded dispatch."""
    record = {
        "event": event,
        **fields,
        "caller": caller_identity(),
        "status": status,
        "duration_ms": duration_ms,
    }
    _emit(record, metric_label, status, duration_ms)


@asynccontextmanager
async def audited(base: dict, metric_label: str):
    """Time the enclosed call and emit exactly one audit line for it.

    The line is emitted on every outcome: success, a ToolError refusal from
    any guard or the tool body, and an unexpected error. The exception is
    re-raised untouched; classification never swallows it.
    """
    started = time.perf_counter()
    status = "ok"
    error_type = None
    try:
        yield
    except ToolError as exc:
        status = "refused"
        error_type = type(exc).__name__
        raise
    except Exception as exc:
        status = "error"
        error_type = type(exc).__name__
        raise
    finally:
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        record = {
            **base,
            "caller": caller_identity(),
            "status": status,
            "duration_ms": duration_ms,
        }
        if error_type is not None:
            record["error_type"] = error_type
        _emit(record, metric_label, status, duration_ms)
