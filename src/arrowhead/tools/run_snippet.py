"""Run a Python snippet in the sandbox, doubly opted in and scrubbed.

Execution requires both the exec_enabled flag and the execute action the
default policy denies, so a snippet cannot run unless a deployment
allowed it twice. The code runs through the configured runner in a fresh
scratch directory under a scrubbed environment, bounded in CPU, memory,
wall time, and output. The interpreter runs isolated (-I) with no site
packages (-S). Output is secret-scanned and redacted before it leaves, so
a value the snippet prints does not exfiltrate a real secret, and it is
returned inside the untrusted framing.
"""

import sys
from typing import TypedDict

import anyio

from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import ACTION_EXECUTE, KIND_TABLELESS, Resource
from arrowhead.config import get_settings
from arrowhead.content.provenance import UNTRUSTED_NOTICE
from arrowhead.content.text_safe import sanitize_text
from arrowhead.errors import ToolError
from arrowhead.exec.base import RunRequest
from arrowhead.exec.factory import build_runner
from arrowhead.exec.subprocess_runner import make_scratch, remove_scratch
from arrowhead.security.secret_scan import redact_text


class RunResult(TypedDict):
    """The bounded, redacted outcome of a sandboxed run."""

    notice: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool
    truncated: bool
    redactions: int


async def run_snippet(code: str, stdin: str = "") -> RunResult:
    """Run a short Python snippet in the sandbox and return its bounded,
    secret-redacted output. Requires the execution feature to be enabled and
    granted. Example: run_snippet(code="print(2 + 2)").
    """
    settings = get_settings()
    if not settings.exec_enabled:
        raise ToolError("sandboxed execution is disabled")
    if not isinstance(code, str) or not code.strip():
        raise ToolError("code must be a non-empty string")
    if len(code.encode("utf-8")) > settings.exec_max_code_bytes:
        raise ToolError(
            f"code exceeds {settings.exec_max_code_bytes} bytes"
        )
    if not isinstance(stdin, str):
        raise ToolError("stdin must be a string")

    # Execution is its own action the default policy denies, so a
    # deployment grants it explicitly on top of the enable flag.
    authorize_action(
        ACTION_EXECUTE, Resource(kind=KIND_TABLELESS, identifier="run_snippet")
    )

    scratch = await anyio.to_thread.run_sync(
        make_scratch, settings.exec_workdir, "snippet"
    )
    try:
        request = RunRequest(
            argv=(sys.executable, "-I", "-S", "-c", code),
            cwd=scratch,
            stdin=stdin,
            cpu_seconds=settings.exec_cpu_seconds,
            memory_bytes=settings.exec_memory_bytes,
            wall_seconds=settings.exec_wall_seconds,
            max_output_bytes=settings.exec_max_output_bytes,
        )
        outcome = await build_runner(settings).run(request)
    finally:
        await anyio.to_thread.run_sync(remove_scratch, scratch)

    return _redacted_result(outcome, settings)


def _redacted_result(outcome, settings) -> RunResult:
    cap = settings.scan_max_findings
    stdout, out_hits = redact_text(sanitize_text(outcome.stdout), max_findings=cap)
    stderr, err_hits = redact_text(sanitize_text(outcome.stderr), max_findings=cap)
    return {
        "notice": UNTRUSTED_NOTICE,
        "exit_code": outcome.exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "duration_ms": outcome.duration_ms,
        "timed_out": outcome.timed_out,
        "truncated": outcome.truncated,
        "redactions": out_hits + err_hits,
    }
