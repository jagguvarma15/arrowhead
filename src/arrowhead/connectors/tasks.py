"""Handle-based asynchronous tasks (the 2026-07-28 stateless pattern).

Long-running work is exposed as ordinary guarded tools that pass a server-minted
task handle as an argument, rather than as a protocol-level session. A start
tool authorizes the work, mints a handle, runs the work in the background, and
returns the handle immediately; task_get polls a task the caller owns and
task_update cancels one. Ownership is enforced server-side from the caller's
identity, so a caller can only ever see or cancel its own tasks, and a task id
it does not own is reported as simply not found.

The registry lives in process, so a task is visible only on the instance that
created it. That is the documented single-instance limitation; the interface is
shaped so a shared backend (the rate limiter's Redis) can hold task state for a
multi-instance deployment later, the same recipe the other connectors follow.
This mirrors the redesigned MCP tasks extension without adopting its wire, which
the stable SDK does not speak.
"""

import asyncio
import secrets
from collections import OrderedDict
from dataclasses import dataclass
from typing import TypedDict

import anyio
from arrowhead.errors import ToolError

from arrowhead.auth.identity import caller_identity
from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import ACTION_SCAN, KIND_PREFIX, Resource
from arrowhead.config import get_settings
from arrowhead.security.input_validation import (
    ValidationError,
    validate_relative_path,
)

STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"

# Bound the number of retained tasks so a caller cannot grow the registry
# without limit; the oldest finished task is dropped first, never a running one.
_MAX_TASKS = 1000


class TaskHandle(TypedDict):
    """The handle a start tool returns immediately."""

    taskId: str
    status: str


class TaskStatus(TypedDict):
    """A task's current state, and its result once it has finished."""

    taskId: str
    status: str
    result: dict | None
    error: str | None


@dataclass
class _Task:
    id: str
    owner: str
    status: str = STATUS_RUNNING
    result: dict | None = None
    error: str | None = None
    runner: asyncio.Task | None = None


class TaskRegistry:
    """In-process store of tasks keyed by server-minted handle."""

    def __init__(self, max_tasks: int = _MAX_TASKS) -> None:
        self._tasks: OrderedDict[str, _Task] = OrderedDict()
        self._max = max_tasks

    def create(self, owner: str) -> _Task:
        task = _Task(id=secrets.token_hex(16), owner=owner)
        self._tasks[task.id] = task
        self._evict()
        return task

    def get(self, task_id: str, owner: str) -> _Task | None:
        task = self._tasks.get(task_id)
        if task is None or task.owner != owner:
            return None
        return task

    def _evict(self) -> None:
        while len(self._tasks) > self._max:
            terminal = next(
                (
                    tid
                    for tid, task in self._tasks.items()
                    if task.status != STATUS_RUNNING
                ),
                None,
            )
            if terminal is not None:
                del self._tasks[terminal]
            else:
                self._tasks.popitem(last=False)

    async def join(self, task_id: str) -> None:
        """Await a task's background runner. For in-process callers and tests."""
        task = self._tasks.get(task_id)
        if task is not None and task.runner is not None:
            await asyncio.shield(_swallow_cancel(task.runner))


async def _swallow_cancel(runner: asyncio.Task) -> None:
    try:
        await runner
    except asyncio.CancelledError:
        pass


_registry = TaskRegistry()


def get_registry() -> TaskRegistry:
    return _registry


async def scan_corpus_async(path_prefix: str = "") -> TaskHandle:
    """Start a background secrets-and-PII scan of the corpus (or a path prefix)
    and return a task handle immediately. Poll it with task_get(task_id=...) and
    cancel it with task_update(task_id=..., action="cancel"). Example:
    scan_corpus_async(path_prefix="exports/").
    """
    settings = get_settings()
    try:
        if path_prefix:
            validate_relative_path(path_prefix)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc

    # Authorize the scan up front and capture the resulting subject: the
    # background runner has no live token, so it cannot re-derive the caller.
    subject = authorize_action(
        ACTION_SCAN, Resource(kind=KIND_PREFIX, identifier=path_prefix)
    )
    task = _registry.create(subject)

    async def run() -> None:
        from arrowhead.tools.doc_scan import _run_scan

        try:
            result = await anyio.to_thread.run_sync(
                _run_scan, path_prefix, subject, settings
            )
        except asyncio.CancelledError:
            task.status = STATUS_CANCELLED
            return
        except Exception:
            task.status = STATUS_FAILED
            task.error = "the task failed"
            return
        if task.status != STATUS_CANCELLED:
            task.status = STATUS_COMPLETED
            task.result = result

    task.runner = asyncio.create_task(run())
    return {"taskId": task.id, "status": task.status}


async def task_get(task_id: str) -> TaskStatus:
    """Return the status of a task you started, and its result once it has
    finished. A task id you do not own is reported as not found. Example:
    task_get(task_id="3f2a...").
    """
    task = _registry.get(task_id, caller_identity())
    if task is None:
        raise ToolError("task not found")
    return {
        "taskId": task.id,
        "status": task.status,
        "result": task.result,
        "error": task.error,
    }


async def task_update(task_id: str, action: str) -> TaskStatus:
    """Update a task you started. The only action is "cancel", which stops a
    running task. A task id you do not own is reported as not found. Example:
    task_update(task_id="3f2a...", action="cancel").
    """
    task = _registry.get(task_id, caller_identity())
    if task is None:
        raise ToolError("task not found")
    if action != "cancel":
        raise ToolError("unknown task action")
    if task.status == STATUS_RUNNING:
        task.status = STATUS_CANCELLED
        if task.runner is not None:
            task.runner.cancel()
    return {
        "taskId": task.id,
        "status": task.status,
        "result": task.result,
        "error": task.error,
    }
