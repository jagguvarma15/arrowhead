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

Timer tasks (task_schedule) share the registry and inherit both limitations:
a pending timer does not survive a restart, and a completed occurrence is
subject to the finished-task eviction like any other task.
"""

import asyncio
import json
import math
import secrets
from collections import OrderedDict
from dataclasses import dataclass
from typing import TypedDict

import anyio

from arrowhead.auth.identity import caller_identity
from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import ACTION_SCAN, KIND_PREFIX, Resource
from arrowhead.config import get_settings
from arrowhead.errors import ToolError
from arrowhead.security.input_validation import (
    ValidationError,
    validate_relative_path,
)

STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"

KIND_BACKGROUND = "background"
KIND_TIMER = "timer"

# Bound the number of retained tasks so a caller cannot grow the registry
# without limit; the oldest finished task is dropped first. A running task is
# never dropped: evicting one would orphan work the caller could no longer
# poll or cancel, so when every retained task is running, starting another
# is refused instead.
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


class TaskListEntry(TypedDict):
    """One owned task in a listing."""

    taskId: str
    status: str
    kind: str


class TaskListResult(TypedDict):
    """Every task the caller currently owns."""

    tasks: list[TaskListEntry]


@dataclass
class _Task:
    id: str
    owner: str
    status: str = STATUS_RUNNING
    result: dict | None = None
    error: str | None = None
    runner: asyncio.Task | None = None
    kind: str = KIND_BACKGROUND


class TaskRegistry:
    """In-process store of tasks keyed by server-minted handle."""

    def __init__(self, max_tasks: int = _MAX_TASKS) -> None:
        self._tasks: OrderedDict[str, _Task] = OrderedDict()
        self._max = max_tasks

    def create(self, owner: str, kind: str = KIND_BACKGROUND) -> _Task:
        # Make room before minting the handle, dropping the oldest finished
        # task first. With every retained task still running there is nothing
        # safe to drop, so the new task is refused and every existing handle
        # stays valid.
        while len(self._tasks) >= self._max:
            terminal = next(
                (
                    tid
                    for tid, task in self._tasks.items()
                    if task.status != STATUS_RUNNING
                ),
                None,
            )
            if terminal is None:
                raise ToolError(
                    "too many tasks are running; retry after one finishes"
                )
            del self._tasks[terminal]
        task = _Task(id=secrets.token_hex(16), owner=owner, kind=kind)
        self._tasks[task.id] = task
        return task

    def get(self, task_id: str, owner: str) -> _Task | None:
        task = self._tasks.get(task_id)
        if task is None or task.owner != owner:
            return None
        return task

    def list_for(self, owner: str) -> list[_Task]:
        """The owner's tasks, most recently created first."""
        return [
            task
            for task in reversed(self._tasks.values())
            if task.owner == owner
        ]

    def count_running(self, owner: str, kind: str) -> int:
        """How many of the owner's tasks of a kind are still running."""
        return sum(
            1
            for task in self._tasks.values()
            if task.owner == owner
            and task.kind == kind
            and task.status == STATUS_RUNNING
        )

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


async def task_list() -> TaskListResult:
    """List the task handles you own with their status and kind. Poll one
    with task_get(task_id=...). Example: task_list().
    """
    return {
        "tasks": [
            {"taskId": task.id, "status": task.status, "kind": task.kind}
            for task in _registry.list_for(caller_identity())
        ]
    }


async def task_schedule(
    delay_seconds: float,
    payload: dict,
    repeat_seconds: float | None = None,
) -> TaskHandle:
    """Schedule a timer that completes after delay_seconds carrying your
    payload; repeat_seconds respawns the next occurrence. Poll with
    task_get(task_id=...); timers do not survive a restart. Example:
    task_schedule(delay_seconds=60, payload={"note": "check build"}).
    """
    settings = get_settings()
    delay = _validated_seconds(
        delay_seconds, "delay_seconds", 0.0, settings.task_schedule_max_delay_seconds
    )
    repeat = None
    if repeat_seconds is not None:
        repeat = _validated_seconds(
            repeat_seconds,
            "repeat_seconds",
            settings.task_schedule_min_repeat_seconds,
            settings.task_schedule_max_delay_seconds,
        )
    if not isinstance(payload, dict):
        raise ToolError("payload must be an object")
    try:
        encoded = json.dumps(payload)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ToolError("payload must be JSON-serializable") from exc
    if len(encoded.encode("utf-8")) > settings.task_payload_max_bytes:
        raise ToolError(
            f"payload exceeds {settings.task_payload_max_bytes} bytes"
        )

    task = _start_timer(caller_identity(), payload, delay, repeat, settings)
    return {"taskId": task.id, "status": task.status}


def _validated_seconds(
    value, name: str, minimum: float, maximum: float
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ToolError(f"{name} must be a number")
    seconds = float(value)
    if not math.isfinite(seconds):
        raise ToolError(f"{name} must be a finite number")
    if seconds < minimum:
        raise ToolError(f"{name} must be at least {minimum}")
    if seconds > maximum:
        raise ToolError(f"{name} must be at most {maximum}")
    return seconds


def _start_timer(
    owner: str, payload: dict, delay: float, repeat: float | None, settings
) -> _Task:
    """Mint and start one timer occurrence under the per-owner cap."""
    if (
        _registry.count_running(owner, KIND_TIMER)
        >= settings.task_schedule_max_per_owner
    ):
        raise ToolError(
            "too many timers are pending; cancel one or wait for one to fire"
        )
    task = _registry.create(owner, kind=KIND_TIMER)

    async def run() -> None:
        try:
            await asyncio.sleep(delay)
        except asyncio.CancelledError:
            task.status = STATUS_CANCELLED
            return
        if task.status == STATUS_CANCELLED:
            return
        result: dict = {"payload": payload, "next_task_id": None}
        if repeat is not None:
            # Respawn the next occurrence under the same caps; a refusal
            # (cap reached, registry full) stops the recurrence and says so
            # rather than failing this occurrence.
            try:
                next_task = _start_timer(owner, payload, repeat, repeat, settings)
            except ToolError:
                result["recurrence"] = "stopped"
            else:
                result["next_task_id"] = next_task.id
        task.status = STATUS_COMPLETED
        task.result = result

    task.runner = asyncio.create_task(run())
    return task
