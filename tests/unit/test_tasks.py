"""The handle-based task primitive: a start tool returns a handle immediately,
the work runs in the background, and only the owner can poll or cancel it.
"""

import pytest

from arrowhead.auth.principal import as_principal
from arrowhead.connectors.tasks import (
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    get_registry,
    scan_corpus_async,
    task_get,
    task_update,
)
from arrowhead.errors import ToolError


async def test_task_runs_to_completion_and_returns_the_result(docs):
    (docs / "a.md").write_text("hello world")
    with as_principal("alice", {"docs:scan", "tasks:read"}):
        handle = await scan_corpus_async("")
        assert handle["status"] == "running"
        await get_registry().join(handle["taskId"])
        status = await task_get(handle["taskId"])
    assert status["status"] == STATUS_COMPLETED
    assert status["result"]["files_scanned"] == 1


async def test_a_task_is_not_visible_to_another_subject(docs):
    (docs / "a.md").write_text("hello")
    with as_principal("alice", {"docs:scan"}):
        handle = await scan_corpus_async("")
        await get_registry().join(handle["taskId"])
    # bob cannot read alice's task; it is reported as simply not found
    with as_principal("bob", {"tasks:read"}):
        with pytest.raises(ToolError):
            await task_get(handle["taskId"])


async def test_cancel_moves_a_running_task_to_a_terminal_state(docs):
    (docs / "a.md").write_text("hello")
    with as_principal("alice", {"docs:scan", "tasks:read", "tasks:write"}):
        handle = await scan_corpus_async("")
        # The background runner has not been scheduled yet, so the task is
        # still running and the cancel takes effect.
        updated = await task_update(handle["taskId"], "cancel")
        assert updated["status"] == STATUS_CANCELLED
        await get_registry().join(handle["taskId"])
        final = await task_get(handle["taskId"])
    assert final["status"] == STATUS_CANCELLED


async def test_unknown_task_action_is_refused(docs):
    with as_principal("alice", {"docs:scan", "tasks:write"}):
        handle = await scan_corpus_async("")
        await get_registry().join(handle["taskId"])
        with pytest.raises(ToolError):
            await task_update(handle["taskId"], "pause")
