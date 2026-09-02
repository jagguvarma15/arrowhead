"""Timer tasks: completion, recurrence, bounds, and cancellation.

Every test joins or cancels the timers it spawns so no pending sleep
leaks into another test; owners are unique per test because the task
registry is process-global and has no autouse reset.
"""

import pytest

from arrowhead.auth.principal import as_principal
from arrowhead.connectors.tasks import (
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    get_registry,
    task_get,
    task_list,
    task_schedule,
    task_update,
)
from arrowhead.errors import ToolError

SCOPES = {"tasks:read", "tasks:write"}


async def test_timer_completes_carrying_the_payload():
    with as_principal("timer-owner-1", SCOPES):
        handle = await task_schedule(
            delay_seconds=0.01, payload={"note": "check build"}
        )
        assert handle["status"] == "running"
        await get_registry().join(handle["taskId"])
        status = await task_get(handle["taskId"])
    assert status["status"] == STATUS_COMPLETED
    assert status["result"] == {
        "payload": {"note": "check build"},
        "next_task_id": None,
    }


async def test_timers_are_listed_with_their_kind():
    with as_principal("timer-owner-2", SCOPES):
        handle = await task_schedule(delay_seconds=60, payload={})
        listing = await task_list()
        entry = next(
            item
            for item in listing["tasks"]
            if item["taskId"] == handle["taskId"]
        )
        assert entry["kind"] == "timer"
        await task_update(handle["taskId"], "cancel")
        await get_registry().join(handle["taskId"])


async def test_recurrence_respawns_the_next_occurrence(configure_env):
    configure_env(ARROWHEAD_TASK_SCHEDULE_MIN_REPEAT_SECONDS="0.01")
    with as_principal("timer-owner-3", SCOPES):
        handle = await task_schedule(
            delay_seconds=0.01, payload={"n": 1}, repeat_seconds=0.01
        )
        await get_registry().join(handle["taskId"])
        status = await task_get(handle["taskId"])
        next_id = status["result"]["next_task_id"]
        assert next_id is not None
        await task_update(next_id, "cancel")
        await get_registry().join(next_id)


async def test_recurrence_stops_when_the_cap_refuses_the_respawn(
    configure_env,
):
    configure_env(ARROWHEAD_TASK_SCHEDULE_MIN_REPEAT_SECONDS="0.01")
    with as_principal("timer-owner-4", SCOPES):
        handle = await task_schedule(
            delay_seconds=0.01, payload={}, repeat_seconds=0.01
        )
        # The cap drops to zero before the timer fires, so the respawn is
        # refused and the occurrence reports the recurrence stopped.
        configure_env(ARROWHEAD_TASK_SCHEDULE_MAX_PER_OWNER="0")
        await get_registry().join(handle["taskId"])
        status = await task_get(handle["taskId"])
    assert status["status"] == STATUS_COMPLETED
    assert status["result"]["next_task_id"] is None
    assert status["result"]["recurrence"] == "stopped"


async def test_cancel_stops_a_pending_timer():
    with as_principal("timer-owner-5", SCOPES):
        handle = await task_schedule(delay_seconds=60, payload={})
        updated = await task_update(handle["taskId"], "cancel")
        assert updated["status"] == STATUS_CANCELLED
        await get_registry().join(handle["taskId"])
        final = await task_get(handle["taskId"])
    assert final["status"] == STATUS_CANCELLED


async def test_delay_and_repeat_bounds_are_enforced(configure_env):
    configure_env(ARROWHEAD_TASK_SCHEDULE_MAX_DELAY_SECONDS="100")
    with as_principal("timer-owner-6", SCOPES):
        with pytest.raises(ToolError):
            await task_schedule(delay_seconds=-1, payload={})
        with pytest.raises(ToolError):
            await task_schedule(delay_seconds=101, payload={})
        with pytest.raises(ToolError):
            await task_schedule(delay_seconds=float("nan"), payload={})
        with pytest.raises(ToolError):
            await task_schedule(delay_seconds=True, payload={})
        with pytest.raises(ToolError):
            await task_schedule(
                delay_seconds=1, payload={}, repeat_seconds=0.5
            )


async def test_payload_shape_and_size_are_enforced(configure_env):
    configure_env(ARROWHEAD_TASK_PAYLOAD_MAX_BYTES="32")
    with as_principal("timer-owner-7", SCOPES):
        with pytest.raises(ToolError):
            await task_schedule(delay_seconds=1, payload="not an object")
        with pytest.raises(ToolError):
            await task_schedule(delay_seconds=1, payload={"big": "x" * 64})
        with pytest.raises(ToolError):
            await task_schedule(delay_seconds=1, payload={"bad": object()})


async def test_per_owner_timer_cap_is_enforced(configure_env):
    configure_env(ARROWHEAD_TASK_SCHEDULE_MAX_PER_OWNER="1")
    with as_principal("timer-owner-8", SCOPES):
        handle = await task_schedule(delay_seconds=60, payload={})
        with pytest.raises(ToolError):
            await task_schedule(delay_seconds=60, payload={})
        await task_update(handle["taskId"], "cancel")
        await get_registry().join(handle["taskId"])
    # Another owner is unaffected by this owner's cap usage.
    with as_principal("timer-owner-9", SCOPES):
        other = await task_schedule(delay_seconds=60, payload={})
        await task_update(other["taskId"], "cancel")
        await get_registry().join(other["taskId"])