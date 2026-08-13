"""The subprocess runner: exit codes, caps, env scrubbing, and timeouts.

Tolerances are generous because resource-limit and process-group
semantics differ between macOS and Linux; the properties asserted (a
bound stops the run, output is capped, the environment is scrubbed) hold
on both, while exact timing does not.
"""

import sys
import time

import pytest

from arrowhead.exec.base import RunRequest
from arrowhead.exec.subprocess_runner import (
    SubprocessRunner,
    make_scratch,
    remove_scratch,
)


@pytest.fixture
def scratch(tmp_path):
    path = make_scratch(tmp_path, "run")
    yield path
    remove_scratch(path)


def python_request(scratch, code, **overrides):
    request = {
        "argv": (sys.executable, "-I", "-S", "-c", code),
        "cwd": scratch,
        "cpu_seconds": 5,
        "wall_seconds": 10.0,
        "max_output_bytes": 1000,
    }
    request.update(overrides)
    return RunRequest(**request)


async def test_exit_code_and_stdout(scratch):
    outcome = await SubprocessRunner().run(
        python_request(scratch, "print('hello'); print('world')")
    )
    assert outcome.exit_code == 0
    assert "hello" in outcome.stdout
    assert outcome.timed_out is False


async def test_nonzero_exit_is_reported(scratch):
    outcome = await SubprocessRunner().run(
        python_request(scratch, "import sys; sys.exit(3)")
    )
    assert outcome.exit_code == 3


async def test_stdin_is_delivered(scratch):
    outcome = await SubprocessRunner().run(
        python_request(
            scratch, "import sys; print(sys.stdin.read().upper())", stdin="abc"
        )
    )
    assert "ABC" in outcome.stdout


async def test_output_is_capped_and_flagged(scratch):
    outcome = await SubprocessRunner().run(
        python_request(
            scratch, "print('x' * 100000)", max_output_bytes=500
        )
    )
    assert len(outcome.stdout.encode("utf-8")) <= 500
    assert outcome.truncated is True


async def test_environment_is_scrubbed(scratch, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_SECRET_MARKER", "must-not-leak")
    outcome = await SubprocessRunner().run(
        python_request(
            scratch,
            "import os; print([k for k in os.environ if k.startswith"
            "('ARROWHEAD')])",
        )
    )
    assert "ARROWHEAD" not in outcome.stdout
    assert "must-not-leak" not in outcome.stdout


async def test_wall_timeout_kills_a_sleeper(scratch):
    started = time.perf_counter()
    outcome = await SubprocessRunner().run(
        python_request(
            scratch, "import time; time.sleep(30)", wall_seconds=1.0
        )
    )
    assert outcome.timed_out is True
    assert outcome.exit_code is None
    assert time.perf_counter() - started < 10


@pytest.mark.skipif(
    sys.platform == "darwin", reason="RLIMIT_CPU delivery is unreliable on macOS"
)
async def test_cpu_limit_stops_a_spin_loop(scratch):
    outcome = await SubprocessRunner().run(
        python_request(
            scratch,
            "x = 0\nwhile True:\n    x += 1",
            cpu_seconds=1,
            wall_seconds=20.0,
        )
    )
    # The CPU limit terminates the process well before the wall clock.
    assert outcome.timed_out is False
    assert outcome.exit_code not in (0, None)
