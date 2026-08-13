"""Adversarial coverage for the sandboxed execution surface.

A resource-hungry snippet is bounded rather than allowed to exhaust the
host, huge output is capped, a fork bomb is contained by the wall clock
and process cap, and run_tests can neither escape its scratch copy nor
write into the real repository.
"""

import sys

import pytest

from arrowhead.config import get_settings
from arrowhead.errors import ToolError
from arrowhead.tools.run_snippet import run_snippet
from arrowhead.tools.run_tests import run_tests


@pytest.fixture
def exec_on(tmp_path, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_EXEC_ENABLED", "true")
    monkeypatch.setenv("ARROWHEAD_EXEC_WORKDIR", str(tmp_path / "scratch"))
    get_settings.cache_clear()
    return tmp_path


async def test_infinite_output_is_capped(exec_on, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_EXEC_MAX_OUTPUT_BYTES", "2000")
    monkeypatch.setenv("ARROWHEAD_EXEC_WALL_SECONDS", "5")
    get_settings.cache_clear()
    result = await run_snippet(
        "import sys\nwhile True:\n    sys.stdout.write('x' * 1000)"
    )
    assert len(result["stdout"].encode("utf-8")) <= 2000
    assert result["truncated"] is True


async def test_sleeping_snippet_is_stopped_by_the_wall_clock(
    exec_on, monkeypatch
):
    monkeypatch.setenv("ARROWHEAD_EXEC_WALL_SECONDS", "1")
    get_settings.cache_clear()
    result = await run_snippet("import time; time.sleep(60)")
    assert result["timed_out"] is True
    assert result["exit_code"] is None


async def test_fork_bomb_is_contained(exec_on, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_EXEC_WALL_SECONDS", "5")
    get_settings.cache_clear()
    # A process-spawning loop is bounded by the process cap and the wall
    # clock; the call returns a result rather than taking down the host.
    result = await run_snippet(
        "import os\n"
        "while True:\n"
        "    try:\n"
        "        os.fork()\n"
        "    except OSError:\n"
        "        pass"
    )
    assert isinstance(result["timed_out"], bool)
    assert "exit_code" in result


async def test_run_tests_cannot_reach_outside_the_repo(exec_on, monkeypatch):
    repo = exec_on / "repo"
    repo.mkdir()
    (repo / "keep.txt").write_text("data\n")
    secret = exec_on / "secret.txt"
    secret.write_text("top secret\n")
    monkeypatch.setenv("ARROWHEAD_REPO_ROOT", str(repo))
    # A test command that tries to read a sibling of the repo sees nothing:
    # only the copied subtree exists in the scratch cwd.
    monkeypatch.setenv(
        "ARROWHEAD_EXEC_TEST_COMMAND",
        f"{sys.executable} -I -S -c "
        "\"import os; print(sorted(os.listdir('.')))\"",
    )
    get_settings.cache_clear()
    result = await run_tests()
    assert "keep.txt" in result["stdout"]
    assert "secret.txt" not in result["stdout"]


async def test_run_tests_writes_never_touch_the_repo(exec_on, monkeypatch):
    repo = exec_on / "repo"
    repo.mkdir()
    (repo / "keep.txt").write_text("data\n")
    monkeypatch.setenv("ARROWHEAD_REPO_ROOT", str(repo))
    monkeypatch.setenv(
        "ARROWHEAD_EXEC_TEST_COMMAND",
        f"{sys.executable} -I -S -c "
        "\"open('written.txt', 'w').write('side effect')\"",
    )
    get_settings.cache_clear()
    before = {p.name for p in repo.iterdir()}
    await run_tests()
    after = {p.name for p in repo.iterdir()}
    assert before == after == {"keep.txt"}


async def test_traversal_prefix_is_refused(exec_on, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_REPO_ROOT", str(exec_on / "repo"))
    (exec_on / "repo").mkdir()
    monkeypatch.setenv(
        "ARROWHEAD_EXEC_TEST_COMMAND", f"{sys.executable} -c 'pass'"
    )
    get_settings.cache_clear()
    with pytest.raises(ToolError):
        await run_tests(path_prefix="../../etc")
