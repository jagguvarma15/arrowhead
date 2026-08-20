"""The exec tools: double opt-in, redaction, and the container argv."""

import sys

import pytest

from arrowhead.config import Settings, get_settings
from arrowhead.errors import ToolError
from arrowhead.exec.base import RunOutcome, RunRequest
from arrowhead.tools.run_snippet import run_snippet
from arrowhead.tools.run_tests import run_tests


@pytest.fixture
def exec_on(tmp_path, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_EXEC_ENABLED", "true")
    monkeypatch.setenv("ARROWHEAD_EXEC_WORKDIR", str(tmp_path / "scratch"))
    get_settings.cache_clear()
    return tmp_path


async def test_disabled_by_default_refuses(tmp_path, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_EXEC_WORKDIR", str(tmp_path / "scratch"))
    get_settings.cache_clear()
    with pytest.raises(ToolError, match="disabled"):
        await run_snippet("print(1)")


async def test_execute_action_denied_by_default_policy(exec_on, monkeypatch):
    from arrowhead.authz.enforce import get_authorizer

    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    get_settings.cache_clear()
    get_authorizer.cache_clear()
    # exec_enabled is on, but the default policy grants no execute action,
    # so a snippet is still denied: the two opt-ins are independent.
    with pytest.raises(ToolError, match="not authorized"):
        await run_snippet("print(1)")
    get_authorizer.cache_clear()


async def test_snippet_runs_and_returns_bounded_output(exec_on):
    result = await run_snippet("print('two plus two is', 2 + 2)")
    assert result["exit_code"] == 0
    assert "two plus two is 4" in result["stdout"]
    assert result["timed_out"] is False
    assert "untrusted" in result["notice"]


async def test_snippet_output_is_secret_redacted(exec_on):
    result = await run_snippet(
        "print('key = AKIAIOSFODNN7EXAMPLE')"
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in result["stdout"]
    assert "[REDACTED:AWS_ACCESS_KEY" in result["stdout"]
    assert result["redactions"] >= 1


async def test_snippet_rejects_empty_and_oversized(exec_on, monkeypatch):
    with pytest.raises(ToolError):
        await run_snippet("")
    monkeypatch.setenv("ARROWHEAD_EXEC_MAX_CODE_BYTES", "8")
    get_settings.cache_clear()
    with pytest.raises(ToolError, match="exceeds"):
        await run_snippet("print('a very long snippet indeed')")


async def test_run_tests_needs_a_command(exec_on, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_REPO_ROOT", str(exec_on / "repo"))
    (exec_on / "repo").mkdir()
    get_settings.cache_clear()
    with pytest.raises(ToolError, match="no test command"):
        await run_tests()


async def test_run_tests_copies_the_subtree_and_runs_there(
    exec_on, monkeypatch
):
    repo = exec_on / "repo"
    repo.mkdir()
    (repo / "answer.txt").write_text("42\n")
    monkeypatch.setenv("ARROWHEAD_REPO_ROOT", str(repo))
    # The command reads the copied file from the scratch cwd and, to prove
    # writes stay in the sandbox, creates a file there too.
    monkeypatch.setenv(
        "ARROWHEAD_EXEC_TEST_COMMAND",
        f"{sys.executable} -I -S -c "
        "\"print('loaded', open('answer.txt').read().strip()); "
        "open('generated.txt', 'w').write('x')\"",
    )
    get_settings.cache_clear()
    result = await run_tests()
    assert result["exit_code"] == 0
    assert "loaded 42" in result["stdout"]
    # The real repo is untouched: the test's write landed in the sandbox,
    # not in the source tree.
    assert {p.name for p in repo.iterdir()} == {"answer.txt"}


async def test_copy_file_cap_is_the_exec_setting(exec_on, monkeypatch):
    repo = exec_on / "repo"
    repo.mkdir()
    (repo / "a.txt").write_text("a\n")
    (repo / "b.txt").write_text("b\n")
    monkeypatch.setenv("ARROWHEAD_REPO_ROOT", str(repo))
    # The sandbox copy is governed by its own cap, not by the symbol-map
    # file limit it once borrowed.
    monkeypatch.setenv("ARROWHEAD_EXEC_COPY_MAX_FILES", "1")
    monkeypatch.setenv("ARROWHEAD_SYMBOL_MAP_MAX_FILES", "50")
    monkeypatch.setenv(
        "ARROWHEAD_EXEC_TEST_COMMAND",
        f"{sys.executable} -I -S -c "
        "\"import os; print('copied', len(os.listdir('.')))\"",
    )
    get_settings.cache_clear()
    result = await run_tests()
    assert "copied 1" in result["stdout"]


def test_container_runner_builds_a_locked_down_argv():
    from arrowhead.exec.container_runner import ContainerRunner

    runner = ContainerRunner("python:3.12-slim")
    argv = runner.build_argv(
        RunRequest(
            argv=("python", "-c", "print(1)"),
            cwd=Settings().exec_workdir,
            memory_bytes=256_000_000,
            cpu_seconds=2,
        )
    )
    joined = " ".join(argv)
    assert "--network none" in joined
    assert "--read-only" in joined
    assert "--memory=256000000" in joined
    # The CPU budget is seconds of CPU time, enforced as a ulimit; it must
    # never surface as a --cpus core count.
    assert "--ulimit=cpu=2" in joined
    assert "--cpus=1" in joined
    assert "--cpus=2" not in joined
    assert "--pids-limit=128" in joined
    assert argv[-3:] == ["python", "-c", "print(1)"]


def test_outcome_shape_is_stable():
    outcome = RunOutcome(
        exit_code=0,
        stdout="x",
        stderr="",
        duration_ms=1.0,
        timed_out=False,
        truncated=False,
    )
    assert outcome.exit_code == 0
