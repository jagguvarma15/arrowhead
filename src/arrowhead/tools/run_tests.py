"""Run a project's tests against an isolated copy of the repo subtree.

Execution is doubly opted in like run_snippet: the exec_enabled flag plus
the execute action the default policy denies. The authorized repo subtree
is copied file by file through the jail into a fresh scratch directory,
bounded by a byte budget, and the configured test command runs there, so
a test that writes never touches the real repository. Output is
secret-scanned and redacted before it leaves, inside the untrusted
framing.
"""

import shlex
from pathlib import Path

import anyio

from arrowhead.authz.enforce import authorize_action, get_authorizer
from arrowhead.authz.policy import (
    ACTION_EXECUTE,
    ACTION_READ,
    KIND_REPO_FILE,
    KIND_REPO_PREFIX,
    Resource,
)
from arrowhead.config import get_settings
from arrowhead.errors import ToolError
from arrowhead.exec.base import RunRequest
from arrowhead.exec.factory import build_runner
from arrowhead.exec.subprocess_runner import make_scratch, remove_scratch
from arrowhead.repo.store import RepoStoreError, build_repo_store
from arrowhead.security.input_validation import (
    ValidationError,
    validate_relative_path,
)
from arrowhead.tools.run_snippet import RunResult, _redacted_result


async def run_tests(path_prefix: str = "") -> RunResult:
    """Copy the authorized repository subtree into the sandbox and run the
    configured test command there, returning its bounded, secret-redacted
    output. Requires the execution feature to be enabled and granted.
    Example: run_tests(path_prefix="src/").
    """
    settings = get_settings()
    if not settings.exec_enabled:
        raise ToolError("sandboxed execution is disabled")
    if not settings.exec_test_command.strip():
        raise ToolError("no test command is configured")
    if path_prefix:
        try:
            validate_relative_path(path_prefix)
        except ValidationError as exc:
            raise ToolError(str(exc)) from exc

    subject = authorize_action(
        ACTION_EXECUTE, Resource(kind=KIND_REPO_PREFIX, identifier=path_prefix)
    )
    argv = tuple(shlex.split(settings.exec_test_command))
    if not argv:
        raise ToolError("the configured test command is empty")

    scratch = await anyio.to_thread.run_sync(
        make_scratch, settings.exec_workdir, "tests"
    )
    try:
        copied = await anyio.to_thread.run_sync(
            _copy_subtree, path_prefix, subject, scratch, settings
        )
        if copied == 0:
            raise ToolError("no authorized files to test under the prefix")
        request = RunRequest(
            argv=argv,
            cwd=scratch,
            cpu_seconds=settings.exec_cpu_seconds,
            memory_bytes=settings.exec_memory_bytes,
            wall_seconds=settings.exec_test_wall_seconds,
            max_output_bytes=settings.exec_max_output_bytes,
        )
        outcome = await build_runner(settings).run(request)
    finally:
        await anyio.to_thread.run_sync(remove_scratch, scratch)

    return _redacted_result(outcome, settings)


def _copy_subtree(path_prefix, subject, scratch: Path, settings) -> int:
    """Copy the authorized repo files under the prefix into scratch.

    Only files the caller may read individually are copied, and the copy
    stops at the byte budget, so the sandbox never holds more of the repo
    than the caller could read or the budget allows.
    """
    store = build_repo_store(settings)
    authorizer = get_authorizer()
    listing = store.list(
        max_files=settings.exec_copy_max_files,
        path_prefix=path_prefix,
    )
    budget = settings.exec_max_copy_bytes
    copied = 0
    for info in listing.items:
        if not authorizer.authorize(
            subject,
            ACTION_READ,
            Resource(kind=KIND_REPO_FILE, identifier=info.path),
        ).allowed:
            continue
        try:
            data = store.read_bytes_raw(info.path)
        except RepoStoreError:
            continue
        budget -= len(data)
        if budget < 0:
            break
        destination = scratch / info.path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        copied += 1
    return copied
