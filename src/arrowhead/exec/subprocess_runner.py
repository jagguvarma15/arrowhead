"""A subprocess runner bounded by OS resource limits.

The command runs in a fresh process group with a scrubbed environment, so
no ARROWHEAD_ configuration and no ambient secrets are inherited. CPU
time, address space, file size, open files, and process count are capped
through setrlimit in a preexec hook, wall time is enforced by killing the
whole process group, and output is read incrementally: the moment either
stream exceeds the cap the run is killed and marked truncated, so a
flooding child can neither fill server memory nor hold the wall clock
open. The command is always an explicit argv, never a shell string, so
there is no shell to inject into.

What this runner does NOT do: it does not block network egress or
filesystem reads beyond ordinary OS permissions. A deployment that needs
those isolated uses the container runner. RLIMIT_AS is unreliable on
macOS, so memory bounding is best effort there and dependable on Linux.
"""

import asyncio
import os
import resource
import shutil
import signal
import time
from pathlib import Path

from arrowhead.exec.base import RunOutcome, RunRequest

# The only environment a bounded process inherits: enough to find a Python
# interpreter and a home, nothing that could carry configuration or a secret.
_BASE_ENV = {
    "PATH": "/usr/bin:/bin:/usr/local/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}


class SubprocessRunner:
    """Runs a command in a resource-bounded child process."""

    async def run(self, request: RunRequest) -> RunOutcome:
        started = time.perf_counter()
        env = {**_BASE_ENV, "HOME": str(request.cwd), **dict(request.env)}
        process = await asyncio.create_subprocess_exec(
            *request.argv,
            cwd=str(request.cwd),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            start_new_session=True,
            preexec_fn=_apply_limits(request),
        )
        stdout, stderr, timed_out = await _communicate_capped(
            process,
            request.stdin.encode("utf-8"),
            request.wall_seconds,
            request.max_output_bytes,
        )
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        out_text, out_truncated = _decode_capped(
            stdout, request.max_output_bytes
        )
        err_text, err_truncated = _decode_capped(
            stderr, request.max_output_bytes
        )
        return RunOutcome(
            exit_code=None if timed_out else process.returncode,
            stdout=out_text,
            stderr=err_text,
            duration_ms=duration_ms,
            timed_out=timed_out,
            truncated=out_truncated or err_truncated,
        )


def _apply_limits(request: RunRequest):
    """A preexec hook installing the child's resource limits.

    Runs in the forked child before exec, so it can call setrlimit on the
    process that is about to become the command.
    """

    def preexec() -> None:
        _set(resource.RLIMIT_CPU, request.cpu_seconds)
        _set(resource.RLIMIT_FSIZE, request.max_output_bytes * 4)
        _set(resource.RLIMIT_NOFILE, 64)
        # A hard process cap turns a fork bomb into a bounded failure. macOS
        # exposes no RLIMIT_NPROC constant on some builds, so it is optional.
        nproc = getattr(resource, "RLIMIT_NPROC", None)
        if nproc is not None:
            _set(nproc, 64)
        if request.memory_bytes:
            addr = getattr(resource, "RLIMIT_AS", None)
            if addr is not None:
                _set(addr, request.memory_bytes)

    return preexec


def _set(which: int, value: int) -> None:
    try:
        resource.setrlimit(which, (value, value))
    except (ValueError, OSError):
        # A limit the platform will not accept is skipped rather than
        # aborting the run; wall time and output caps still apply.
        pass


def _kill_group(process) -> None:
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


async def _communicate_capped(
    process, stdin_bytes: bytes, wall_seconds: float, cap: int
) -> tuple[bytes, bytes, bool]:
    """Feed stdin and collect both streams, stopping runaway output early.

    Each stream is read in chunks and only the first cap + 1 bytes are
    kept; the moment either stream exceeds the cap the whole process
    group is killed. A cap kill leaves timed_out False and surfaces the
    signal as a negative exit code; only the wall clock sets timed_out.
    """

    async def feed() -> None:
        try:
            process.stdin.write(stdin_bytes)
            await process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            process.stdin.close()

    async def read_capped(stream) -> bytes:
        chunks: list[bytes] = []
        collected = 0
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                return b"".join(chunks)
            if collected <= cap:
                keep = chunk[: cap + 1 - collected]
                chunks.append(keep)
                collected += len(keep)
            if collected > cap:
                _kill_group(process)

    feeder = asyncio.ensure_future(feed())
    timed_out = False
    try:
        stdout, stderr = await asyncio.wait_for(
            asyncio.gather(
                read_capped(process.stdout), read_capped(process.stderr)
            ),
            timeout=wall_seconds,
        )
    except TimeoutError:
        timed_out = True
        _kill_group(process)
        stdout, stderr = await asyncio.gather(
            read_capped(process.stdout), read_capped(process.stderr)
        )
    await asyncio.gather(feeder, return_exceptions=True)
    await process.wait()
    return stdout, stderr, timed_out


def _decode_capped(data: bytes, cap: int) -> tuple[str, bool]:
    truncated = len(data) > cap
    return data[:cap].decode("utf-8", errors="replace"), truncated


def make_scratch(root: Path, name: str) -> Path:
    """Create an empty scratch directory for one run under the exec root."""
    root.mkdir(parents=True, exist_ok=True)
    scratch = root / name
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True)
    return scratch


def remove_scratch(scratch: Path) -> None:
    """Remove a run's scratch directory, ignoring an already-gone tree."""
    shutil.rmtree(scratch, ignore_errors=True)
