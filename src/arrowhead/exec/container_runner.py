"""A container runner for hardened deployments.

Wraps the same RunRequest in a docker invocation that adds the isolation
the subprocess runner cannot: no network, a read-only root filesystem,
and hard CPU-time, memory, and process caps enforced by the container
runtime.
The scratch directory is the only writable mount. Building the argv is
kept separate from running it so the composition is unit-testable without
a container runtime present.
"""

import asyncio
import time

from arrowhead.exec.base import RunOutcome, RunRequest
from arrowhead.exec.subprocess_runner import (
    _communicate_capped,
    _decode_capped,
)


class ContainerRunner:
    """Runs a command inside a locked-down container."""

    def __init__(self, image: str, *, docker: str = "docker") -> None:
        if not image:
            raise ValueError("the container runner needs an image")
        self._image = image
        self._docker = docker

    def build_argv(self, request: RunRequest) -> list[str]:
        """The docker argv that runs request under container isolation."""
        return [
            self._docker,
            "run",
            "--rm",
            "--interactive",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp",  # noqa: S108  # container-internal tmpfs mount, not a host path
            f"--memory={request.memory_bytes}",
            # cpu_seconds is a time budget, so it maps to RLIMIT_CPU via
            # ulimit exactly as in the subprocess runner; --cpus takes a
            # core count and would turn seconds into parallelism.
            "--cpus=1",
            f"--ulimit=cpu={max(1, request.cpu_seconds)}",
            "--pids-limit=128",
            "--volume",
            f"{request.cwd}:/work",
            "--workdir",
            "/work",
            self._image,
            *request.argv,
        ]

    async def run(self, request: RunRequest) -> RunOutcome:
        started = time.perf_counter()
        process = await asyncio.create_subprocess_exec(
            *self.build_argv(request),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
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
