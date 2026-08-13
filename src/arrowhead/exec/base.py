"""The runner seam and its request and outcome shapes.

A runner takes a fully specified request (argv, stdin, working directory,
and every resource bound) and returns a structured outcome. Timing out or
being killed by a resource limit is an ordinary outcome, not an
exception, so a caller always gets a result to report rather than a
crash. The seam mirrors the embeddings and completion providers: a small
protocol with concrete implementations chosen by configuration.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class RunRequest:
    """Everything a runner needs to execute one command under bounds."""

    argv: tuple[str, ...]
    cwd: Path
    stdin: str = ""
    env: Mapping[str, str] = field(default_factory=dict)
    cpu_seconds: int = 10
    memory_bytes: int = 512_000_000
    wall_seconds: float = 30.0
    max_output_bytes: int = 200_000


@dataclass(frozen=True)
class RunOutcome:
    """The structured result of a run, including whether a bound stopped it."""

    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool
    truncated: bool


class Runner(Protocol):
    """Executes a bounded command and returns its outcome."""

    async def run(self, request: RunRequest) -> RunOutcome: ...
