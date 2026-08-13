"""Build the configured runner."""

from arrowhead.config import Settings
from arrowhead.exec.base import Runner


def build_runner(settings: Settings) -> Runner:
    if settings.exec_runner == "container":
        from arrowhead.exec.container_runner import ContainerRunner

        return ContainerRunner(settings.exec_container_image)
    from arrowhead.exec.subprocess_runner import SubprocessRunner

    return SubprocessRunner()
