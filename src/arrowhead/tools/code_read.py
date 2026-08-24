"""Read a file from the jailed repository, line-sliced and framed.

Validates the path, authorizes the read against the repo namespace, then
reads through the store that enforces containment, the byte cap, and the
binary refusal. An optional line range slices the sanitized text so a
caller pays context only for the span it needs, and the result carries
the line span in its provenance metadata.
"""

import anyio

from arrowhead.authz.enforce import authorize_action
from arrowhead.authz.policy import ACTION_READ, KIND_REPO_FILE, Resource
from arrowhead.config import get_settings
from arrowhead.content.provenance import ProvenancedResult, wrap_content
from arrowhead.content.text_safe import sanitize_text
from arrowhead.errors import ToolError
from arrowhead.repo.store import RepoStoreError, build_repo_store
from arrowhead.security.input_validation import (
    ValidationError,
    validate_relative_path,
)


async def code_read(
    path: str, start_line: int = 1, end_line: int = 0
) -> ProvenancedResult:
    """Read a repository file by relative path, optionally sliced to a line
    range; end_line 0 means to the end. Returns sanitized text wrapped with
    provenance. Example: code_read(path="src/app.py", start_line=10,
    end_line=40).
    """
    settings = get_settings()
    try:
        validate_relative_path(path)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc
    start, end = _validated_range(start_line, end_line)
    allowed = settings.repo_allowed_extension_set()
    if allowed and not path.lower().endswith(tuple(allowed)):
        raise ToolError("file extension is not allowed")

    authorize_action(ACTION_READ, Resource(kind=KIND_REPO_FILE, identifier=path))

    store = build_repo_store(settings)
    try:
        text = await anyio.to_thread.run_sync(store.read_text, path)
    except RepoStoreError as exc:
        raise ToolError(str(exc)) from exc

    lines = sanitize_text(text).splitlines()
    last = len(lines) if end == 0 else min(end, len(lines))
    sliced = "\n".join(lines[start - 1 : last])
    return wrap_content(
        sliced,
        source=f"{path}:{start}-{last}",
        content_format="text",
    )


def _validated_range(start_line, end_line) -> tuple[int, int]:
    try:
        start = int(start_line)
        end = int(end_line)
    except (TypeError, ValueError) as exc:
        raise ToolError("line numbers must be integers") from exc
    if start < 1:
        raise ToolError("start_line must be at least 1")
    if end != 0 and end < start:
        raise ToolError("end_line must be 0 or at least start_line")
    return start, end
