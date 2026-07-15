import pytest
from fastmcp.exceptions import ToolError

from arrowhead.tools.read_file import read_file


async def test_file_inside_jail_is_returned(jail):
    (jail / "notes").mkdir()
    (jail / "notes" / "hello.txt").write_text("hello from the jail")
    assert await read_file("notes/hello.txt") == "hello from the jail"


async def test_parent_traversal_rejected(jail):
    with pytest.raises(ToolError):
        await read_file("../../etc/passwd")


async def test_absolute_path_rejected(jail):
    with pytest.raises(ToolError):
        await read_file("/etc/passwd")


async def test_symlink_escaping_jail_rejected(jail, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "secret.txt"
    outside.write_text("secret")
    (jail / "innocent.txt").symlink_to(outside)
    with pytest.raises(ToolError):
        await read_file("innocent.txt")


async def test_symlink_inside_jail_is_allowed(jail):
    (jail / "real.txt").write_text("real")
    (jail / "alias.txt").symlink_to(jail / "real.txt")
    assert await read_file("alias.txt") == "real"


async def test_missing_file_reported_without_echoing_path(jail):
    with pytest.raises(ToolError) as excinfo:
        await read_file("no/such/file.txt")
    assert "no/such/file.txt" not in str(excinfo.value)


async def test_oversized_file_rejected(jail, monkeypatch):
    from arrowhead.config import get_settings

    monkeypatch.setenv("ARROWHEAD_READ_FILE_MAX_BYTES", "8")
    get_settings.cache_clear()
    (jail / "big.txt").write_text("x" * 64)
    with pytest.raises(ToolError):
        await read_file("big.txt")
