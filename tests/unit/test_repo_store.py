"""The repo jail: containment, pruning, binary refusal, and caps."""

import pytest

from arrowhead.config import get_settings
from arrowhead.repo.store import (
    BinaryFileError,
    RepoFileNotFoundError,
    RepoFileTooLargeError,
    RepoStoreError,
    build_repo_store,
)


def store():
    return build_repo_store(get_settings())


def test_read_inside_the_jail(repo):
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("print('ok')\n")
    assert store().read_text("src/app.py") == "print('ok')\n"


def test_traversal_is_contained(repo):
    with pytest.raises(RepoStoreError):
        store().read_text("../../etc/passwd")


def test_symlink_escape_is_contained(repo, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "secret.py"
    outside.write_text("leak = True\n")
    (repo / "link.py").symlink_to(outside)
    with pytest.raises(RepoStoreError):
        store().read_text("link.py")
    listed = {info.path for info in store().list().items}
    assert "link.py" not in listed


def test_symlinked_directory_is_not_followed(repo, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside-dir")
    (outside / "secret.py").write_text("leak = True\n")
    (repo / "vendor").symlink_to(outside, target_is_directory=True)
    listed = {info.path for info in store().list().items}
    assert not any(path.startswith("vendor") for path in listed)


def test_excluded_directories_are_pruned(repo):
    (repo / ".git").mkdir()
    (repo / ".git" / "config").write_text("[core]\n")
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "pkg.js").write_text("x")
    (repo / "app.py").write_text("ok = 1\n")
    listed = {info.path for info in store().list().items}
    assert listed == {"app.py"}
    with pytest.raises(RepoFileNotFoundError):
        store().read_text(".git/config")


def test_binary_files_are_refused(repo):
    (repo / "blob.py").write_bytes(b"\x00\x01\x02compiled")
    with pytest.raises(BinaryFileError):
        store().read_text("blob.py")


def test_oversized_files_are_refused(repo, monkeypatch):
    monkeypatch.setenv("ARROWHEAD_REPO_MAX_FILE_BYTES", "16")
    get_settings.cache_clear()
    (repo / "big.py").write_text("x" * 64)
    with pytest.raises(RepoFileTooLargeError):
        store().read_text("big.py")


def test_listing_is_bounded_and_prefix_filtered(repo):
    (repo / "a").mkdir()
    for index in range(5):
        (repo / "a" / f"m{index}.py").write_text("pass\n")
    (repo / "top.py").write_text("pass\n")
    listing = store().list(path_prefix="a/", max_files=3)
    assert listing.truncated is True
    assert len(listing.items) == 3
    assert all(info.path.startswith("a/") for info in listing.items)


def test_extension_filter_applies(repo):
    (repo / "app.py").write_text("pass\n")
    (repo / "image.png").write_bytes(b"\x89PNG")
    listing = store().list(
        extensions=get_settings().repo_allowed_extension_set()
    )
    assert {info.path for info in listing.items} == {"app.py"}
