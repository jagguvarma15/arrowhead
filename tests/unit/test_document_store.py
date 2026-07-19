import pytest

from arrowhead.store.document_store import (
    DocumentExistsError,
    DocumentNotFoundError,
    DocumentStore,
    DocumentStoreError,
    DocumentTooLargeError,
    QuotaExceededError,
)


def make_store(root, *, read=1000, write=1000, quota=10000):
    return DocumentStore(
        root, read_max_bytes=read, write_max_bytes=write, quota_bytes=quota
    )


def test_read_document_inside_corpus(tmp_path):
    (tmp_path / "notes.txt").write_text("hello corpus")
    store = make_store(tmp_path)
    assert store.read_bytes("notes.txt") == b"hello corpus"


def test_read_missing_document(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(DocumentNotFoundError):
        store.read_bytes("nope.txt")


def test_parent_traversal_rejected(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(DocumentStoreError):
        store.read_bytes("../outside.txt")


def test_symlink_escape_rejected_on_read(tmp_path, tmp_path_factory):
    secret = tmp_path_factory.mktemp("outside") / "secret.txt"
    secret.write_text("secret")
    (tmp_path / "alias.txt").symlink_to(secret)
    store = make_store(tmp_path)
    with pytest.raises(DocumentStoreError):
        store.read_bytes("alias.txt")


def test_oversized_read_rejected(tmp_path):
    (tmp_path / "big.txt").write_text("x" * 100)
    store = make_store(tmp_path, read=8)
    with pytest.raises(DocumentTooLargeError):
        store.read_bytes("big.txt")


def test_write_new_document(tmp_path):
    store = make_store(tmp_path)
    info = store.write_atomic("sub/new.txt", b"content")
    assert info.path == "sub/new.txt"
    assert (tmp_path / "sub" / "new.txt").read_bytes() == b"content"


def test_write_no_clobber_by_default(tmp_path):
    (tmp_path / "exists.txt").write_text("old")
    store = make_store(tmp_path)
    with pytest.raises(DocumentExistsError):
        store.write_atomic("exists.txt", b"new")
    assert (tmp_path / "exists.txt").read_text() == "old"


def test_write_overwrite_when_permitted(tmp_path):
    (tmp_path / "exists.txt").write_text("old")
    store = make_store(tmp_path)
    store.write_atomic("exists.txt", b"new", overwrite=True)
    assert (tmp_path / "exists.txt").read_text() == "new"


def test_write_beyond_size_cap_rejected(tmp_path):
    store = make_store(tmp_path, write=4)
    with pytest.raises(DocumentTooLargeError):
        store.write_atomic("x.txt", b"toolong")


def test_write_beyond_quota_rejected(tmp_path):
    (tmp_path / "filler.txt").write_bytes(b"x" * 90)
    store = make_store(tmp_path, quota=100)
    with pytest.raises(QuotaExceededError):
        store.write_atomic("more.txt", b"y" * 50)


def test_write_leaves_no_temp_files(tmp_path):
    store = make_store(tmp_path)
    store.write_atomic("a.txt", b"data")
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".arrowhead")]
    assert leftovers == []


def test_list_filters_by_extension(tmp_path):
    (tmp_path / "a.txt").write_text("t")
    (tmp_path / "b.json").write_text("{}")
    (tmp_path / "c.md").write_text("m")
    store = make_store(tmp_path)
    txt_and_md = store.list(extensions=frozenset({".txt", ".md"}))
    assert {info.path for info in txt_and_md} == {"a.txt", "c.md"}


def test_list_bounded_by_max_files(tmp_path):
    for i in range(10):
        (tmp_path / f"f{i}.txt").write_text("x")
    store = make_store(tmp_path)
    assert len(store.list(max_files=3)) == 3


def test_list_skips_escaping_symlink(tmp_path, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "secret.txt"
    outside.write_text("secret")
    (tmp_path / "alias.txt").symlink_to(outside)
    (tmp_path / "real.txt").write_text("ok")
    store = make_store(tmp_path)
    assert {info.path for info in store.list()} == {"real.txt"}


def test_stat_reports_metadata(tmp_path):
    (tmp_path / "doc.json").write_text("{}")
    store = make_store(tmp_path)
    info = store.stat("doc.json")
    assert info.extension == ".json"
    assert info.size == 2


def test_missing_root_lists_empty(tmp_path):
    store = make_store(tmp_path / "does-not-exist")
    assert store.list() == []
