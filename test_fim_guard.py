import hashlib
import os

import pytest

import fim_guard
from fim_guard import FimError, diff, hash_file, scan

POSIX = os.name == "posix"
NOT_ROOT = POSIX and hasattr(os, "geteuid") and os.geteuid() != 0


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def link(target, path, is_dir=False):
    try:
        os.symlink(target, path, target_is_directory=is_dir)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available here")


def scan_ok(root, **options):
    entries, problems = scan(root, **options)
    assert problems == []
    return entries


# ---------- hashing, nested directories, diff ----------

def test_hash_is_sha256_of_content(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello")
    assert hash_file(f) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_nested_directories_use_relative_posix_paths(tmp_path):
    (tmp_path / "sub" / "deeper").mkdir(parents=True)
    (tmp_path / "emptydir").mkdir()
    (tmp_path / "a.txt").write_bytes(b"A")
    (tmp_path / "sub" / "b.txt").write_bytes(b"B")
    (tmp_path / "sub" / "deeper" / "c d.txt").write_bytes(b"C")
    (tmp_path / "empty.txt").write_bytes(b"")
    (tmp_path / "ünï.txt").write_bytes(b"U")
    assert scan_ok(tmp_path) == {
        "a.txt": sha(b"A"), "sub/b.txt": sha(b"B"), "sub/deeper/c d.txt": sha(b"C"),
        "empty.txt": sha(b""), "ünï.txt": sha(b"U"),     # empty directories are not recorded
    }


def test_diff_reports_added_removed_and_modified(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "keep.txt").write_text("same")
    (tmp_path / "sub" / "edit.txt").write_text("v1")
    (tmp_path / "gone.txt").write_text("bye")
    before = scan_ok(tmp_path)
    (tmp_path / "sub" / "edit.txt").write_text("v2")      # same size, different content
    (tmp_path / "gone.txt").unlink()
    (tmp_path / "new.txt").write_text("hi")
    assert diff(before, scan_ok(tmp_path)) == {
        "added": ["new.txt"], "removed": ["gone.txt"], "modified": ["sub/edit.txt"]}


def test_baseline_file_inside_the_directory_is_excluded(tmp_path):
    (tmp_path / "a.txt").write_text("A")
    (tmp_path / "baseline.json").write_text("{}")
    assert list(scan_ok(tmp_path, skip=tmp_path / "baseline.json")) == ["a.txt"]
    assert "baseline.json" in scan_ok(tmp_path)           # recorded when it is not excluded


def test_missing_or_non_directory_root_is_rejected(tmp_path):
    (tmp_path / "file.txt").write_text("x")
    for bad in (tmp_path / "missing", tmp_path / "file.txt"):
        with pytest.raises(FimError, match="not a directory"):
            scan(bad)


# ---------- symlink policy: never followed ----------

def test_symlink_is_recorded_as_a_link_and_never_followed(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret v1")
    root = tmp_path / "root"
    root.mkdir()
    target = os.path.join("..", "outside.txt")
    link(target, root / "link")
    first = scan_ok(root)
    assert first == {"link": "symlink:" + target}
    outside.write_text("secret v2, changed outside the monitored directory")
    assert scan_ok(root) == first                         # the file behind the link is never read


def test_changing_a_link_target_is_detected(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    link(str(tmp_path / "x"), root / "l")
    before = scan_ok(root)
    (root / "l").unlink()
    link(str(tmp_path / "y"), root / "l")
    assert diff(before, scan_ok(root))["modified"] == ["l"]


def test_file_replaced_by_a_symlink_is_a_modification(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "passwd").write_text("root:x:0:0")
    before = scan_ok(root)
    (root / "passwd").unlink()
    link("/etc/passwd", root / "passwd")
    assert diff(before, scan_ok(root))["modified"] == ["passwd"]


def test_directory_symlink_is_not_traversed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("s")
    root = tmp_path / "root"
    root.mkdir()
    link(str(outside), root / "out", is_dir=True)
    entries = scan_ok(root)
    assert list(entries) == ["out"] and entries["out"].startswith("symlink:")


def test_symlink_loops_do_not_hang_or_recurse(tmp_path):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    link("b", root / "a")
    link("a", root / "b")                                 # a -> b -> a
    link("..", root / "sub" / "up", is_dir=True)          # sub/up -> root (a directory loop)
    assert set(scan_ok(root)) == {"a", "b", "sub/up"}


def test_broken_symlink_is_recorded(tmp_path):
    link("does-not-exist", tmp_path / "dangling")
    assert scan_ok(tmp_path) == {"dangling": "symlink:does-not-exist"}


def test_root_that_is_a_symlink_is_resolved(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "a.txt").write_text("A")
    link(str(real), tmp_path / "alias", is_dir=True)
    assert scan_ok(tmp_path / "alias") == scan_ok(real) == {"a.txt": sha(b"A")}


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="needs O_NOFOLLOW")
def test_hash_file_refuses_to_follow_a_link(tmp_path):
    (tmp_path / "target").write_text("x")
    link(str(tmp_path / "target"), tmp_path / "l")
    with pytest.raises(OSError):
        hash_file(str(tmp_path / "l"))


# ---------- special files ----------

@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_named_pipe_is_recorded_by_type_and_never_hashed(tmp_path, monkeypatch):
    os.mkfifo(tmp_path / "pipe")
    (tmp_path / "a.txt").write_text("A")
    real = fim_guard.hash_file

    def guarded(path):
        assert not str(path).endswith("pipe"), "a pipe must never be opened for hashing"
        return real(path)

    monkeypatch.setattr(fim_guard, "hash_file", guarded)
    assert scan_ok(tmp_path) == {"a.txt": sha(b"A"), "pipe": "special:fifo"}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_hash_file_refuses_non_regular_files(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(OSError, match="not a regular file"):
        hash_file(str(tmp_path / "pipe"))


# ---------- unreadable files and directories: the scan must say it is incomplete ----------

def test_unreadable_file_makes_the_scan_incomplete(tmp_path, monkeypatch):
    (tmp_path / "ok.txt").write_text("ok")
    (tmp_path / "blocked.txt").write_text("x")
    real = fim_guard.hash_file

    def fake(path):
        if str(path).endswith("blocked.txt"):
            raise PermissionError(13, "Permission denied", path)
        return real(path)

    monkeypatch.setattr(fim_guard, "hash_file", fake)
    entries, problems = scan(tmp_path)
    assert "ok.txt" in entries and "blocked.txt" not in entries
    assert len(problems) == 1 and "blocked.txt" in problems[0] and "Permission denied" in problems[0]


def test_unreadable_directory_makes_the_scan_incomplete(tmp_path, monkeypatch):
    (tmp_path / "locked").mkdir()
    (tmp_path / "locked" / "x.txt").write_text("x")
    (tmp_path / "ok.txt").write_text("ok")
    real = os.scandir

    def fake(path="."):
        if os.fspath(path).endswith("locked"):
            raise PermissionError(13, "Permission denied", os.fspath(path))
        return real(path)

    monkeypatch.setattr(os, "scandir", fake)
    entries, problems = scan(tmp_path)
    assert "ok.txt" in entries and len(problems) == 1 and "locked" in problems[0]


@pytest.mark.skipif(not NOT_ROOT, reason="needs a non-root POSIX user (root ignores file permissions)")
def test_real_permission_errors_are_reported(tmp_path):
    (tmp_path / "ok.txt").write_text("ok")
    (tmp_path / "secret.txt").write_text("s")
    (tmp_path / "locked").mkdir()
    (tmp_path / "locked" / "x.txt").write_text("x")
    os.chmod(tmp_path / "secret.txt", 0)
    os.chmod(tmp_path / "locked", 0)
    try:
        entries, problems = scan(tmp_path)
    finally:
        os.chmod(tmp_path / "locked", 0o700)
        os.chmod(tmp_path / "secret.txt", 0o600)
    assert "ok.txt" in entries and len(problems) == 2
