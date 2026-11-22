import json
import os
import stat

import pytest

import fim_guard
from fim_guard import FimError, load_key, read_baseline, sign, write_baseline

GOOD = "sha256:" + "ab" * 32
KEY = b"0123456789abcdef-test-key"


def raw(tmp_path, text):
    path = tmp_path / "baseline.json"
    path.write_text(text, encoding="utf-8")
    return path


def doc(entries=None, **extra):
    data = {"version": 1, "entries": {"a.txt": GOOD} if entries is None else entries}
    data.update(extra)
    return json.dumps(data)


# ---------- reading and validating ----------

def test_round_trip_with_every_entry_kind(tmp_path):
    entries = {"a.txt": GOOD, "link": "symlink:../x", "pipe": "special:fifo", "d/e f.txt": GOOD}
    path = tmp_path / "baseline.json"
    write_baseline(path, entries)
    assert read_baseline(path) == entries


def test_empty_baseline_is_valid(tmp_path):
    assert read_baseline(raw(tmp_path, doc({}))) == {}


@pytest.mark.parametrize("text", [
    "", "not json", "[]", "{}", "null",
    json.dumps({"version": 2, "entries": {}}),
    json.dumps({"version": 1, "entries": []}),
    json.dumps({"version": 1}),
    doc(surprise=1),
    '{"version": 1, "entries": {"a": "%s", "a": "%s"}}' % (GOOD, GOOD),   # duplicate keys
    pytest.param("[" * 200000, id="hostile-nesting-depth"),
    pytest.param('{"version": 1, "entries": {"a.txt": ' + "[" * 200000, id="hostile-nesting-in-entries"),
])
def test_bad_structure_is_rejected(tmp_path, text):
    with pytest.raises(FimError):
        read_baseline(raw(tmp_path, text))


@pytest.mark.parametrize("path", ["/etc/passwd", "../x", "a/../b", "a//b", "", ".", "a/./b", "a\x00b", "a/"])
def test_bad_paths_are_rejected(tmp_path, path):
    with pytest.raises(FimError, match="relative"):
        read_baseline(raw(tmp_path, doc({path: GOOD})))


@pytest.mark.parametrize("entry", [
    "sha256:" + "AB" * 32,          # upper case
    "sha256:" + "ab" * 31,          # too short
    "sha256:" + "ab" * 33,          # too long
    "ab" * 32,                      # no prefix
    "md5:" + "ab" * 16,             # wrong algorithm
    "sha256:" + "ab" * 32 + "\n",   # trailing newline
    "sha256:" + "zz" * 32,          # not hex
    "special:unknown", "symlink:", "", 123, None, ["x"], {"sha256": GOOD},
])
def test_bad_entries_are_rejected(tmp_path, entry):
    with pytest.raises(FimError, match="entry"):
        read_baseline(raw(tmp_path, doc({"a.txt": entry})))


def test_unreadable_baselines_are_clean_errors(tmp_path):
    with pytest.raises(FimError, match="cannot read baseline"):
        read_baseline(tmp_path / "missing.json")
    with pytest.raises(FimError, match="cannot read baseline"):
        read_baseline(tmp_path)                                    # a directory
    binary = tmp_path / "binary.json"
    binary.write_bytes(b"\xff\xfe\x00{")
    with pytest.raises(FimError, match="not valid"):
        read_baseline(binary)


# ---------- atomic writing ----------

def test_failed_replace_keeps_the_old_baseline_and_leaves_no_temp_file(tmp_path, monkeypatch):
    path = tmp_path / "baseline.json"
    write_baseline(path, {"a.txt": GOOD})
    before = path.read_text()

    def boom(src, dst):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(FimError, match="cannot write baseline"):
        write_baseline(path, {"b.txt": GOOD})
    assert path.read_text() == before
    assert [p.name for p in tmp_path.iterdir()] == ["baseline.json"]


def test_failure_while_writing_keeps_the_old_baseline(tmp_path, monkeypatch):
    path = tmp_path / "baseline.json"
    write_baseline(path, {"a.txt": GOOD})
    before = path.read_text()

    def boom(fd):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(FimError, match="cannot write baseline"):
        write_baseline(path, {"b.txt": GOOD})
    assert path.read_text() == before
    assert [p.name for p in tmp_path.iterdir()] == ["baseline.json"]


def test_parent_directories_are_created(tmp_path):
    path = tmp_path / "a" / "b" / "baseline.json"
    write_baseline(path, {})
    assert read_baseline(path) == {}


def test_unwritable_location_is_a_clean_error(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(FimError, match="cannot write baseline"):
        write_baseline(blocker / "sub" / "baseline.json", {})


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_baseline_is_private_to_its_owner(tmp_path):
    path = tmp_path / "baseline.json"
    write_baseline(path, {})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


# ---------- optional HMAC ----------

def test_signature_ignores_dict_order_but_covers_the_content():
    a = sign({"a": GOOD, "b": GOOD}, KEY)
    assert a == sign({"b": GOOD, "a": GOOD}, KEY)
    assert a != sign({"a": GOOD, "c": GOOD}, KEY)
    assert a != sign({"a": GOOD, "b": GOOD}, KEY + b"x")


def test_hmac_round_trip_and_tampering(tmp_path):
    path = tmp_path / "baseline.json"
    write_baseline(path, {"a.txt": GOOD}, KEY)
    assert read_baseline(path, KEY) == {"a.txt": GOOD}
    data = json.loads(path.read_text())
    data["entries"]["a.txt"] = "sha256:" + "cd" * 32          # edited without knowing the key
    path.write_text(json.dumps(data))
    with pytest.raises(FimError, match="HMAC does not match"):
        read_baseline(path, KEY)


def test_wrong_key_is_rejected(tmp_path):
    path = tmp_path / "baseline.json"
    write_baseline(path, {"a.txt": GOOD}, KEY)
    with pytest.raises(FimError, match="HMAC does not match"):
        read_baseline(path, b"a-completely-different-key")


def test_unsigned_baseline_is_refused_when_a_key_is_given(tmp_path):
    path = tmp_path / "baseline.json"
    write_baseline(path, {"a.txt": GOOD})                     # an attacker swaps in an unsigned baseline
    with pytest.raises(FimError, match="no HMAC"):
        read_baseline(path, KEY)


def test_signed_baseline_without_a_key_warns(tmp_path, capsys):
    path = tmp_path / "baseline.json"
    write_baseline(path, {"a.txt": GOOD}, KEY)
    assert read_baseline(path) == {"a.txt": GOOD}
    assert "NOT being verified" in capsys.readouterr().err


@pytest.mark.parametrize("value", [123, None, "", "ünï-not-hex"])
def test_malformed_hmac_field_is_a_clean_error(tmp_path, value):
    with pytest.raises(FimError):
        read_baseline(raw(tmp_path, doc(hmac=value)), KEY)


def test_key_file_rules(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    good = tmp_path / "key.txt"
    good.write_bytes(KEY + b"\n")
    assert load_key(good, root) == KEY                         # the trailing newline is ignored
    short = tmp_path / "short.txt"
    short.write_bytes(b"abc")
    with pytest.raises(FimError, match="too short"):
        load_key(short, root)
    with pytest.raises(FimError, match="cannot read key file"):
        load_key(tmp_path / "missing.txt", root)
    inside = root / "key.txt"
    inside.write_bytes(KEY)
    with pytest.raises(FimError, match="inside the monitored directory"):
        load_key(inside, root)


def test_module_has_no_default_key():
    assert not any(name.lower().endswith("key") and isinstance(getattr(fim_guard, name), bytes)
                   for name in dir(fim_guard))
