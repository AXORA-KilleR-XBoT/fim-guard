import json
import os

import pytest

import fim_guard
from fim_guard import main

KEY = b"0123456789abcdef-test-key"


def tree(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "a.txt").write_text("one")
    return data, str(tmp_path / "keep" / "baseline.json")


def test_exit_codes_for_clean_and_changed_trees(tmp_path, capsys):
    data, base = tree(tmp_path)
    assert main(["init", str(data), "-b", base]) == 0
    assert main(["check", str(data), "-b", base]) == 0
    assert "OK: no changes detected" in capsys.readouterr().out

    (data / "a.txt").write_text("two")
    assert main(["check", str(data), "-b", base]) == 1
    assert "MODIFIED  a.txt" in capsys.readouterr().out

    (data / "a.txt").write_text("one")
    (data / "b.txt").write_text("new")
    assert main(["check", str(data), "-b", base]) == 1
    assert "ADDED     b.txt" in capsys.readouterr().out

    (data / "b.txt").unlink()
    (data / "a.txt").unlink()
    assert main(["check", str(data), "-b", base]) == 1
    assert "REMOVED   a.txt" in capsys.readouterr().out


def test_errors_exit_with_2_and_no_traceback(tmp_path, capsys):
    data, base = tree(tmp_path)
    assert main(["check", str(data), "-b", base]) == 2                  # no baseline yet
    assert main(["init", str(tmp_path / "missing"), "-b", base]) == 2   # no such directory
    assert main(["init", str(data / "a.txt"), "-b", base]) == 2         # a file, not a directory
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    assert main(["check", str(data), "-b", str(broken)]) == 2
    err = capsys.readouterr().err
    assert err.count("error:") == 4 and "Traceback" not in err


def test_a_hostile_baseline_is_an_error_not_a_crash_or_a_change_report(tmp_path, capsys):
    data, base = tree(tmp_path)
    hostile = tmp_path / "hostile.json"
    hostile.write_text("[" * 200000)       # nesting so deep that the JSON parser gives up
    assert main(["check", str(data), "-b", str(hostile)]) == 2
    err = capsys.readouterr().err
    assert "error:" in err and "Traceback" not in err


def test_bad_usage_exits_with_2():
    for argv in (["bogus", "."], ["check"], []):
        with pytest.raises(SystemExit) as exc:
            main(argv)
        assert exc.value.code == 2


def test_incomplete_scan_is_never_reported_as_ok(tmp_path, monkeypatch, capsys):
    data, base = tree(tmp_path)
    (data / "blocked.txt").write_text("x")
    assert main(["init", str(data), "-b", base]) == 0
    capsys.readouterr()
    real = fim_guard.hash_file

    def fake(path):
        if str(path).endswith("blocked.txt"):
            raise PermissionError(13, "Permission denied", path)
        return real(path)

    monkeypatch.setattr(fim_guard, "hash_file", fake)
    assert main(["check", str(data), "-b", base]) == 2                  # unreadable file, nothing else changed
    out = capsys.readouterr()
    assert "OK" not in out.out and "cannot read blocked.txt" in out.err
    (data / "a.txt").write_text("changed")
    assert main(["check", str(data), "-b", base]) == 2                  # still 2: the result is not trustworthy
    assert "MODIFIED  a.txt" in capsys.readouterr().out                 # but the finding is still shown


def test_init_refuses_to_write_a_baseline_from_an_incomplete_scan(tmp_path, monkeypatch, capsys):
    data, base = tree(tmp_path)

    def fake(path):
        raise PermissionError(13, "Permission denied", path)

    monkeypatch.setattr(fim_guard, "hash_file", fake)
    assert main(["init", str(data), "-b", base]) == 2
    assert not os.path.exists(base)
    assert "baseline was NOT written" in capsys.readouterr().err


def test_baseline_inside_the_directory_warns_and_is_excluded(tmp_path, capsys):
    data, _ = tree(tmp_path)
    inside = str(data / "baseline.json")
    assert main(["init", str(data), "-b", inside]) == 0
    assert "inside the monitored directory" in capsys.readouterr().err
    assert json.loads((data / "baseline.json").read_text())["entries"].keys() == {"a.txt"}
    assert main(["check", str(data), "-b", inside]) == 0               # the baseline never reports itself


def test_hostile_file_names_cannot_forge_output(tmp_path, capsys):
    data, base = tree(tmp_path)
    evil = "evil\x1b[31m\nREMOVED   fake.txt"
    try:
        (data / evil).write_text("1")
    except OSError:
        pytest.skip("this file system does not allow such names")
    assert main(["init", str(data), "-b", base]) == 0
    (data / evil).write_text("2")
    capsys.readouterr()
    assert main(["check", str(data), "-b", base]) == 1
    out = capsys.readouterr().out
    assert "\x1b" not in out and not any(line.startswith("REMOVED") for line in out.splitlines())
    assert "\\x1b[31m\\x0aREMOVED   fake.txt" in out


@pytest.mark.skipif(os.name != "posix", reason="needs file names that are not valid UTF-8")
def test_non_utf8_file_names_round_trip_and_print_safely(tmp_path, capsys):
    data, base = tree(tmp_path)
    bad = os.fsencode(str(data)) + b"/bad-\xff.txt"
    try:
        with open(bad, "wb") as f:
            f.write(b"1")
    except OSError:
        pytest.skip("this file system does not allow such names")
    assert main(["init", str(data), "-b", base]) == 0
    assert main(["check", str(data), "-b", base]) == 0
    with open(bad, "wb") as f:
        f.write(b"2")
    capsys.readouterr()
    assert main(["check", str(data), "-b", base]) == 1
    assert "bad-\\udcff.txt" in capsys.readouterr().out


def test_hmac_workflow(tmp_path, capsys):
    data, base = tree(tmp_path)
    key = tmp_path / "secrets" / "fim.key"
    key.parent.mkdir()
    key.write_bytes(KEY)
    assert main(["init", str(data), "-b", base, "--key-file", str(key)]) == 0
    assert "HMAC-signed" in capsys.readouterr().out
    assert main(["check", str(data), "-b", base, "--key-file", str(key)]) == 0

    forged = json.loads(open(base).read())                              # change the baseline without the key
    forged["entries"]["a.txt"] = "sha256:" + "00" * 32
    with open(base, "w") as f:
        json.dump(forged, f)
    capsys.readouterr()
    assert main(["check", str(data), "-b", base, "--key-file", str(key)]) == 2
    assert "HMAC does not match" in capsys.readouterr().err


def test_key_inside_the_monitored_directory_is_refused(tmp_path, capsys):
    data, base = tree(tmp_path)
    key = data / "fim.key"
    key.write_bytes(KEY)
    assert main(["init", str(data), "-b", base, "--key-file", str(key)]) == 2
    assert "inside the monitored directory" in capsys.readouterr().err
    assert not os.path.exists(base)
