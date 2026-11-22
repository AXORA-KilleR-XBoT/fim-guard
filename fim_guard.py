"""fim-guard: a small file integrity monitor.

`init` records a baseline (a SHA-256 hash for every file); `check` compares the
directory with that baseline and reports ADDED, REMOVED and MODIFIED paths. It detects
changes after the fact. It does not prevent them, and it is not forensic-grade protection.

Symlink policy: symbolic links are NEVER followed. A link is recorded as a link
("symlink:<target text>"), so a changed target is detected and nothing outside the
monitored directory is ever read through a link. Special files (pipes, sockets,
devices) are recorded by type and never opened.
"""
import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

BASELINE_VERSION = 1
MIN_KEY_BYTES = 16
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
SYMLINK = re.compile(r"symlink:.+", re.S)
SPECIAL = re.compile(r"special:(fifo|socket|char-device|block-device)")
# O_NOFOLLOW: refuse to follow a link that appears after we looked at the path.
# O_NONBLOCK: opening a pipe that appears after we looked must not hang.
READ_FLAGS = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
              | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0))


class FimError(Exception):
    """A problem that is shown to the user as a short message (exit code 2)."""


def safe(text):
    """Escape control characters so a hostile file name cannot rewrite what the terminal shows."""
    return "".join(ch if ch.isprintable() else (f"\\x{ord(ch):02x}" if ord(ch) < 256 else f"\\u{ord(ch):04x}")
                   for ch in text)


def is_inside(path, folder):
    return path == folder or folder in path.parents


# ---------- scanning ----------

def hash_file(path):
    fd = os.open(path, READ_FLAGS)
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise OSError("not a regular file any more (changed during the scan?)")
        digest = hashlib.sha256()
        while block := f.read(1 << 16):
            digest.update(block)
    return digest.hexdigest()


def describe(path):
    """Baseline entry for one path, or None for directories: sha256:<hex>, symlink:<target>, special:<kind>."""
    mode = os.lstat(path).st_mode
    if stat.S_ISLNK(mode):
        return "symlink:" + os.readlink(path)
    if stat.S_ISREG(mode):
        return "sha256:" + hash_file(path)
    for test, kind in ((stat.S_ISFIFO, "fifo"), (stat.S_ISSOCK, "socket"),
                       (stat.S_ISCHR, "char-device"), (stat.S_ISBLK, "block-device")):
        if test(mode):
            return "special:" + kind
    return None


def scan(root, skip=None):
    """Walk `root`; return (entries, problems).

    entries is {relative/posix/path: entry}. A non-empty `problems` list means the scan is
    INCOMPLETE and must not be treated as a clean result. `skip` is the baseline file.
    """
    root = Path(root).resolve()
    if not root.is_dir():
        raise FimError(f"not a directory: {safe(str(root))}")
    skip_rel = None
    if skip is not None and is_inside(Path(skip).resolve(), root):
        skip_rel = Path(skip).resolve().relative_to(root).as_posix()
    entries, problems = {}, []

    def on_error(exc):  # os.walk calls this when a directory cannot be listed
        problems.append(f"cannot read directory {safe(str(exc.filename))}: {exc.strerror}")

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=on_error):
        dirnames.sort()
        # os.walk lists links to directories among the directories but does not enter them.
        links_to_dirs = [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]
        for name in sorted(filenames + links_to_dirs):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if rel == skip_rel:
                continue
            try:
                entry = describe(path)
            except OSError as exc:
                problems.append(f"cannot read {safe(rel)}: {exc.strerror or exc}")
                continue
            if entry is not None:
                entries[rel] = entry
    return entries, problems


def diff(baseline, current):
    return {"added": sorted(current.keys() - baseline.keys()),
            "removed": sorted(baseline.keys() - current.keys()),
            "modified": sorted(p for p in baseline.keys() & current.keys() if baseline[p] != current[p])}


# ---------- baseline file ----------

def canonical(entries):
    return json.dumps({"version": BASELINE_VERSION, "entries": entries},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(entries, key):
    return hmac.new(key, canonical(entries), hashlib.sha256).hexdigest()


def write_baseline(path, entries, key=None):
    """Write atomically: a temporary file in the same folder replaces the old baseline in one step,
    so an interrupted write cannot leave a half-written baseline behind."""
    doc = {"version": BASELINE_VERSION, "entries": entries}
    if key:
        doc["hmac"] = sign(entries, key)
    path = Path(path)
    tmp = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")  # mode 0600
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except OSError as exc:
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise FimError(f"cannot write baseline {path}: {exc.strerror or exc}") from exc


def _no_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate keys")
    return dict(pairs)


def invalid_entry(rel, entry):
    """Return a problem description for a baseline path/entry pair, or None if it is fine."""
    # An absolute path ("/etc/passwd") or a doubled/trailing slash produces an empty part.
    if not rel or "\x00" in rel or any(part in ("", ".", "..") for part in rel.split("/")):
        return "path must be relative, with no '.', '..' or empty parts"
    if not isinstance(entry, str) or not (
            DIGEST.fullmatch(entry) or SYMLINK.fullmatch(entry) or SPECIAL.fullmatch(entry)):
        return "entry must be sha256:<64 lowercase hex>, symlink:<target> or special:<kind>"
    return None


def read_baseline(path, key=None):
    """Load and validate a baseline; return its entries. Raises FimError if anything is wrong."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_keys)
    except OSError as exc:
        raise FimError(f"cannot read baseline {path}: {exc.strerror or exc}") from exc
    except (ValueError, RecursionError) as exc:  # bad JSON, duplicate keys, bad UTF-8 or absurdly deep nesting
        raise FimError(f"baseline {path} is not valid: {exc}") from exc
    if (not isinstance(doc, dict) or doc.get("version") != BASELINE_VERSION
            or not isinstance(doc.get("entries"), dict) or set(doc) - {"version", "entries", "hmac"}):
        raise FimError(f"baseline {path} has an unexpected structure (version {BASELINE_VERSION} expected)")
    entries = doc["entries"]
    for rel, entry in entries.items():
        problem = invalid_entry(rel, entry)
        if problem:
            raise FimError(f"baseline entry {safe(repr(rel))}: {problem}")
    if key is not None:
        stored = doc.get("hmac")
        if not isinstance(stored, str):
            raise FimError("a key was given but the baseline has no HMAC (unsigned baselines are refused)")
        if not hmac.compare_digest(stored.encode("utf-8"), sign(entries, key).encode("ascii")):
            raise FimError("baseline HMAC does not match: the file was modified or the key is wrong")
    elif "hmac" in doc:
        print("warning: the baseline has an HMAC but no --key-file was given, so its integrity "
              "is NOT being verified", file=sys.stderr)
    return entries


def load_key(path, root):
    if is_inside(Path(path).resolve(), Path(root).resolve()):
        raise FimError("the key file is inside the monitored directory; keep it somewhere else")
    try:
        key = Path(path).read_bytes().strip()
    except OSError as exc:
        raise FimError(f"cannot read key file {path}: {exc.strerror or exc}") from exc
    if len(key) < MIN_KEY_BYTES:
        raise FimError(f"key file {path} is too short: use at least {MIN_KEY_BYTES} random bytes")
    return key


# ---------- command line ----------

def run(args):
    root = Path(args.directory).resolve()
    baseline_path = Path(args.baseline).resolve()
    key = load_key(args.key_file, root) if args.key_file else None
    if is_inside(baseline_path, root):
        print("warning: the baseline is inside the monitored directory. Anyone who can change files "
              "there can change the baseline too; store it elsewhere.", file=sys.stderr)
    baseline = read_baseline(baseline_path, key) if args.command == "check" else None
    entries, problems = scan(root, skip=baseline_path)
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    if args.command == "init":
        if problems:
            raise FimError("scan incomplete: the baseline was NOT written")
        write_baseline(baseline_path, entries, key)
        print(f"Baseline saved: {len(entries)} entries -> {args.baseline}" + (" (HMAC-signed)" if key else ""))
        return 0
    changes = diff(baseline, entries)
    for kind, paths in changes.items():
        for path in paths:
            print(f"{kind.upper():<9} {safe(path)}")
    if problems:
        raise FimError("scan incomplete: this result cannot be trusted")
    if any(changes.values()):
        return 1
    print("OK: no changes detected")
    return 0


def main(argv=None):
    """Exit codes: 0 = no changes, 1 = changes found, 2 = error (bad input, unreadable files,
    invalid baseline or key). An incomplete scan is always exit code 2, never "OK"."""
    p = argparse.ArgumentParser(description="Minimal file integrity monitor (detects changes, does not prevent them).")
    p.add_argument("command", choices=["init", "check"])
    p.add_argument("directory")
    p.add_argument("-b", "--baseline", default="baseline.json",
                   help="baseline file; keep it OUTSIDE the monitored directory (default: baseline.json)")
    p.add_argument("--key-file", help="file with a secret key (>= 16 random bytes) to HMAC-sign / verify the baseline")
    args = p.parse_args(argv)
    try:
        return run(args)
    except FimError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
