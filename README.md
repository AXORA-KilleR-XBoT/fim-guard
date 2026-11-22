# FIM Guard

A small file integrity monitor in Python. `init` records a SHA-256 hash for every file below a
directory (the *baseline*); `check` scans the directory again and lists files that were **added**,
**removed** or **modified** since then.

<!-- Placeholders to replace before publishing (search for YOUR):
     - YOUR_GITHUB_USERNAME in the badge below (remove the comment markers after the repository exists)
     - YOUR NAME in LICENSE
[![Python CI](https://github.com/YOUR_GITHUB_USERNAME/fim-guard/actions/workflows/tests.yml/badge.svg)](https://github.com/YOUR_GITHUB_USERNAME/fim-guard/actions/workflows/tests.yml)
-->

> **Scope:** FIM Guard **detects** changes after they happened. It does not prevent tampering, it does
> not restore files, and it is not forensic-grade evidence. Its answer is only as trustworthy as the
> baseline and the machine it runs on: read [Trust and limits](#trust-and-limits) before relying on it.
> It is a learning project; for real systems, look at established tools such as AIDE or Tripwire.

## What problem it solves

"Did anything in this directory change since I last looked?" For a web root, a configuration folder
or a folder of scripts, an unexpected change is worth a look. Comparing content hashes answers the
question without storing copies of the files.

## Features

- SHA-256 content hashes, read in chunks (large files are not loaded into memory).
- Added / removed / modified report, one line per path, with sorted and relative paths.
- Explicit exit codes: `0` no changes, `1` changes found, `2` error. An incomplete scan is never reported as clean.
- Symbolic links are **never followed**: a link is recorded as a link, so nothing outside the directory is read through it.
- The baseline is validated when it is loaded, and written atomically (a failed write cannot leave a half-written baseline).
- Optional HMAC signature for the baseline, with the key kept in a separate file.
- File names are treated as untrusted when printed (control characters are escaped).
- Standard library only; `pytest` is needed just for the tests.

## How it works

```text
init  directory --> scan --> baseline.json  { "version": 1, "entries": { "<relative path>": "<entry>" }, "hmac": "..." }
check directory --> scan --> compare with the baseline --> ADDED / REMOVED / MODIFIED, exit code 0, 1 or 2
```

An entry is `sha256:<hex>` for a regular file, `symlink:<target text>` for a symbolic link, or
`special:<kind>` for a pipe, socket or device. Special files are recorded by type and are never opened
(opening a pipe could hang the scan). Directories are not recorded; only the files inside them are.

## Requirements

- Python 3.10 or newer. The tests were run locally on Python 3.10, 3.11, 3.12 and 3.13 (Linux).
- Nothing to install to run the tool. `pytest` is needed only to run the tests.

## Quick start

macOS / Linux. This creates a throw-away folder `demo/` next to the script (`demo/` is git-ignored):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt      # only needed for the tests

mkdir -p demo/site demo/state
echo "debug=false" > demo/site/config.ini
echo "<h1>hello</h1>" > demo/site/index.html

python fim_guard.py init  demo/site --baseline demo/state/baseline.json
python fim_guard.py check demo/site --baseline demo/state/baseline.json

echo "debug=true" > demo/site/config.ini      # change a file
echo "new" > demo/site/new.txt                # add a file
rm demo/site/index.html                       # remove a file
python fim_guard.py check demo/site --baseline demo/state/baseline.json
echo "exit code: $?"
```

Windows (PowerShell) for the setup and the tests; the demo above is written for a POSIX shell. None of
this was run on Windows while preparing the project:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Keep the baseline (`demo/state/`) **outside** the directory you monitor (`demo/site/`).

## Example output

Real output of the commands above:

```text
$ python fim_guard.py init demo/site --baseline demo/state/baseline.json
Baseline saved: 2 entries -> demo/state/baseline.json

$ python fim_guard.py check demo/site --baseline demo/state/baseline.json
OK: no changes detected

$ python fim_guard.py check demo/site --baseline demo/state/baseline.json     # after the three changes
ADDED     new.txt
REMOVED   index.html
MODIFIED  config.ini
exit code: 1
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | `init` wrote the baseline, or `check` found no changes. |
| `1` | `check` found at least one added, removed or modified path. |
| `2` | An error: bad arguments, unreadable files or directories, invalid baseline, wrong key. If any file could not be read, the scan is **incomplete** and the exit code is `2` even if no change was seen. `init` writes no baseline in that case. |

## Optional: sign the baseline (HMAC)

Without a signature, anyone who can edit the baseline can hide a change by editing it too. With a
secret key, the baseline carries an HMAC-SHA-256 signature that `check` verifies:

```bash
python -c "import secrets; print(secrets.token_hex(32))" > demo/hmac.key
chmod 600 demo/hmac.key
python fim_guard.py init  demo/site --baseline demo/state/signed.json --key-file demo/hmac.key
python fim_guard.py check demo/site --baseline demo/state/signed.json --key-file demo/hmac.key
```

If the baseline is edited afterwards, `check` stops with:

```text
error: baseline HMAC does not match: the file was modified or the key is wrong
```

Rules the tool enforces: the key must be at least 16 bytes; the key file must **not** be inside the
monitored directory; a key given for an unsigned baseline is an error; a signed baseline checked
*without* a key prints a warning that its integrity is not being verified. There is no built-in key
and the repository must never contain one (`*.key` is git-ignored).

## Tests and CI

```bash
python -m pytest -q
```

The tests cover: hashing, nested paths, symbolic links (never followed, loops, broken links, retargeted
links, a file replaced by a link), pipes, unreadable files and directories, malformed or tampered
baselines, atomic writes and write failures, the HMAC rules, the exit codes, and hostile file names.
One test needs a non-root POSIX user (root ignores file permissions), so it is skipped when the tests
run as root.

`.github/workflows/tests.yml` runs the tests on Python 3.10 to 3.13 for pushes to `main`, pull requests
and manual runs, then runs `init`, a change and `check` once with the real command line. It has
read-only repository permissions, and the actions it uses are pinned to full commit SHAs.

## Trust and limits

- **Detection, not prevention.** The tool tells you something changed. It cannot stop a change or
  tell you who made it or why.
- **The baseline is the weak point.** Store it outside the monitored directory and make it readable
  only by the account that runs the tool (the tool creates it with owner-only permissions on POSIX).
  Better, sign it and keep the key somewhere an attacker on the monitored machine cannot read, for
  example on another machine. If the attacker can read the key file, a signature adds nothing.
- **Signatures do not prove freshness.** The HMAC covers the entries, not the date. An older, validly
  signed baseline can be put back (a rollback) and `check` will accept it.
- **A compromised machine cannot vouch for itself.** An attacker with administrator rights can also
  change this program, Python, or the output you read. For that situation run the check from outside.
- Only content is compared. Permissions, owners, timestamps, extended attributes, empty directories
  and hard-link relationships are **not** recorded, so changes to them are not reported.
- A file changed *during* a scan, or changed and restored between two scans, can be missed.
- Symbolic links are compared by their target text only; the file a link points to is hashed only if
  it also lies inside the monitored directory. (The directory you pass on the command line is resolved
  first, so it may itself be a link.)
- **`init` trusts the current state.** It records whatever is in the directory now and replaces an
  existing baseline without asking. Run it only when you believe the directory is in a good state.
- Not tested on Windows, on network file systems or on very large directory trees (no performance
  measurements were made; every file is read on every scan).

## Roadmap

Real work that is still open:

- Exclude patterns (for logs, caches and other files that are expected to change).
- Optionally record permissions and owners.
- Protection against rolling back to an older signed baseline (a counter or timestamp in the signed data).
- A JSON report format for scripts.
- Run and fix the tests on Windows, and measure the speed on a large directory.

## License

MIT, see `LICENSE`. The copyright holder in that file is a placeholder (`YOUR NAME`): replace it
with your own name before publishing.
