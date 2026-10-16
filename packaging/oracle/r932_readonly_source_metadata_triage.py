#!/usr/bin/env python3
"""R932: bounded Flop source metadata ONLY, never file data or service changes.

No values, nonce, keys, command argv, filenames or DID are printed. A reported
inventory is not a writer fence, app-consistent backup or OCI retirement proof.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

ROOT = Path("/var/lib/technocore-safe-agent")
APP = Path("/opt/technocore-safe-agent")
HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
KNOWN_DIRS = frozenset(("observer", "signer", "autopilot", "close1",
                        "proof-plans", "public-proofs", "resident-exports"))
MAX_FILES = 2048
MAX_DIRS = 128
MAX_ELAPSED = 8


class Stop(Exception):
    pass


def need(ok, reason):
    if not ok:
        raise Stop(reason)


def inspect(root=ROOT, *, start=None, file_cap=MAX_FILES, dir_cap=MAX_DIRS):
    """Read-only directory-FD metadata traversal. Never open file contents."""
    if start is None:
        start = time.monotonic()
    seen = set()
    report = {
        "files": 0, "dirs": 0, "bytes": 0,
        "symlinks": 0, "other_special": 0, "hardlinks": 0,
        "unknown_top_dirs": 0, "incomplete": False,
        "stop_reason": "none",
        "groups": {g: {"files": 0, "bytes": 0}
                   for g in sorted(KNOWN_DIRS | {"root"})},
    }
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)

    def walk(fd, group, depth):
        need(time.monotonic() - start < MAX_ELAPSED, "TIME_LIMIT")
        need(depth <= 7, "DEPTH_LIMIT")
        report["dirs"] += 1
        need(report["dirs"] <= dir_cap, "DIR_COUNT_LIMIT")
        with os.scandir(fd) as entries:
            for entry in entries:
                need(time.monotonic() - start < MAX_ELAPSED, "TIME_LIMIT")
                name = entry.name
                need(name not in ("", ".", ".."), "BAD_ENTRY")
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                need((info.st_dev, info.st_ino) not in seen, "DUPLICATE_INODE")
                seen.add((info.st_dev, info.st_ino))
                if stat.S_ISLNK(info.st_mode):
                    report["symlinks"] += 1
                    continue
                if stat.S_ISDIR(info.st_mode):
                    if depth == 0 and name not in KNOWN_DIRS:
                        report["unknown_top_dirs"] += 1
                        continue
                    try:
                        child = os.open(name, flags, dir_fd=fd)
                    except OSError:
                        raise Stop("DIRECTORY_REPLACED_OR_UNREADABLE") from None
                    try:
                        current = os.fstat(child)
                        need((info.st_dev, info.st_ino) ==
                             (current.st_dev, current.st_ino),
                             "DIRECTORY_CHANGED")
                        walk(child, name if depth == 0 else group, depth + 1)
                    finally:
                        os.close(child)
                    continue
                if not stat.S_ISREG(info.st_mode):
                    report["other_special"] += 1
                    continue
                if info.st_nlink != 1:
                    report["hardlinks"] += 1
                    continue
                report["files"] += 1
                need(report["files"] <= file_cap, "FILE_COUNT_LIMIT")
                report["bytes"] += info.st_size
                report["groups"][group]["files"] += 1
                report["groups"][group]["bytes"] += info.st_size

    try:
        fd = os.open(root, flags)
        try:
            walk(fd, "root", 0)
        finally:
            os.close(fd)
    except (OSError, Stop) as error:
        report["incomplete"] = True
        report["stop_reason"] = (
            str(error) if isinstance(error, Stop) else "FILESYSTEM_READ_FAILURE"
        )
    if any(report[k] for k in (
        "symlinks", "other_special", "hardlinks", "unknown_top_dirs"
    )):
        report["incomplete"] = True
        if report["stop_reason"] == "none":
            report["stop_reason"] = "UNCLASSIFIED_ENTRY"
    return report


def main():
    need(sys.platform.startswith("linux"), "LINUX_REQUIRED")
    need(os.geteuid() == 0, "ROOT_REQUIRED")
    need(APP.is_dir() and ROOT.is_dir(), "SOURCE_PATHS_MISSING")
    need((APP / "src/flop_agent/oracle_signer.py").is_file(),
         "SOURCE_MARKER_MISSING")
    try:
        head = subprocess.run(
            ["git", "-C", str(APP), "-c", "safe.directory=" + str(APP),
             "rev-parse", "--verify", "HEAD"],
            capture_output=True, text=True, timeout=4,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Stop("SOURCE_HEAD_CHECK_UNAVAILABLE") from None
    need(head.returncode == 0, "SOURCE_HEAD_CHECK_FAILED")
    need(head.stdout.strip() == HEAD, "SOURCE_HEAD_DRIFT")
    print("R932_SOURCE_IDENTITY=PASS", flush=True)
    for index, path in enumerate((
        ROOT / "observer/lobby-capture.sqlite3",
        ROOT / "observer/lobby-capture-service.sqlite3",
    ), start=1):
        try:
            info = path.lstat()
        except OSError:
            result = "MISSING_OR_UNREADABLE"
        else:
            result = str(info.st_size) if (
                stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            ) else "UNSAFE_TYPE"
        print(f"R932_DB{index}_BYTES={result}", flush=True)
    report = inspect()
    print("R932_STATE_SUMMARY=" + json.dumps(
        report, sort_keys=True, separators=(",", ":")), flush=True)
    print("R932_STATE_COVERAGE=" + (
        "INCOMPLETE" if report["incomplete"] else "METADATA_ONLY"
    ), flush=True)
    print("R932_NO_DATA_VALUES_NO_WRITES_NO_SIGN_NO_RETIRE", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (Stop, OSError, ValueError, TypeError) as error:
        print("R932_STOP=" + (
            str(error) if isinstance(error, Stop) else type(error).__name__
        ), flush=True)
        print("R932_NO_DATA_VALUES_NO_WRITES_NO_SIGN_NO_RETIRE", flush=True)
        sys.exit(42)
