#!/usr/bin/env python3
"""R1002 source-only complete lstat manifest to an *encrypted* transport pipe.

DO NOT run with stdout aimed at a terminal or log. No content reads, no sudo
inside the tool, no source-state writes or service control. This manifest is
NOT a coherent writer-epoch snapshot, not an archive and not cutover proof.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

SOURCE = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
ROOT = Path("/var/lib/technocore-safe-agent")
APP = Path("/opt/technocore-safe-agent")
MAX_ITEMS = 22_000
MAX_DEPTH = 14
MAX_DIRS = 4_096
MAX_SECONDS = 28.0
MAX_PATH_BYTES = 2048
MAX_TOTAL_JSON = 12 * 1024 * 1024
OPEN_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class Stop(Exception):
    pass


def need(value, code):
    if not value:
        raise Stop(code)


def preflight():
    need(sys.platform == "linux" and os.geteuid() == 0
         and os.getppid() > 1 and not sys.stdout.isatty()
         and len(sys.argv) == 1, "ORIGINAL_ROOT_NO_TERMINAL_REQUIRED")
    need(os.uname().nodename == "technocore-resident"
         and APP.is_dir() and ROOT.is_dir()
         and (APP / "src/flop_agent/oracle_signer.py").is_file()
         and not Path("/opt/tradebot-k137").exists(),
         "WRONG_ORIGINAL_GUEST_REFUSED")
    process = subprocess.run(
        ["/usr/bin/git", "-C", str(APP), "-c", "safe.directory="+str(APP),
         "rev-parse", "--verify", "HEAD"], timeout=6,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C",
             "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"})
    need(process.returncode == 0 and process.stdout.strip() == SOURCE.encode(),
         "SOURCE_HEAD_MISMATCH_STOP")


def scan(root: Path, *, monotonic=time.monotonic):
    start = monotonic()
    need(root.is_absolute(), "SOURCE_ROOT_ABSOLUTE_STOP")
    entries = []
    total = 0
    directories = 0
    links = 0

    def budget():
        need(monotonic() - start < MAX_SECONDS, "TIMEOUT_SCAN_STOP")
        need(len(entries) < MAX_ITEMS, "ENTRY_LIMIT_STOP")

    def walk(fd, prefix: str, depth: int):
        nonlocal total, directories, links
        budget()
        need(depth <= MAX_DEPTH, "DEPTH_LIMIT_STOP")
        directories += 1
        need(directories <= MAX_DIRS, "DIR_LIMIT_STOP")
        with os.scandir(fd) as iterator:
            names = sorted(e.name for e in iterator)
        need(len(names) == len(set(names)), "DUPLICATE_NAMES_STOP")
        for name in names:
            budget()
            need(isinstance(name, str) and name not in (".", "..")
                 and "/" not in name and "\0" not in name,
                 "UNSAFE_NAME_STOP")
            path = prefix + "/" + name if prefix else name
            need(len(os.fsencode(path)) <= MAX_PATH_BYTES, "PATH_TOO_LONG_STOP")
            s = os.stat(name, dir_fd=fd, follow_symlinks=False)
            row = {"path": path, "mode": stat.S_IMODE(s.st_mode),
                   "uid": s.st_uid, "gid": s.st_gid,
                   "mtime_ns": s.st_mtime_ns,
                   "nlink": s.st_nlink}
            if stat.S_ISDIR(s.st_mode):
                row["type"] = "dir"
                entries.append(row)
                child = os.open(name, OPEN_DIR, dir_fd=fd)
                try:
                    verify = os.fstat(child)
                    need((s.st_dev, s.st_ino) == (verify.st_dev, verify.st_ino)
                         and stat.S_ISDIR(verify.st_mode),
                         "DIRECTORY_CHANGED_STOP")
                    walk(child, path, depth + 1)
                finally:
                    os.close(child)
            elif stat.S_ISREG(s.st_mode):
                need(s.st_size >= 0 and s.st_blocks >= 0,
                     "SIZE_INVALID_STOP")
                row.update({"type": "file", "size": s.st_size,
                            "allocated": s.st_blocks * 512})
                total += s.st_blocks * 512
                entries.append(row)
            elif stat.S_ISLNK(s.st_mode):
                links += 1
                target = os.readlink(name, dir_fd=fd)
                need(len(os.fsencode(target)) <= MAX_PATH_BYTES,
                     "SYMLINK_TARGET_LONG_STOP")
                row.update({"type": "symlink", "target": target})
                entries.append(row)
            else:
                raise Stop("SPECIAL_FILE_STOP")
            need(len(entries) <= MAX_ITEMS, "ENTRY_LIMIT_STOP")

    parent_fd = os.open(root, OPEN_DIR)
    try:
        before = os.fstat(parent_fd)
        need(stat.S_ISDIR(before.st_mode), "ROOT_NOT_DIR_STOP")
        walk(parent_fd, "", 0)
        after = os.fstat(parent_fd)
        need((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
             "SOURCE_ROOT_REPLACED_STOP")
    finally:
        os.close(parent_fd)
    need(bool(entries), "EMPTY_SOURCE_STOP")
    paths = [e["path"] for e in entries]
    need(len(paths) == len(set(paths)), "DUPLICATE_PATH_STOP")
    # Not JSON sorted until all source subdirectories are scanned.
    return {"schema": 1, "kind": "flop-original-full-tree-metadata-v1",
            "source_commit": SOURCE, "root": "FLOP_STATE_DIR",
            "walk_complete": True, "writer_epoch_proven": False,
            "content_digests_proven": False,
            "sqlite_coherent_backup_proven": False,
            "files": sum(e["type"] == "file" for e in entries),
            "directories": directories, "symlinks": links,
            "allocated_bytes": total, "entries": entries}


def main():
    preflight()
    payload = scan(ROOT)
    raw = json.dumps(payload, ensure_ascii=True,
                     sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    need(len(raw) <= MAX_TOTAL_JSON, "JSON_OUTPUT_TOO_LARGE_STOP")
    # Only a private authenticated encrypted pipe may receive this manifest.
    # Caller must fail closed on upstream ssh exit, never display raw JSON.
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    try:
        main()
    except (Stop, OSError, ValueError, UnicodeError,
            subprocess.TimeoutExpired) as exc:
        code = str(exc) if isinstance(exc, Stop) else type(exc).__name__
        print("FLOP_R1002_SOURCE_MANIFEST_STOP=" + code, file=sys.stderr)
        sys.exit(42)
