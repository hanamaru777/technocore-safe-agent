#!/usr/bin/env python3
"""R862 bounded Flop STATE pathname/size metadata scan; not a backup.

OPEN DIRECTORY FDs ONLY. Does NOT open or read STATE file bytes.
PRODUCTION INVOCATION IS NOT AUTHORIZED BY GITHUB CI.
Do not use this for an archive cutover, OCI IAM or signer continuity proof.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

ROOT = Path("/var/lib/technocore-safe-agent")
APP = Path("/opt/technocore-safe-agent")
GROUPS = frozenset((
    "observer", "signer", "autopilot", "close1", "proof-plans",
    "public-proofs", "resident-exports",
))
MAX_ITEMS = 512
MAX_DIRS = 32
MAX_DEPTH = 4
MAX_PATH = 200
MAX_SECONDS = 12.0
MAX_SINGLE = 3 * 1024**3
MAX_TOTAL = 6 * 1024**3
SAFE_NAME = re.compile(r"[A-Za-z0-9._-]{1,150}\Z")
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)

class Stop(Exception):
    pass

def require(ok, reason):
    if not ok:
        raise Stop(reason)

def inventory(root, *, max_seconds=MAX_SECONDS):
    """Return synthetic-compatible metadata, without creating a file or reading data."""
    started = time.monotonic()
    files = []
    dirs = 0
    total = 0
    def budget():
        require(time.monotonic() - started < max_seconds, "TIME_BUDGET_STOP")
    def walk(fd, prefix="", depth=0):
        nonlocal dirs, total
        budget()
        dirs += 1
        require(dirs <= MAX_DIRS, "DIRECTORY_COUNT_STOP")
        with os.scandir(fd) as entries:
            for entry in entries:
                budget()
                name = entry.name
                require(isinstance(name, str) and
                        SAFE_NAME.fullmatch(name) is not None and
                        name not in (".", ".."), "PATH_NAME_STOP")
                relative = (prefix + "/" if prefix else "") + name
                require(len(relative) <= MAX_PATH, "PATH_LENGTH_STOP")
                require(len(files) + dirs <= MAX_ITEMS + MAX_DIRS,
                        "ENTRY_COUNT_STOP")
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(not stat.S_ISLNK(info.st_mode), "SYMLINK_STOP")
                if stat.S_ISDIR(info.st_mode):
                    require(depth < MAX_DEPTH and
                            (bool(prefix) or name in GROUPS),
                            "UNEXPECTED_DIRECTORY_STOP")
                    child = os.open(name, DIRECTORY_FLAGS, dir_fd=fd)
                    try:
                        check = os.fstat(child)
                        require(stat.S_ISDIR(check.st_mode) and
                                (info.st_dev, info.st_ino) ==
                                (check.st_dev, check.st_ino),
                                "DIRECTORY_CHANGED_STOP")
                        walk(child, relative, depth+1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode):
                    require(info.st_nlink == 1, "HARDLINK_STOP")
                    require(0 <= info.st_size <= MAX_SINGLE, "FILE_SIZE_STOP")
                    total += info.st_size
                    require(total <= MAX_TOTAL, "TOTAL_SIZE_STOP")
                    files.append({"path": relative, "type": "regular",
                                  "size": info.st_size})
                    require(len(files) <= MAX_ITEMS, "FILE_COUNT_STOP")
                else:
                    raise Stop("NONREGULAR_FILE_STOP")
    fd = os.open(root, DIRECTORY_FLAGS)
    try:
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode), "INVALID_ROOT_STOP")
        walk(fd)
    finally:
        os.close(fd)
    files.sort(key=lambda item: item["path"])
    return files, dirs, total

def summary(files, dirs, total):
    groups = {"root": 0, **{name: 0 for name in sorted(GROUPS)}}
    for entry in files:
        group = entry["path"].split("/", 1)[0]
        groups[group if group in GROUPS else "root"] += 1
    payload = json.dumps(files, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return {"file_count": len(files), "directory_count": dirs,
            "size_bytes": total,
            "path_size_digest": hashlib.sha256(payload).hexdigest(),
            "groups": groups}

def main():
    require(sys.platform.startswith("linux") and os.geteuid() == 0
            and not sys.argv[1:], "ROOT_LINUX_NO_ARGS_REQUIRED")
    # Refuse the unrelated K137 host and cloud shell. This is not a
    # caller authorization to run on the protected source machine.
    require(APP.is_dir() and (APP / "src/flop_agent/oracle_signer.py").is_file()
            and ROOT.is_dir(), "NOT_THE_FLOP_OCI_SOURCE")
    files, dirs, total = inventory(ROOT)
    result = summary(files, dirs, total)
    print("FLOP_R862_FILES=" + str(result["file_count"]))
    print("FLOP_R862_DIRECTORIES=" + str(result["directory_count"]))
    print("FLOP_R862_SIZE_BYTES=" + str(result["size_bytes"]))
    for key, value in result["groups"].items():
        print("FLOP_R862_GROUP_" + key.upper().replace("-", "_")
              + "=" + str(value))
    print("FLOP_R862_METADATA_FINGERPRINT_SHA256=" + result["path_size_digest"])
    print("FLOP_R862_NAMES_VALUES_NONCE_DID_NOT_PRINTED")
    print("FLOP_R862_NO_ARCHIVE_OR_WRITER_EPOCH_PROOF")
    print("FLOP_R862_METADATA_ONLY_PASS")

if __name__ == "__main__":
    try:
        main()
    except (Stop, OSError, ValueError, TypeError) as err:
        print("FLOP_R862_STOP=" +
              (str(err) if isinstance(err, Stop) else type(err).__name__))
        sys.exit(42)
