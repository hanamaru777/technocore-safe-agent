#!/usr/bin/env python3
"""R1005: offhost audit of SQLite backup images; never run on live hosts.

Two valid SQLite files are NOT proof of one common source writer epoch.
Caller-supplied hashes are NOT proof of original source provenance.
Neither payload data nor private paths are logged.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time

EXPECTED = ("lobby-capture.sqlite3", "lobby-capture-service.sqlite3")
MAX_SIZE = 2 * 1024**3
MAX_SECONDS = 120.0
SQLITE_HEADER = b"SQLite format 3\x00"
HEX64 = re.compile(r"[a-f0-9]{64}\Z")


class Stop(Exception):
    pass


def require(value: bool, reason: str) -> None:
    if not value:
        raise Stop(reason)


def live_host_refusal() -> None:
    require(sys.platform.startswith("linux") and os.geteuid() != 0,
            "OFFHOST_NONROOT_LINUX_REQUIRED")
    require(not Path("/opt/technocore-safe-agent").exists() and
            not Path("/opt/tradebot-k137").exists(), "LIVE_HOST_FORBIDDEN")


def opened_dir(path: Path) -> int:
    require(path.is_absolute() and ".." not in path.parts,
            "ARCHIVE_PATH_REQUIRED")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for name in path.parts[1:]:
            next_fd = os.open(name, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        require(info.st_uid == os.geteuid() and stat.S_ISDIR(info.st_mode)
                and info.st_mode & 0o077 == 0, "ARCHIVE_DIR_CUSTODY_STOP")
        return fd
    except BaseException:
        os.close(fd)
        raise


def identity(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns,
            s.st_ctime_ns, s.st_mode, s.st_nlink)


def verify_image(dir_fd: int, name: str, expected_sha: str, *,
                 seconds: float = MAX_SECONDS):
    require(name in EXPECTED, "INVALID_DATABASE_NAME_STOP")
    require(isinstance(expected_sha, str) and HEX64.fullmatch(expected_sha),
            "EXTERNAL_SHA256_PIN_REQUIRED")
    for tail in ("-wal", "-shm", "-journal"):
        try:
            os.stat(name + tail, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise Stop("SIDECAR_NOT_PORTABLE_IMAGE_STOP")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                 dir_fd=dir_fd)
    conn = None
    try:
        first = os.fstat(fd)
        require(stat.S_ISREG(first.st_mode) and first.st_nlink == 1
                and first.st_uid == os.geteuid() and first.st_mode & 0o077 == 0
                and 100 <= first.st_size <= MAX_SIZE,
                "DATABASE_CUSTODY_OR_BOUND_STOP")
        require(os.pread(fd, len(SQLITE_HEADER), 0) == SQLITE_HEADER,
                "SQLITE_FILE_HEADER_STOP")
        digest = hashlib.sha256()
        size = 0
        while size < first.st_size:
            block = os.pread(fd, min(1024 * 1024, first.st_size - size), size)
            require(bool(block), "DATABASE_FILE_TRUNCATED_STOP")
            size += len(block)
            digest.update(block)
        require(size == first.st_size and digest.hexdigest() == expected_sha,
                "ORIGINAL_HASH_PIN_MISMATCH_STOP")
        require(identity(os.fstat(fd)) == identity(first),
                "DATABASE_CHANGED_DURING_HASH_STOP")
        # /proc/self/fd fixes identity even across path replacement; immutable
        # prohibits SQLite sidecar creation on the archived image.
        conn = sqlite3.connect(f"file:/proc/self/fd/{fd}?mode=ro&immutable=1",
                               uri=True, timeout=1.0)
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA query_only=ON")
        deadline = time.monotonic() + seconds
        calls = 0

        def limit():
            nonlocal calls
            calls += 1
            return int(calls > 500_000 or time.monotonic() > deadline)

        conn.set_progress_handler(limit, 1000)
        for table, required in (
            ("messages", (("seq", "INTEGER", 1),
                          ("payload", "TEXT", 0))),
            ("meta", (("key", "TEXT", 1),
                      ("value", "TEXT", 0))),
        ):
            columns = conn.execute(f"PRAGMA table_info({table})").fetchall()
            require(len(columns) == 2 and all(
                columns[i][1] == col and columns[i][2].upper() == typ
                and bool(columns[i][5]) == bool(pk)
                for i, (col, typ, pk) in enumerate(required)),
                "CAPTURE_SCHEMA_MISMATCH_STOP")
        result = conn.execute("PRAGMA integrity_check").fetchall()
        require(len(result) == 1 and result[0] == ("ok",),
                "SQLITE_INTEGRITY_FAIL_STOP")
        count, low, high = conn.execute(
            "SELECT COUNT(*), MIN(seq), MAX(seq) FROM messages").fetchone()
        require(type(count) is int and count >= 0 and
                (count == 0 and low is None and high is None or
                 count > 0 and type(low) is int and type(high) is int
                 and 0 <= low <= high), "INVALID_SEQUENCE_SUMMARY_STOP")
        require(conn.execute("PRAGMA quick_check").fetchone() == ("ok",),
                "SQLITE_QUICK_CHECK_FAIL_STOP")
        conn.close()
        conn = None
        require(identity(os.fstat(fd)) == identity(first),
                "DATABASE_CHANGED_DURING_SQLITE_AUDIT_STOP")
        return {"bytes": size, "messages": count, "sha256": digest.hexdigest()}
    finally:
        if conn is not None:
            conn.close()
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    parser.add_argument("--legacy-sha256", required=True)
    parser.add_argument("--service-sha256", required=True)
    args = parser.parse_args()
    live_host_refusal()
    fd = opened_dir(Path(args.directory))
    try:
        results = [verify_image(fd, name, pin) for name, pin in zip(
            EXPECTED, (args.legacy_sha256, args.service_sha256))]
    finally:
        os.close(fd)
    print("FLOP_R1005_TWO_PINNED_IMAGES_SQLITE_INTEGRITY_PASS")
    for label, item in zip(("LEGACY", "SERVICE"), results):
        print(f"FLOP_R1005_{label}_BYTES={item['bytes']}")
        print(f"FLOP_R1005_{label}_MESSAGES={item['messages']}")
        print(f"FLOP_R1005_{label}_SHA256={item['sha256']}")
    print("FLOP_R1005_SQLITE_ONLINE_BACKUP_PROVENANCE=NOT_PROVEN")
    print("FLOP_R1005_COMMON_WRITER_EPOCH=NOT_PROVEN")
    print("FLOP_R1005_ORIGINAL_SIGNER_NONCE_LEDGER_CONTINUITY=NOT_PROVEN")
    print("FLOP_R1005_NO_SOURCE_OR_ARCHIVE_MUTATION=YES")
    print("FLOP_R1005_OCI_RETIREMENT=STRICT_NO_GO")


if __name__ == "__main__":
    try:
        main()
    except (Stop, OSError, ValueError, TypeError, sqlite3.Error) as error:
        code = str(error) if isinstance(error, Stop) else type(error).__name__
        print("FLOP_R1005_STOP=" + code)
        sys.exit(42)
