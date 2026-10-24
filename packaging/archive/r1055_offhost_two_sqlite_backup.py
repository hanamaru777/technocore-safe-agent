#!/usr/bin/env python3
"""R1055: make and audit two SQLite online-backup images on an OFFHOST copy.

SOURCE-ONLY DRAFT. Never an Oracle/K137 production backup or common writer
epoch proof. No host services, credentials, signer, wallet or network.
Any application writer fence is an EXTERNAL prerequisite, not implemented here.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time

HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location(
    "flop_r1055_r1005", HERE / "verify-capture-backup-images.py")
R1005 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R1005)

NAMES = R1005.EXPECTED
MAX_SECONDS = 180
CHUNK = 1024 * 1024


class Stop(Exception):
    """Bounded fixed-code failure; never format private names or contents."""


def need(value, reason):
    if not value:
        raise Stop(reason)


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def inspect_source_fd(fd, name):
    f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fd)
    try:
        s = os.fstat(f)
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and
             s.st_uid == os.geteuid() and s.st_mode & 0o077 == 0 and
             100 <= s.st_size <= R1005.MAX_SIZE, "SOURCE_FILE_CUSTODY_STOP")
        return identity(s)
    finally:
        os.close(f)


def source_children(fd):
    entries = os.listdir(fd)
    need(len(entries) <= 8, "SOURCE_ENTRY_BOUND_STOP")
    extras = set(entries) - set(NAMES)
    for name in extras:
        need(any(name == base + tail for base in NAMES
                 for tail in ("-wal", "-shm", "-journal")),
             "SOURCE_UNKNOWN_ENTRY_STOP")
        s = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and
             s.st_uid == os.geteuid(), "SOURCE_SIDECAR_STOP")
    need(set(NAMES) <= set(entries), "SOURCE_TWO_DATABASES_REQUIRED_STOP")


def digest_image(fd, name):
    f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fd)
    try:
        before = os.fstat(f)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_uid == os.geteuid() and before.st_mode & 0o077 == 0
             and 100 <= before.st_size <= R1005.MAX_SIZE,
             "IMAGE_CUSTODY_STOP")
        sha = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            block = os.pread(f, min(CHUNK, before.st_size - offset), offset)
            need(bool(block), "IMAGE_TRUNCATED_STOP")
            sha.update(block)
            offset += len(block)
        need(identity(before) == identity(os.fstat(f)),
             "IMAGE_CHANGED_STOP")
        return sha.hexdigest()
    finally:
        os.close(f)


def backup_pair(source: Path, destination: Path) -> dict:
    """Write two independently correct images; DO NOT assert common epoch.

    Destination is exclusive and remains quarantined on ANY error; the caller
    must never regard an incomplete directory as an accepted archive.
    """
    R1005.live_host_refusal()
    need(source.is_absolute() and destination.is_absolute() and
         ".." not in source.parts and ".." not in destination.parts and
         source != destination, "PATH_STOP")
    start = time.monotonic()
    srcfd = R1005.opened_dir(source)
    parentfd = None
    dstfd = None
    try:
        source_children(srcfd)
        first = {name: inspect_source_fd(srcfd, name) for name in NAMES}
        parentfd = R1005.opened_dir(destination.parent)
        # Exclusive destination: never overwrite or remove an existing copy.
        os.mkdir(destination.name, 0o700, dir_fd=parentfd)
        dstfd = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parentfd)
        results = {}
        for name in NAMES:
            need(time.monotonic() - start < MAX_SECONDS,
                 "BACKUP_TOTAL_TIME_STOP")
            leaf = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                           os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dstfd)
            os.close(leaf)
            src = dst = None
            try:
                src = sqlite3.connect(
                    f"file:/proc/self/fd/{srcfd}/{name}?mode=ro",
                    uri=True, timeout=1.0)
                dst = sqlite3.connect(
                    f"file:/proc/self/fd/{dstfd}/{name}?mode=rw",
                    uri=True, timeout=1.0)
                src.execute("PRAGMA trusted_schema=OFF")
                dst.execute("PRAGMA trusted_schema=OFF")
                def progress(status, remaining, total):
                    if time.monotonic() - start > MAX_SECONDS:
                        raise Stop("BACKUP_TOTAL_TIME_STOP")
                src.backup(dst, pages=128, progress=progress, sleep=0.02)
                dst.commit()
            finally:
                if dst is not None:
                    dst.close()
                if src is not None:
                    src.close()
            need(inspect_source_fd(srcfd, name) == first[name],
                 "SOURCE_DRIFT_STOP")
            expected = digest_image(dstfd, name)
            checked = R1005.verify_image(dstfd, name, expected,
                                         seconds=R1005.MAX_SECONDS)
            results[name] = {"sha256": expected, "bytes": checked["bytes"],
                             "messages": checked["messages"]}
        need(set(os.listdir(dstfd)) == set(NAMES),
             "DESTINATION_NOT_TWO_IMAGES_STOP")
        need(all(inspect_source_fd(srcfd, n) == first[n] for n in NAMES),
             "SOURCE_FINAL_DRIFT_STOP")
        need(time.monotonic() - start <= MAX_SECONDS,
             "BACKUP_TOTAL_TIME_STOP")
        return {"images": results, "image_count": 2,
                "sql_integrity": "PASS",
                "original_source_provenance": "NOT_PROVEN",
                "both_database_common_writer_epoch": "NOT_PROVEN",
                "source_metadata_unchanged": "NOT_PROVEN",
                "all_writers_fenced": "NO",
                "original_oci_retirement": "STRICT_NO_GO"}
    finally:
        if dstfd is not None:
            os.close(dstfd)
        if parentfd is not None:
            os.close(parentfd)
        os.close(srcfd)


def main():
    p = argparse.ArgumentParser(description="OFFHOST two SQLite images only")
    p.add_argument("--source-copy", required=True)
    p.add_argument("--new-destination", required=True)
    args = p.parse_args()
    result = backup_pair(Path(args.source_copy), Path(args.new_destination))
    print("FLOP_R1055_OFFHOST_TWO_SQLITE_IMAGES_INTEGRITY_PASS")
    print("FLOP_R1055_IMAGE_COUNT=2")
    print("FLOP_R1055_TOTAL_BYTES=" +
          str(sum(x["bytes"] for x in result["images"].values())))
    print("FLOP_R1055_COMMON_WRITER_EPOCH=NOT_PROVEN")
    print("FLOP_R1055_ORIGINAL_SOURCE_PROVENANCE=NOT_PROVEN")
    print("FLOP_R1055_OCI_RETIREMENT=STRICT_NO_GO")


if __name__ == "__main__":
    try:
        main()
    except (Stop, R1005.Stop, OSError, sqlite3.Error, ValueError, TypeError):
        print("FLOP_R1055_STOP=GUARD_OR_BACKUP_STOP")
        sys.exit(42)
