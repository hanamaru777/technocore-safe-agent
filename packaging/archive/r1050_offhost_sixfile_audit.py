#!/usr/bin/env python3
"""R1050 OFFHOST ONLY: six-file source-pin matching and SQLite-image audit.

This script never produces a migration-ready, common-writer-epoch, or
OCI-retirement GO verdict. Pin-map bytes are operator-supplied and are NOT
independent original-OCI provenance; no private ledger contents are printed.
Never execute on OCI production or the shared AWS Lightsail K137 host.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

BASE = Path(__file__).with_name("verify-capture-backup-images.py")
SPEC = importlib.util.spec_from_file_location("flop_r1005_offhost", BASE)
R1005 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R1005)

SQLITE = R1005.EXPECTED
LEDGER = (
    "oracle-signer-receipts.json",
    "autopilot-outbox.json",
    "nonces.json",
    "verified-did.json",
)
EXPECTED = frozenset((*SQLITE, *LEDGER))
MAX_JSON = 1024 * 1024
MAX_PINMAP = 4096
MAX_TOTAL_ENTRIES = 12
HEX64 = re.compile(r"[a-f0-9]{64}\Z")


class Stop(Exception):
    pass


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise Stop(reason)


def no_dupes(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "DUPLICATE_JSON_KEY_STOP")
        result[key] = value
    return result


def pin_map(value: bytes) -> dict[str, str]:
    need(isinstance(value, bytes) and len(value) <= MAX_PINMAP,
         "PIN_MAP_SIZE_STOP")
    try:
        obj = json.loads(value.decode("utf-8", "strict"),
                         object_pairs_hook=no_dupes)
    except (UnicodeError, ValueError, TypeError) as error:
        if isinstance(error, Stop):
            raise
        raise Stop("PIN_MAP_JSON_STOP") from None
    need(type(obj) is dict and set(obj) == {"schema_version", "pins"}
         and type(obj["schema_version"]) is int
         and obj["schema_version"] == 1,
         "PIN_MAP_SCHEMA_STOP")
    pins = obj["pins"]
    need(type(pins) is dict and set(pins) == EXPECTED,
         "PIN_MAP_SIX_NAMES_STOP")
    need(all(type(sha) is str and HEX64.fullmatch(sha)
             for sha in pins.values()), "PIN_MAP_HASH_STOP")
    return pins


def read_private_pin_map(path: Path) -> dict[str, str]:
    need(path.is_absolute() and ".." not in path.parts,
         "PIN_MAP_PATH_STOP")
    # R1005's fd-relative root walk blocks ancestor symlinks. O_NOFOLLOW
    # alone on the last leaf would NOT protect a symlinked parent directory.
    parent_fd = R1005.opened_dir(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_uid == os.geteuid()
                 and before.st_mode & 0o077 == 0
                 and 1 <= before.st_size <= MAX_PINMAP, "PIN_MAP_CUSTODY_STOP")
            data = os.read(fd, MAX_PINMAP + 1)
            need(len(data) == before.st_size
                 and fingerprint(os.fstat(fd)) == fingerprint(before),
                 "PIN_MAP_READ_OR_DRIFT_STOP")
            return pin_map(data)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def fingerprint(meta):
    return (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_nlink,
            meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)


def hash_private_ledger(dirfd: int, name: str, expected: str) -> int:
    need(name in LEDGER, "LEDGER_NAME_STOP")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                 dir_fd=dirfd)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid == os.geteuid()
             and before.st_mode & 0o077 == 0
             and 2 <= before.st_size <= MAX_JSON,
             "LEDGER_FILE_CUSTODY_STOP")
        sha = hashlib.sha256()
        count = 0
        while count < before.st_size:
            chunk = os.pread(fd, min(65536, before.st_size - count), count)
            need(bool(chunk), "LEDGER_TRUNCATION_STOP")
            count += len(chunk)
            sha.update(chunk)
        need(count == before.st_size
             and sha.hexdigest() == expected, "LEDGER_SHA256_STOP")
        need(fingerprint(os.fstat(fd)) == fingerprint(before),
             "LEDGER_DRIFT_STOP")
        return count
    finally:
        os.close(fd)


def audit_offhost(directory: Path, pins: dict[str, str]) -> dict[str, int]:
    need(set(pins) == EXPECTED, "SIX_PIN_COVERAGE_STOP")
    fd = R1005.opened_dir(directory)
    try:
        # Reject unknown siblings, journals, WAL/SHM sidecars and links.
        # A portable archive is exactly these six regular data images.
        children = os.listdir(fd)
        need(len(children) <= MAX_TOTAL_ENTRIES and set(children) == EXPECTED,
             "ARCHIVE_EXACT_SIX_FILES_STOP")
        result = {}
        for name in SQLITE:
            result[name] = R1005.verify_image(fd, name, pins[name])["bytes"]
        for name in LEDGER:
            result[name] = hash_private_ledger(fd, name, pins[name])
        need(set(result) == EXPECTED, "ARCHIVE_COVERAGE_STOP")
        return result
    finally:
        os.close(fd)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--directory", required=True)
    ap.add_argument("--pin-map", required=True)
    args = ap.parse_args()
    R1005.live_host_refusal()
    pins = read_private_pin_map(Path(args.pin_map))
    result = audit_offhost(Path(args.directory), pins)
    print("FLOP_R1050_SIX_PINNED_FILES_AND_TWO_SQLITE_IMAGES_PASS")
    print("FLOP_R1050_IMAGE_COUNT=2")
    print("FLOP_R1050_PRIVATE_LEDGER_COUNT=4")
    print("FLOP_R1050_TOTAL_BYTES=" + str(sum(result.values())))
    print("FLOP_R1050_PRIVATE_LEDGER_SCHEMA=NOT_VERIFIED")
    print("FLOP_R1050_PIN_MAP_SOURCE_AUTHENTICITY=NOT_PROVEN")
    print("FLOP_R1050_PINNED_FILES_ORIGINAL_OCI_PROVENANCE=NOT_PROVEN")
    print("FLOP_R1050_COMMON_WRITER_EPOCH=NOT_PROVEN")
    print("FLOP_R1050_EXTERNAL_SIGNER_POST_AND_NONCE=NOT_PROVEN")
    print("FLOP_R1050_ALL_WRITERS_FENCED=NO")
    print("FLOP_R1050_NO_EXPLICIT_FILE_WRITES=YES")
    print("FLOP_R1050_ARCHIVE_ATIME_UNCHANGED=NOT_PROVEN")
    print("FLOP_R1050_OCI_RETIREMENT=STRICT_NO_GO")


if __name__ == "__main__":
    try:
        main()
    except (Stop, R1005.Stop, OSError, ValueError, TypeError,
            json.JSONDecodeError) as error:
        why = str(error) if isinstance(error, (Stop, R1005.Stop)) else "GUARD_STOP"
        print("FLOP_R1050_STOP=" + why)
        sys.exit(42)
