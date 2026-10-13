#!/usr/bin/env python3
"""R864: SEPARATE HOST ONLY. Seal already staged snapshot into #851 manifest.

Never reads OCI/AWS services, fetches secrets, signs, copies or uploads.
It does read local staged *file contents* to hash them, so run only in a
trusted isolated environment after separate secure snapshot transfer.
This cannot establish a cold writer epoch, completeness of source snapshot,
or authorization to delete Oracle Compute.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

BUFFER = 128 * 1024
MAX_FILES = 512
MAX_TOTAL = 6 * 1024 ** 3
MAX_MANIFEST = 256 * 1024
MANIFEST = "RETIREMENT-MANIFEST.json"
KIND = "flop-retirement-offhost-v1"


class Stop(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Stop(reason)


def contract():
    path = Path(__file__).resolve().with_name("retirement_archive_contract.py")
    require(path.is_file(), "CONTRACT_NOT_INSTALLED")
    spec = importlib.util.spec_from_file_location("flop_r861_archive_contract", path)
    require(spec is not None and spec.loader is not None, "CONTRACT_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checked_dir(root):
    require(root.is_absolute(), "ABSOLUTE_STAGE_REQUIRED")
    path = Path(root.anchor)
    for name in root.parts[1:]:
        path = path / name
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                "STAGE_PARENT_NOT_PRIVATE_DIRECTORY")
    require(root.stat().st_uid == os.geteuid() and
            not (root.stat().st_mode & 0o022), "STAGE_NOT_PRIVATE_OR_OWNED")
    require(not Path("/opt/technocore-safe-agent").exists() and
            not Path("/opt/tradebot-k137").exists(), "NOT_AN_ISOLATED_HOST")


def regular_under(root, name):
    parts = name.split("/")
    require(len(parts) <= 8 and parts[0] in ("state", "capture") and
            all(part and part not in (".", "..") and "\\" not in part
                for part in parts), "INVALID_STAGE_RELATIVE_PATH")
    path = root
    for i, part in enumerate(parts):
        path = path / part
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode), "STAGE_SYMLINK_STOP")
        require(stat.S_ISDIR(info.st_mode) if i < len(parts) - 1
                else stat.S_ISREG(info.st_mode), "STAGE_FILE_TYPE_STOP")
    require(info.st_nlink == 1, "STAGE_HARDLINK_STOP")
    return path


def enumerate_paths(root):
    """Read names only for exact coverage; stage is never a live source."""
    paths = set()
    dirs = 0
    def walk(directory, prefix):
        nonlocal dirs
        dirs += 1
        require(dirs <= 64, "STAGE_DIRECTORY_LIMIT")
        with os.scandir(directory) as scan:
            for item in scan:
                name = item.name
                require(name and name not in (".", "..") and
                        "/" not in name and "\\" not in name,
                        "STAGE_NAME_INVALID")
                rel = prefix + "/" + name if prefix else name
                require(len(rel) <= 250, "STAGE_NAME_TOO_LONG")
                info = item.stat(follow_symlinks=False)
                require(not stat.S_ISLNK(info.st_mode), "STAGE_SYMLINK_STOP")
                if stat.S_ISDIR(info.st_mode):
                    walk(Path(directory) / name, rel)
                else:
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                            "STAGE_NONREGULAR_STOP")
                    require(len(paths) < MAX_FILES + 1, "STAGE_FILE_LIMIT")
                    paths.add(rel)
    walk(root, "")
    return paths


def hash_stable(path, expected_size):
    require(type(expected_size) is int and 0 < expected_size <= 3*1024**3,
            "EXPECTED_SIZE_INVALID")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                before.st_size == expected_size, "STAGED_SIZE_MISMATCH")
        dig = hashlib.sha256()
        total = 0
        while True:
            part = os.read(fd, BUFFER)
            if not part:
                break
            total += len(part)
            require(total <= expected_size, "STAGED_FILE_GROWTH")
            dig.update(part)
        after = os.fstat(fd)
        require(total == expected_size and
                (before.st_dev, before.st_ino, before.st_size,
                 before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns),
                "STAGED_FILE_CHANGED_DURING_HASH")
        return dig.hexdigest()
    finally:
        os.close(fd)


def seal(root, capture_meta, state_meta):
    checked_dir(root)
    require(not os.path.lexists(root / MANIFEST), "MANIFEST_ALREADY_PRESENT")
    spec = contract()
    try:
        capture, state = spec.plan(capture_meta, state_meta)
    except spec.Stop as error:
        raise Stop("CONTRACT_" + str(error)) from None
    expected = {name: size for name, size in state}
    for entry, (_, source, target) in zip(capture_meta["files"], spec.DBS):
        require(entry["archive_file"] == source, "CAPTURE_ORDER_MISMATCH")
        require(target not in expected, "DESTINATION_COLLISION")
        expected[target] = entry["archive_size"]
    require(9 <= len(expected) <= MAX_FILES, "EXPECTED_FILE_COUNT_INVALID")
    require(sum(expected.values()) <= MAX_TOTAL, "EXPECTED_TOTAL_EXCESS")
    actual = enumerate_paths(root)
    require(actual == set(expected), "STAGE_FILES_NOT_EXACTLY_MANIFESTED")
    entries = []
    for name in sorted(expected):
        file = regular_under(root, name)
        entries.append({"path": name, "size": expected[name],
                        "sha256": hash_stable(file, expected[name])})
    doc = {"schema": 1, "kind": KIND, "source_commit": spec.SOURCE,
           "files": entries}
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    require(len(raw) <= MAX_MANIFEST, "MANIFEST_SIZE_EXCEEDED")
    # Exclusive creation; no overwrites/replays. fsync the file and parent.
    fd = os.open(root / MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as target:
            target.write(raw)
            target.flush()
            os.fsync(target.fileno())
        dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except Exception:
        # Leave visible incomplete manifest and STOP. NEVER claim sealed.
        raise
    return len(entries), hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True)
    parser.add_argument("--capture-metadata", required=True)
    parser.add_argument("--state-inventory", required=True)
    args = parser.parse_args()
    spec = contract()
    try:
        capture = spec.limited_json(Path(args.capture_metadata))
        inventory = spec.limited_json(Path(args.state_inventory))
    except spec.Stop as error:
        raise Stop("METADATA_" + str(error)) from None
    count, anchor = seal(Path(args.stage), capture, inventory)
    print("FLOP_R864_OFFHOST_STAGED_MANIFEST_SEALED count=" + str(count))
    print("FLOP_R864_EXTERNAL_MANIFEST_SHA256=" + anchor)
    print("FLOP_R864_NO_UPLOAD_NO_RESTORE_NO_WRITER_EPOCH_PROOF")
    print("FLOP_R864_ORACLE_DELETION_NOT_AUTHORIZED")


if __name__ == "__main__":
    try:
        main()
    except (Stop, OSError, ValueError, TypeError, KeyError) as error:
        print("FLOP_R864_SEAL_STOP=" +
              (str(error) if isinstance(error, Stop) else type(error).__name__))
        sys.exit(42)
