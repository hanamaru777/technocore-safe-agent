"""R1066: bounded *ciphertext-only* SSH pipe endpoints (not a live migration runner).

This module never reads archive recovery material, Oracle state, Vault, or TradeBot.
The sender consumes an ALREADY sealed immutable R1001 archive on an authorized
offhost POSIX copy. The receiver writes ciphertext only into an owner-approved
K137 quarantine root (fixed path); cannot restore, launch or authorize cutover.

SSH/host-key authentication, operator enrollment, cgroup and source-admission
are EXTERNAL preconditions, not established by executing these functions.
Never pipe secrets/unencrypted source through this interface.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

# Real K137's private landing directory must be separately approved/created.
LANDING = Path("/var/lib/flop-migration-r1066")
MAX_PART = 128 * 1024 * 1024 + 4096
CHUNK = 1024 * 1024
FILE = re.compile(r"(?:header\.bin|commit\.bin|part-[0-9]{4}\.bin)\Z")
ID = re.compile(r"[0-9a-f]{32}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")

class Stop(ValueError):
    pass

def need(condition, code):
    if not condition:
        raise Stop(code)

def private_dir(path):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts, "PATH_STOP")
    # Parent chain must not contain a symlink. Its system-owned directories
    # need not be 0700; the actual landing itself must be 0700.
    for item in (path, *path.parents):
        need(not item.is_symlink(), "PATH_LINK_STOP")
    s = path.lstat()
    need(stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o700
         and s.st_uid == os.geteuid(), "PRIVATE_OWNER_STOP")
    return path

def sha_validate(value):
    need(type(value) is str and DIGEST.fullmatch(value), "DIGEST_STOP")
    return value

def name_validate(value):
    need(type(value) is str and FILE.fullmatch(value), "FILE_NAME_STOP")
    return value

def id_validate(value):
    need(type(value) is str and ID.fullmatch(value), "ARCHIVE_ID_STOP")
    return value

def positive_size(value):
    need(type(value) is int and 0 < value <= MAX_PART, "FILE_SIZE_STOP")
    return value

def exact_file(path, *, expected_size=None):
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    s = os.fstat(fd)
    try:
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and
             s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o600
             and 0 < s.st_size <= MAX_PART and
             (expected_size is None or s.st_size == expected_size), "FILE_CUSTODY_STOP")
        return fd, (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    except BaseException:
        os.close(fd)
        raise

def hash_fd(fd):
    h = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        data = os.read(fd, CHUNK)
        if not data: break
        h.update(data)
    return h.hexdigest()

def send_part(archive, name, expected_size, expected_sha, offset, output):
    """Write only a PINNED ciphertext file suffix as raw binary bytes."""
    archive = private_dir(archive)
    name_validate(name); positive_size(expected_size); sha_validate(expected_sha)
    need(type(offset) is int and 0 <= offset < expected_size, "OFFSET_STOP")
    need((archive / "commit.bin").is_file(), "ARCHIVE_UNCOMMITTED")
    fd, original = exact_file(archive / name, expected_size=expected_size)
    try:
        need(hash_fd(fd) == expected_sha, "SOURCE_HASH_STOP")
        os.lseek(fd, offset, os.SEEK_SET)
        remaining = expected_size - offset
        while remaining:
            data = os.read(fd, min(CHUNK, remaining))
            need(bool(data), "SOURCE_TRUNCATED")
            output.write(data)
            remaining -= len(data)
        s = os.fstat(fd)
        need((s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns) == original,
             "SOURCE_DRIFT")
    finally:
        os.close(fd)

def _stage_root(landing, archive_id):
    private_dir(landing)
    id_validate(archive_id)
    # No mkdir or chmod of original host roots; no ownership changes.
    root = landing / "incoming" / archive_id
    private_dir(landing / "incoming")
    return private_dir(root)

def status(landing, archive_id, name):
    """Read only the safely staged ciphertext offset/hash, not live receipts."""
    name_validate(name)
    root = _stage_root(landing, archive_id)
    final = root / name
    partial = root / (name + ".partial")
    need(not (final.exists() and partial.exists()), "TWO_COPIES_STOP")
    existing = final if final.exists() else partial
    if not existing.exists():
        return {"state":"ABSENT", "offset":0, "sha256":hashlib.sha256(b"").hexdigest()}
    fd, meta = exact_file(existing)
    try:
        return {"state":"COMPLETE" if existing == final else "PARTIAL",
                "offset":meta[2], "sha256":hash_fd(fd)}
    finally:
        os.close(fd)

def receive_part(landing, archive_id, name, expected_size, expected_sha,
                 offset, expected_prefix_sha, input_stream):
    """Append and commit ONLY authenticated-length ciphertext. Never overwrite."""
    name_validate(name); positive_size(expected_size); sha_validate(expected_sha)
    sha_validate(expected_prefix_sha)
    need(type(offset) is int and 0 <= offset < expected_size, "OFFSET_STOP")
    root = _stage_root(landing, archive_id)
    final, partial = root / name, root / (name + ".partial")
    need(not final.exists() and not final.is_symlink(), "ALREADY_COMPLETE_STOP")
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os,"O_CLOEXEC",0)
    fd = os.open(partial, flags, 0o600)
    try:
        meta = os.fstat(fd)
        need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and
             meta.st_uid == os.geteuid() and stat.S_IMODE(meta.st_mode) == 0o600
             and meta.st_size == offset, "PARTIAL_CUSTODY_STOP")
        h = hashlib.sha256()
        os.lseek(fd, 0, os.SEEK_SET)
        left = offset
        while left:
            data = os.read(fd, min(CHUNK,left))
            need(bool(data), "PREFIX_TRUNCATED")
            h.update(data); left -= len(data)
        need(h.hexdigest() == expected_prefix_sha, "PREFIX_MISMATCH_STOP")
        os.lseek(fd, offset, os.SEEK_SET)
        remaining = expected_size - offset
        while remaining:
            data = input_stream.read(min(CHUNK, remaining))
            need(type(data) is bytes and bool(data), "STREAM_TRUNCATED")
            h.update(data)
            pos = 0
            while pos < len(data):
                written = os.write(fd, data[pos:])
                need(written > 0, "WRITE_STOP")
                pos += written
            remaining -= len(data)
        # A following byte means somebody sent a different stream than enrolled.
        need(input_stream.read(1) == b"", "STREAM_OVERRUN_STOP")
        need(h.hexdigest() == expected_sha, "CIPHERTEXT_SHA_STOP")
        os.fsync(fd)
    finally:
        os.close(fd)
    # Commit is explicitly LAST, after all expected parts are already present.
    # This is still staging, NOT proof of a decrypted R1001 archive.
    if name == "commit.bin":
        need((root / "header.bin").is_file() and
             any(root.glob("part-[0-9][0-9][0-9][0-9].bin")), "COMMIT_ORDER_STOP")
    os.link(partial, final)  # O_EXCL-like: cannot replace an existing file.
    os.unlink(partial)
    d = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(d)
    finally: os.close(d)
    return {"operation":"CIPHERTEXT_STAGED_ONLY", "bytes":expected_size,
            "live_restore":"NOT_PERFORMED", "cutover":"NO_GO",
            "oci_retirement":"STRICT_NO_GO"}

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="action", required=True)
    for action in ("status","receive","send"):
        q = sub.add_parser(action)
        q.add_argument("--archive-id",required=True)
        q.add_argument("--file",required=True)
        if action == "send":
            q.add_argument("--source",required=True)
        if action in ("receive","send"):
            q.add_argument("--bytes",type=int,required=True)
            q.add_argument("--sha256",required=True)
            q.add_argument("--offset",type=int,required=True)
        if action == "receive":
            q.add_argument("--prefix-sha256",required=True)
    a = p.parse_args()
    try:
        id_validate(a.archive_id); name_validate(a.file)
        if a.action == "status":
            print(json.dumps(status(LANDING,a.archive_id,a.file),sort_keys=True))
        elif a.action == "send":
            send_part(Path(a.source),a.file,a.bytes,a.sha256,a.offset,sys.stdout.buffer)
        else:
            print(json.dumps(receive_part(LANDING,a.archive_id,a.file,a.bytes,a.sha256,
                                          a.offset,a.prefix_sha256,sys.stdin.buffer),
                             sort_keys=True))
    except (Stop, OSError, ValueError, TypeError):
        # Fixed redacted stderr; no private file paths or invalid values.
        print("R1066_CIPHERTEXT_PIPE_STOP",file=sys.stderr)
        return 42
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
