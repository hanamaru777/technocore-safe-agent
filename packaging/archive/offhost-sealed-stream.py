#!/usr/bin/env python3
"""R1001 off-host-only authenticated encrypted *byte stream* carrier.

This deliberately does NOT establish original source provenance, cross-writer
consistency, SQLite backup correctness, same-DID continuity, or cutover safety.
Pass source bytes over an authenticated SSH pipe; only encrypted shards persist
in the offhost workdir. Never run on the original OCI or AWS K137 live host.

Format is independently restorable within this implementation; intentionally
v1 frozen. Do not rename existing ciphertext part files or edit the receipt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HEADER_MAGIC = b"FLOPENV1"
PART_MAGIC = b"FLOPPART"
COMMIT_MAGIC = b"FLOPCMT1"
HEADER = struct.Struct(">8s16s16s4sII")
PART_HEADER = struct.Struct(">8s16sI")
FRAME = struct.Struct(">II")
COMMIT_HEADER = struct.Struct(">8sI")
CHUNK_BYTES = 1024 * 1024
SHARD_LIMIT = 128 * 1024 * 1024
MAX_PARTS = 256
MAX_CHUNKS = 65_536
MAX_SOURCE_BYTES = 64 * 1024**3
ITERATIONS = 600_000
STOP_TAG = "FLOP_R1001_SEALED_STREAM_STOP="
HEX = re.compile(r"[0-9a-f]{64}\Z")


class Stop(Exception):
    pass


def need(condition, code):
    if not condition:
        raise Stop(code)


def guard_offhost():
    need(sys.platform == "linux" and os.geteuid() != 0,
         "OFFHOST_LINUX_NONROOT_REQUIRED")
    need(not Path("/opt/technocore-safe-agent").exists()
         and not Path("/opt/tradebot-k137").exists(),
         "LIVE_HOST_REFUSED")


def private_file(path: Path) -> bytes:
    need(path.is_absolute(), "SECRET_ABSOLUTE_PATH_REQUIRED")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    owned_dir(path.parent)
    fd = os.open(path, flags)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1
             and s.st_uid == os.geteuid() and not (s.st_mode & 0o077)
             and 0 < s.st_size <= 1024,
             "SECRET_FILE_CUSTODY_STOP")
        raw = os.read(fd, 1025).strip()
        need(HEX.fullmatch(raw.decode("ascii")) is not None,
             "SECRET_FILE_FORMAT_STOP")
        return raw
    finally:
        os.close(fd)


def key_for(secret, salt):
    return hashlib.pbkdf2_hmac("sha256", secret, salt, ITERATIONS, dklen=32)


def fsync_parent(directory: Path):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def owned_dir(directory: Path):
    need(directory.is_absolute() and ".." not in directory.parts,
         "DIR_ABSOLUTE_REQUIRED")
    need(not directory.is_symlink(), "DIR_SYMLINK_STOP")
    s = os.lstat(directory)
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == os.geteuid()
         and not (s.st_mode & 0o077), "DIR_CUSTODY_STOP")


def write_new_file(directory: Path, name: str, blob: bytes):
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
             | getattr(os, "O_CLOEXEC", 0))
    fd = os.open(directory / name, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as file:
            file.write(blob)
            file.flush()
            os.fsync(file.fileno())
    finally:
        os.close(fd)
    fsync_parent(directory)


def init_secret(path: Path):
    guard_offhost()
    need(path.is_absolute() and path.parent.is_dir(),
         "SECRET_DEST_ABSOLUTE_REQUIRED")
    # Prefer a private directory, never blindly adjust someone else's perms.
    owned_dir(path.parent)
    need(not path.exists() and not path.is_symlink(), "SECRET_ALREADY_EXISTS_STOP")
    write_new_file(path.parent, path.name, os.urandom(32).hex().encode() + b"\n")
    print("FLOP_R1001_NEW_RANDOM_ARCHIVE_SECRET_FILE=CREATED_PRIVATE_0600")
    print("FLOP_R1001_SECRET_BYTES_NOT_PRINTED=YES")
    print("FLOP_R1001_KEEP_SECRET_SEPARATE_FROM_ARCHIVE=YES")


class Writer:
    def __init__(self, root: Path, hdr: bytes, archive_id: bytes):
        self.root, self.hdr, self.aid = root, hdr, archive_id
        self.fd = None
        self.part_index = 0
        self.part_bytes = 0
        self.hash = None
        self.parts = []

    def open_part(self):
        need(self.part_index < MAX_PARTS, "TOO_MANY_SHARDS_STOP")
        name = f"part-{self.part_index:04d}.bin"
        self.fd = os.open(self.root / name,
                          os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                          0o600)
        prefix = PART_HEADER.pack(PART_MAGIC, self.aid, self.part_index)
        position = 0
        while position < len(prefix):
            n = os.write(self.fd, prefix[position:])
            need(n > 0, "WRITE_FAILED_STOP")
            position += n
        self.part_bytes = len(prefix)
        self.hash = hashlib.sha256(prefix)

    def emit(self, bytes_out: bytes):
        written = 0
        while written < len(bytes_out):
            x = os.write(self.fd, bytes_out[written:])
            need(x > 0, "WRITE_FAILED_STOP")
            written += x
        self.part_bytes += len(bytes_out)
        self.hash.update(bytes_out)

    def close_part(self):
        if self.fd is None:
            return
        os.fsync(self.fd)
        os.close(self.fd)
        self.fd = None
        self.parts.append({"name": f"part-{self.part_index:04d}.bin",
                           "bytes": self.part_bytes,
                           "sha256": self.hash.hexdigest()})
        self.part_index += 1
        fsync_parent(self.root)

    def chunk(self, frame: bytes):
        if self.fd is None:
            self.open_part()
        if self.part_bytes > PART_HEADER.size and self.part_bytes + len(frame) > SHARD_LIMIT:
            self.close_part()
            self.open_part()
        self.emit(frame)


def seal(root: Path, secret_path: Path):
    guard_offhost()
    need(root.is_absolute() and root.parent.is_dir()
         and not root.exists() and not root.is_symlink(),
         "NEW_ARCHIVE_DIR_REQUIRED")
    owned_dir(root.parent)
    need(not os.isatty(0), "STDIN_PIPE_REQUIRED")
    recovery_material = private_file(secret_path)
    salt, archive_id, nonce_prefix = os.urandom(16), os.urandom(16), os.urandom(4)
    hdr = HEADER.pack(HEADER_MAGIC, salt, archive_id, nonce_prefix,
                      ITERATIONS, CHUNK_BYTES)
    aad = hashlib.sha256(hdr).digest()
    aes = AESGCM(key_for(recovery_material, salt))
    recovery_material = b""
    os.mkdir(root, mode=0o700)
    owned_dir(root)
    fsync_parent(root.parent)
    write_new_file(root, "header.bin", hdr)
    out = Writer(root, hdr, archive_id)
    plain_hash, plain_bytes, chunk_index = hashlib.sha256(), 0, 0
    try:
        while True:
            b = sys.stdin.buffer.read(CHUNK_BYTES)
            if not b:
                break
            need(chunk_index < MAX_CHUNKS and plain_bytes + len(b) <= MAX_SOURCE_BYTES,
                 "ARCHIVE_INPUT_LIMIT_STOP")
            plain_hash.update(b)
            plain_bytes += len(b)
            compressed = zlib.compress(b, 1)
            seq = struct.pack(">Q", chunk_index)
            nonce = nonce_prefix + seq
            encrypted = aes.encrypt(nonce, compressed, aad + seq + struct.pack(">I", len(b)))
            frame = FRAME.pack(len(b), len(encrypted)) + encrypted
            out.chunk(frame)
            chunk_index += 1
        need(chunk_index > 0, "EMPTY_SOURCE_REFUSED")
        out.close_part()
        commit = {"version": 1, "archive_id": archive_id.hex(),
                  "plaintext_bytes": plain_bytes,
                  "plaintext_sha256": plain_hash.hexdigest(),
                  "chunks": chunk_index, "parts": out.parts}
        commit_raw = json.dumps(commit, sort_keys=True, separators=(",", ":")).encode()
        payload = aes.encrypt(nonce_prefix + b"\xff" * 8,
                              commit_raw, aad + b"FINAL")
        write_new_file(root, "commit.bin",
                       COMMIT_HEADER.pack(COMMIT_MAGIC, len(payload)) + payload)
    except BaseException:
        out.close_part()  # intentionally retain incomplete encrypted shards for diagnostics
        raise
    print("FLOP_R1001_ENCRYPTION_COMPLETED=YES")
    print("FLOP_R1001_ENCRYPTED_PARTS=" + str(len(out.parts)))
    print("FLOP_R1001_PLAINTEXT_BYTES=" + str(plain_bytes))
    print("FLOP_R1001_PLAINTEXT_NOT_WRITTEN_TO_DISK=YES")
    print("FLOP_R1001_ORIGINAL_SOURCE_AUTHENTICITY_NOT_PROVEN=YES")
    print("FLOP_R1001_WRITER_EPOCH_NOT_PROVEN=YES")


def open_regular(root: Path, name: str, max_size: int | None = None):
    fd = os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid()
             and s.st_nlink == 1 and not (s.st_mode & 0o077),
             "CIPHERTEXT_FILE_CUSTODY_STOP")
        if max_size is not None:
            need(s.st_size <= max_size, "CIPHERTEXT_FILE_TOO_LARGE_STOP")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def exactly(file, n):
    result = bytearray()
    while len(result) < n:
        x = file.read(n - len(result))
        need(bool(x), "TRUNCATED_ARCHIVE_STOP")
        result.extend(x)
    return bytes(result)


def verify(root: Path, secret_path: Path):
    guard_offhost()
    owned_dir(root)
    with open_regular(root, "header.bin", HEADER.size) as f:
        header_bytes = f.read()
    need(len(header_bytes) == HEADER.size, "HEADER_SIZE_STOP")
    magic, salt, archive_id, prefix, iteration, size = HEADER.unpack(header_bytes)
    need(magic == HEADER_MAGIC and iteration == ITERATIONS and size == CHUNK_BYTES,
         "HEADER_UNSUPPORTED_STOP")
    aad = hashlib.sha256(header_bytes).digest()
    recovery_material = private_file(secret_path)
    aes = AESGCM(key_for(recovery_material, salt))
    recovery_material = b""
    with open_regular(root, "commit.bin", 256 * 1024) as f:
        payload = f.read()
    need(len(payload) > COMMIT_HEADER.size + 16, "COMMIT_TRUNCATED_STOP")
    cmagic, declared = COMMIT_HEADER.unpack(payload[:COMMIT_HEADER.size])
    need(cmagic == COMMIT_MAGIC and declared == len(payload) - COMMIT_HEADER.size,
         "COMMIT_SHAPE_STOP")
    try:
        commit_raw = aes.decrypt(prefix + b"\xff" * 8,
                                 payload[COMMIT_HEADER.size:], aad + b"FINAL")
    except Exception:
        raise Stop("COMMIT_AUTHENTICATION_STOP") from None
    need(len(commit_raw) < 128 * 1024, "COMMIT_TOO_LARGE_STOP")
    try:
        commit = json.loads(commit_raw)
    except (ValueError, UnicodeError):
        raise Stop("COMMIT_JSON_STOP") from None
    need(isinstance(commit, dict) and set(commit) == {
         "version", "archive_id", "plaintext_bytes", "plaintext_sha256",
         "chunks", "parts"} and commit["version"] == 1
         and commit["archive_id"] == archive_id.hex(),
         "COMMIT_SCHEMA_STOP")
    records = commit["parts"]
    need(isinstance(records, list) and 1 <= len(records) <= MAX_PARTS
         and type(commit["chunks"]) is int and 1 <= commit["chunks"] <= MAX_CHUNKS
         and type(commit["plaintext_bytes"]) is int
         and 0 < commit["plaintext_bytes"] <= MAX_SOURCE_BYTES
         and isinstance(commit["plaintext_sha256"], str)
         and HEX.fullmatch(commit["plaintext_sha256"]) is not None,
         "COMMIT_RANGE_STOP")
    expected_names = {"header.bin", "commit.bin"}
    for j, rec in enumerate(records):
        name = f"part-{j:04d}.bin"
        need(isinstance(rec, dict) and set(rec) == {"name", "bytes", "sha256"}
             and rec["name"] == name and type(rec["bytes"]) is int
             and 0 < rec["bytes"] <= SHARD_LIMIT + FRAME.size + 100
             and isinstance(rec["sha256"], str)
             and HEX.fullmatch(rec["sha256"]) is not None,
             "COMMIT_PART_SCHEMA_STOP")
        expected_names.add(name)
    need(set(os.listdir(root)) == expected_names, "UNEXPECTED_ARCHIVE_FILES_STOP")
    plain = hashlib.sha256()
    total, chunk_index = 0, 0
    for j, rec in enumerate(records):
        with open_regular(root, rec["name"], SHARD_LIMIT + FRAME.size + 100) as f:
            part_hash = hashlib.sha256()
            nread = 0
            h = exactly(f, PART_HEADER.size)
            part_hash.update(h)
            nread += len(h)
            need(PART_HEADER.unpack(h) == (PART_MAGIC, archive_id, j),
                 "PART_HEADER_STOP")
            while True:
                prefix_frame = f.read(FRAME.size)
                if not prefix_frame:
                    break
                need(len(prefix_frame) == FRAME.size, "FRAME_HEADER_TRUNCATED_STOP")
                orig_len, cipher_len = FRAME.unpack(prefix_frame)
                need(1 <= orig_len <= CHUNK_BYTES and 16 < cipher_len <= CHUNK_BYTES + 1024
                     and chunk_index < MAX_CHUNKS,
                     "FRAME_SIZE_STOP")
                cipher = exactly(f, cipher_len)
                part_hash.update(prefix_frame)
                part_hash.update(cipher)
                nread += len(prefix_frame) + len(cipher)
                seq = struct.pack(">Q", chunk_index)
                try:
                    compressed = aes.decrypt(prefix + seq, cipher,
                                             aad + seq + struct.pack(">I", orig_len))
                    dec = zlib.decompressobj()
                    recovered = dec.decompress(compressed, CHUNK_BYTES + 1)
                    need(dec.eof and not dec.unused_data and not dec.unconsumed_tail
                         and len(recovered) == orig_len,
                         "DECOMPRESS_SHAPE_STOP")
                except Stop:
                    raise
                except Exception:
                    raise Stop("FRAME_AUTHENTICATION_OR_COMPRESSION_STOP") from None
                total += len(recovered)
                need(total <= MAX_SOURCE_BYTES, "PLAIN_SIZE_LIMIT_STOP")
                plain.update(recovered)
                chunk_index += 1
            need(nread == rec["bytes"] and part_hash.hexdigest() == rec["sha256"],
                 "PART_DIGEST_STOP")
    need(chunk_index == commit["chunks"] and total == commit["plaintext_bytes"]
         and plain.hexdigest() == commit["plaintext_sha256"],
         "PLAIN_REASSEMBLY_STOP")
    print("FLOP_R1001_AUTHENTICATED_CIPHERTEXT_ROUNDTRIP=PASS")
    print("FLOP_R1001_ENCRYPTED_PARTS=" + str(len(records)))
    print("FLOP_R1001_PLAINTEXT_BYTES=" + str(total))
    print("FLOP_R1001_PLAINTEXT_NOT_WRITTEN_TO_DISK=YES")
    print("FLOP_R1001_ORIGINAL_SOURCE_AUTHENTICITY_NOT_PROVEN=YES")
    print("FLOP_R1001_WRITER_EPOCH_NOT_PROVEN=YES")
    print("FLOP_R1001_NOT_RETIREMENT_AUTHORITY=YES")


def main():
    cli = argparse.ArgumentParser(description="Offhost only confidential archive envelope")
    actions = cli.add_subparsers(dest="action", required=True)
    s = actions.add_parser("init-secret")
    s.add_argument("--secret-file", type=Path, required=True)
    for name in ("seal", "verify"):
        p = actions.add_parser(name)
        p.add_argument("--archive-dir", type=Path, required=True)
        p.add_argument("--secret-file", type=Path, required=True)
    opts = cli.parse_args()
    if opts.action == "init-secret":
        init_secret(opts.secret_file)
    elif opts.action == "seal":
        seal(opts.archive_dir, opts.secret_file)
    else:
        verify(opts.archive_dir, opts.secret_file)


if __name__ == "__main__":
    try:
        main()
    except (Stop, OSError, ValueError, UnicodeError) as error:
        code = str(error) if isinstance(error, Stop) else type(error).__name__
        print(STOP_TAG + code)
        sys.exit(42)
