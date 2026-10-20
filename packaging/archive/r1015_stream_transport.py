#!/usr/bin/env python3
"""R1015: bounded ciphertext wire for the existing FLOPENV1 format.

Source-only DRAFT. Sender runs on a separate non-root offhost computer, NOT
OCI original or AWS tradebot-k137. Receiver stores ciphertext only in a new
private directory. This is NOT a writer fence, storage authorization or
complete/independent restore. Never use for live state without a proven
all-writer epoch, authenticated expected source digest and owner approval.
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
import struct
import sys
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = Path(__file__).with_name("offhost-sealed-stream.py")
SPEC = importlib.util.spec_from_file_location("flop_r1001_wire_dependency", BASE)
FORMAT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FORMAT)

MAGIC = b"FLOPWIR1"
PACKET = struct.Struct(">cI")
END_PART = struct.Struct(">IQ32s")
FLOOR_BYTES = 20 * 1024**3
MAX_RECORD = FORMAT.CHUNK_BYTES + 2048
MAX_ARCHIVE_BYTES = FORMAT.MAX_PARTS * (FORMAT.SHARD_LIMIT + 1024)
STOP_TAG = "FLOP_R1015_STOP="


class Stop(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Stop(code)


def exact(stream, count):
    need(0 <= count <= MAX_RECORD, "RECORD_LIMIT_STOP")
    data = bytearray()
    while len(data) < count:
        b = stream.read(count - len(data))
        need(bool(b), "WIRE_TRUNCATED_STOP")
        data.extend(b)
    return bytes(data)


def packet(out, kind, value):
    need(len(kind) == 1 and len(value) <= MAX_RECORD, "WIRE_PACKET_RANGE_STOP")
    out.write(PACKET.pack(kind, len(value)))
    out.write(value)


def read_packet(stream):
    head = exact(stream, PACKET.size)
    kind, length = PACKET.unpack(head)
    return kind, exact(stream, length)


def full_write(fd, data):
    done = 0
    while done < len(data):
        n = os.write(fd, data[done:])
        need(n > 0, "CIPHERTEXT_WRITE_STOP")
        done += n


def seal_stream(source, output, recovery_path, expected_bytes, expected_sha):
    """Emit existing R1001 archive entries without ANY local ciphertext spool."""
    FORMAT.guard_offhost()
    need(type(expected_bytes) is int and 1 <= expected_bytes <= FORMAT.MAX_SOURCE_BYTES,
         "EXPECTED_SIZE_REQUIRED")
    need(isinstance(expected_sha, str)
         and FORMAT.HEX.fullmatch(expected_sha) is not None,
         "EXPECTED_DIGEST_REQUIRED")
    need(not os.isatty(source.fileno()), "SOURCE_PIPE_REQUIRED")
    material = FORMAT.private_file(recovery_path)
    salt, archive_id, nonce_prefix = os.urandom(16), os.urandom(16), os.urandom(4)
    hdr = FORMAT.HEADER.pack(FORMAT.HEADER_MAGIC, salt, archive_id,
                             nonce_prefix, FORMAT.ITERATIONS, FORMAT.CHUNK_BYTES)
    aad = hashlib.sha256(hdr).digest()
    aes = AESGCM(FORMAT.key_for(material, salt))
    material = b""
    output.write(MAGIC)
    packet(output, b"H", hdr)
    plain_sha = hashlib.sha256()
    plain_size, index, part_index = 0, 0, 0
    count_parts = 0
    records = []
    part_size, part_sha = 0, None

    def start_part():
        nonlocal part_size, part_sha
        need(part_index < FORMAT.MAX_PARTS, "PART_COUNT_STOP")
        prefix = FORMAT.PART_HEADER.pack(FORMAT.PART_MAGIC, archive_id, part_index)
        packet(output, b"P", prefix)
        part_size = len(prefix)
        part_sha = hashlib.sha256(prefix)

    def finish_part():
        nonlocal part_index, count_parts
        need(part_sha is not None, "PART_MISSING_STOP")
        digest = part_sha.digest()
        packet(output, b"E", END_PART.pack(part_index, part_size, digest))
        records.append({"name": f"part-{part_index:04d}.bin",
                        "bytes": part_size, "sha256": digest.hex()})
        part_index += 1
        count_parts += 1

    while True:
        plain = source.read(FORMAT.CHUNK_BYTES)
        if not plain:
            break
        need(index < FORMAT.MAX_CHUNKS and plain_size + len(plain) <= expected_bytes,
             "SOURCE_OVERLONG_STOP")
        plain_sha.update(plain)
        plain_size += len(plain)
        seq = struct.pack(">Q", index)
        cipher = aes.encrypt(nonce_prefix + seq, zlib.compress(plain, 1),
                             aad + seq + struct.pack(">I", len(plain)))
        frame = FORMAT.FRAME.pack(len(plain), len(cipher)) + cipher
        need(len(frame) <= MAX_RECORD, "FRAME_TOO_LARGE_STOP")
        if part_sha is None:
            start_part()
        elif part_size > FORMAT.PART_HEADER.size and part_size + len(frame) > FORMAT.SHARD_LIMIT:
            finish_part()
            start_part()
        packet(output, b"F", frame)
        part_sha.update(frame)
        part_size += len(frame)
        index += 1
    need(plain_size == expected_bytes and plain_sha.hexdigest() == expected_sha,
         "SOURCE_PIN_MISMATCH_STOP")
    finish_part()
    commit = {"version": 1, "archive_id": archive_id.hex(),
              "plaintext_bytes": plain_size, "plaintext_sha256": plain_sha.hexdigest(),
              "chunks": index, "parts": records}
    plain_commit = json.dumps(commit, separators=(",", ":"), sort_keys=True).encode()
    encrypted = aes.encrypt(nonce_prefix + b"\xff" * 8,
                            plain_commit, aad + b"FINAL")
    blob = FORMAT.COMMIT_HEADER.pack(FORMAT.COMMIT_MAGIC, len(encrypted)) + encrypted
    need(len(blob) <= 256 * 1024, "COMMIT_BOUND_STOP")
    packet(output, b"C", blob)
    packet(output, b"Z", b"")
    output.flush()
    return {"parts": count_parts, "plaintext_bytes": plain_size}


def private_parent(path):
    need(path.is_absolute() and ".." not in path.parts and path.name not in ("", ".", ".."),
         "DEST_ABSOLUTE_PATH_STOP")
    parent = path.parent
    need(parent.resolve(strict=True) == parent, "PARENT_SYMLINK_STOP")
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()
             and st.st_mode & 0o077 == 0, "PARENT_CUSTODY_STOP")
        return fd
    except BaseException:
        os.close(fd)
        raise


def enough_space(dirfd, amount, floor):
    st = os.fstatvfs(dirfd)
    need(st.f_bavail * st.f_frsize - amount >= floor, "DISK_FLOOR_STOP")


def receive_stream(source, dest, *, floor=FLOOR_BYTES):
    """Store untrusted ciphertext as a new, bounded, all-or-nothing *claim*.

    Not an authenticated restore: the separate recovery secret is needed to
    verify R1001 plaintext and commit independently on a different machine.
    On failure partial ciphertext remains QUARANTINED; it is never committed.
    """
    need(sys.platform == "linux" and os.geteuid() != 0,
         "LINUX_NONROOT_RECEIVER_ONLY")
    need(floor >= FLOOR_BYTES, "DISK_FLOOR_MINIMUM_STOP")
    need(exact(source, len(MAGIC)) == MAGIC, "WIRE_MAGIC_STOP")
    kind, hdr = read_packet(source)
    need(kind == b"H" and len(hdr) == FORMAT.HEADER.size, "HEADER_PACKET_STOP")
    fields = FORMAT.HEADER.unpack(hdr)
    need(fields[0] == FORMAT.HEADER_MAGIC
         and fields[4] == FORMAT.ITERATIONS and fields[5] == FORMAT.CHUNK_BYTES,
         "HEADER_FORMAT_STOP")
    archive_id = fields[2]
    pfd = private_parent(dest)
    dfd = None
    file_fd = None
    total = 0
    count = 0
    frames = 0
    stage = "PART"
    hashed = None
    part_size = 0
    try:
        # Exclusive creation; no overwrite, deletion or mutation of old archives.
        os.mkdir(dest.name, 0o700, dir_fd=pfd)
        os.fsync(pfd)
        dfd = os.open(dest.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                      dir_fd=pfd)
        enough_space(dfd, len(hdr), floor)

        def new_file(name, content):
            nonlocal file_fd
            file_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                              | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
            enough_space(dfd, len(content), floor)
            full_write(file_fd, content)
            os.fsync(file_fd)
            os.close(file_fd)
            file_fd = None

        new_file("header.bin", hdr)
        total += len(hdr)
        while True:
            kind, data = read_packet(source)
            if stage == "PART":
                if kind == b"C":
                    need(count > 0 and FORMAT.COMMIT_HEADER.size + 16 < len(data)
                         <= 256 * 1024, "EARLY_OR_BAD_COMMIT_STOP")
                    magic, declared = FORMAT.COMMIT_HEADER.unpack(
                        data[:FORMAT.COMMIT_HEADER.size])
                    need(magic == FORMAT.COMMIT_MAGIC
                         and declared == len(data) - FORMAT.COMMIT_HEADER.size,
                         "COMMIT_FORMAT_STOP")
                    need(total + len(data) <= MAX_ARCHIVE_BYTES,
                         "ARCHIVE_BOUND_STOP")
                    new_file("commit.bin", data)
                    total += len(data)
                    stage = "END"
                    continue
                need(kind == b"P" and len(data) == FORMAT.PART_HEADER.size
                     and count < FORMAT.MAX_PARTS,
                     "PART_PACKET_STOP")
                need(FORMAT.PART_HEADER.unpack(data) ==
                     (FORMAT.PART_MAGIC, archive_id, count), "PART_ID_STOP")
                file_fd = os.open(f"part-{count:04d}.bin",
                                  os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                  0o600, dir_fd=dfd)
                enough_space(dfd, len(data), floor)
                full_write(file_fd, data)
                hashed = hashlib.sha256(data)
                part_size = len(data)
                stage = "FRAME"
            elif stage == "FRAME":
                if kind == b"F":
                    need(len(data) >= FORMAT.FRAME.size + 17,
                         "FRAME_TRUNCATED_STOP")
                    n_plain, n_cipher = FORMAT.FRAME.unpack(data[:FORMAT.FRAME.size])
                    need(1 <= n_plain <= FORMAT.CHUNK_BYTES
                         and 16 < n_cipher <= FORMAT.CHUNK_BYTES + 1024
                         and n_cipher + FORMAT.FRAME.size == len(data)
                         and frames < FORMAT.MAX_CHUNKS
                         and part_size + len(data) <= FORMAT.SHARD_LIMIT + MAX_RECORD
                         and total + part_size + len(data) <= MAX_ARCHIVE_BYTES,
                         "FRAME_RANGE_STOP")
                    enough_space(dfd, len(data), floor)
                    full_write(file_fd, data)
                    hashed.update(data)
                    part_size += len(data)
                    frames += 1
                else:
                    need(kind == b"E" and len(data) == END_PART.size
                         and part_size > FORMAT.PART_HEADER.size,
                         "PART_END_STOP")
                    idx, size, digest = END_PART.unpack(data)
                    need(idx == count and size == part_size
                         and hashed.digest() == digest, "PART_DIGEST_STOP")
                    os.fsync(file_fd)
                    os.close(file_fd)
                    file_fd = None
                    total += part_size
                    count += 1
                    stage = "PART"
            else:
                need(kind == b"Z" and data == b"", "FINAL_PACKET_STOP")
                need(source.read(1) == b"", "TRAILING_WIRE_BYTES_STOP")
                os.fsync(dfd)
                os.fsync(pfd)
                return {"parts": count, "ciphertext_bytes": total,
                        "plaintext_not_written": True,
                        "restore_and_source_epoch_not_proven": True}
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if dfd is not None:
            os.close(dfd)
        os.close(pfd)


def main():
    cli = argparse.ArgumentParser(description="Offhost encrypted wire - DRAFT")
    cmd = cli.add_subparsers(dest="action", required=True)
    send = cmd.add_parser("send")
    send.add_argument("--secret-file", type=Path, required=True)
    send.add_argument("--expected-bytes", type=int, required=True)
    send.add_argument("--expected-sha256", required=True)
    recv = cmd.add_parser("receive")
    recv.add_argument("--archive-dir", type=Path, required=True)
    opts = cli.parse_args()
    if opts.action == "send":
        r = seal_stream(sys.stdin.buffer, sys.stdout.buffer, opts.secret_file,
                        opts.expected_bytes, opts.expected_sha256)
        print("FLOP_R1015_SENDER_ENCRYPTED_STREAM_COMPLETE=YES", file=sys.stderr)
        print("FLOP_R1015_ENCRYPTED_PARTS=" + str(r["parts"]), file=sys.stderr)
    else:
        r = receive_stream(sys.stdin.buffer, opts.archive_dir)
        print("FLOP_R1015_RECEIVER_CIPHERTEXT_DURABLE=YES")
        print("FLOP_R1015_ENCRYPTED_PARTS=" + str(r["parts"]))
        print("FLOP_R1015_INDEPENDENT_RESTORE_NOT_PROVEN=YES")
        print("FLOP_R1015_NOT_PRODUCTION_AUTHORITY=YES")


if __name__ == "__main__":
    try:
        main()
    except (Stop, FORMAT.Stop, OSError, ValueError, TypeError,
            UnicodeError) as error:
        msg = str(error) if isinstance(error, (Stop, FORMAT.Stop)) else type(error).__name__
        print(STOP_TAG + msg, file=sys.stderr)
        sys.exit(42)
