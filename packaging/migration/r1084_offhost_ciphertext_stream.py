"""R1084 bounded R1001-compatible encrypted stream for authorized OFFLINE roots.

No production admission, authentication enrollment, SSH, service stop/start,
Oracle access, DISARMED K137 restorer permission or cutover capability.
The source never stages 26GiB ciphertext locally. Its only output is a
binary stream of encrypted R1001 files; the receiving offhost filesystem
must have independent custody and capacity. Windows NTFS is NOT enrolled.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import struct
import sys
import zlib


def _transfer():
    spec = importlib.util.spec_from_file_location(
        "r1084_bounded_transfer", Path(__file__).with_name("r1066_transfer.py"))
    obj = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = obj
    spec.loader.exec_module(obj)
    return obj


T = _transfer()
C = T.C
MAGIC = b"FLOPST01"
HEADER = struct.Struct(">cI")
MAX_DATA = C.CHUNK_BYTES + 8192
MAX_NAME = 32
MAX_STREAM_BYTES = C.MAX_SOURCE_BYTES + 128 * 1024**2
RESERVE = 1024**3


class Stop(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise Stop(code)


def _exact(stream, count):
    need(type(count) is int and 0 <= count <= MAX_DATA, "WIRE_BOUND")
    out = bytearray()
    while len(out) < count:
        data = stream.read(count - len(out))
        need(type(data) is bytes and bool(data), "WIRE_TRUNCATED")
        out.extend(data)
    return bytes(out)


def _write_all(output, data):
    view = memoryview(data)  # no quadratic copies for short/write-limited pipes
    cursor = 0
    while cursor < len(view):
        n = output.write(view[cursor:])
        need(type(n) is int and 0 < n <= len(view) - cursor, "WIRE_OUTPUT_STOP")
        cursor += n


class Sender:
    def __init__(self, output):
        need(not (hasattr(output, "isatty") and output.isatty()), "TTY_OUTPUT_STOP")
        self.output, self.opened, self.length = output, False, 0
        _write_all(self.output, MAGIC)

    def record(self, tag, payload=b""):
        need(tag in (b"S", b"D", b"E", b"F") and type(payload) is bytes
             and len(payload) <= MAX_DATA, "WIRE_RECORD_STOP")
        _write_all(self.output, HEADER.pack(tag, len(payload)))
        if payload:
            _write_all(self.output, payload)

    def begin(self, name):
        need(not self.opened and len(name) <= MAX_NAME, "WIRE_ORDER_STOP")
        self.record(b"S", name.encode("ascii", "strict"))
        self.opened, self.length, self.digest = True, 0, hashlib.sha256()

    def write(self, data):
        need(self.opened and type(data) is bytes and data
             and len(data) <= MAX_DATA, "WIRE_WRITE_STOP")
        self.record(b"D", data)
        self.length += len(data)
        self.digest.update(data)

    def end(self):
        need(self.opened, "WIRE_END_STOP")
        self.record(b"E", struct.pack(">Q", self.length) + self.digest.digest())
        self.opened = False

    def finish(self):
        need(not self.opened, "WIRE_ORDER_STOP")
        self.record(b"F")


class StreamWriter:
    """The audited R1001 Writer part framing, without a source-host disk."""
    def __init__(self, wire, aid):
        self.wire, self.aid = wire, aid
        self.part_index, self.part_bytes = 0, 0
        self.parts, self.active = [], False

    def open_part(self):
        need(not self.active and self.part_index < C.MAX_PARTS, "PART_BOUND")
        self.wire.begin(f"part-{self.part_index:04d}.bin")
        prefix = C.PART_HEADER.pack(C.PART_MAGIC, self.aid, self.part_index)
        self.wire.write(prefix)
        self.digest = hashlib.sha256(prefix)
        self.part_bytes, self.active = len(prefix), True

    def emit(self, data):
        need(self.active and self.part_bytes + len(data) <= C.SHARD_LIMIT + 4096,
             "PART_SPACE_STOP")
        self.wire.write(data)
        self.digest.update(data)
        self.part_bytes += len(data)

    def close_part(self):
        if not self.active:
            return
        self.wire.end()
        self.parts.append({"name": f"part-{self.part_index:04d}.bin",
                           "bytes": self.part_bytes,
                           "sha256": self.digest.hexdigest()})
        self.part_index += 1
        self.active = False

    def chunk(self, data):
        if not self.active:
            self.open_part()
        if self.part_bytes > C.PART_HEADER.size and self.part_bytes + len(data) > C.SHARD_LIMIT:
            self.close_part()
            self.open_part()
        self.emit(data)


def seal_offline_to_stream(app, state, recovery, output, *, source_head):
    """Encrypt only two strictly OFFLINE roots, never the real unfenced OCI roots.

    Recovery material is independent of R987 / Vault seed. This function has
    no CLI credential injection path. A future SSH/owner transport requires
    independent review, owner approval and proven fenced acquisition.
    """
    roots, manifest, identities = T.census(app, state, source_head)
    return seal_manifest_to_stream(roots, manifest, identities, recovery, output)


def seal_manifest_to_stream(roots, manifest, identities, recovery, output, *, recensus=None):
    """Reuse R1001 framing for an inventory held by a separately admitted caller.

    No new live CLI/bypass: the ordinary entrypoint above remains offline-only.
    The R1089 caller rechecks its signed lease/kernel fence during iteration.
    """
    T.need(type(recovery) is bytes and len(recovery) >= 32, "RECOVERY_MISSING")
    salt, aid, prefix = os.urandom(16), os.urandom(16), os.urandom(4)
    hdr = C.HEADER.pack(C.HEADER_MAGIC, salt, aid, prefix, C.ITERATIONS, C.CHUNK_BYTES)
    aes = C.AESGCM(C.key_for(recovery, salt))
    aad = hashlib.sha256(hdr).digest()
    wire = Sender(output)
    wire.begin("header.bin")
    wire.write(hdr)
    wire.end()
    writer = StreamWriter(wire, aid)
    plain_hash = hashlib.sha256()
    pending = bytearray()
    total, index = 0, 0

    def emit(data):
        nonlocal total, index
        T.need(index < C.MAX_CHUNKS and total + len(data) <= C.MAX_SOURCE_BYTES,
               "STREAM_BOUND")
        seq = index.to_bytes(8, "big")
        cipher = aes.encrypt(prefix + seq, zlib.compress(data, 1),
                             aad + seq + len(data).to_bytes(4, "big"))
        writer.chunk(C.FRAME.pack(len(data), len(cipher)) + cipher)
        plain_hash.update(data)
        total += len(data)
        index += 1

    try:
        blocks = (T.pack(roots, manifest, identities) if recensus is None else
                  T.pack(roots, manifest, identities, recensus=recensus))
        for data in blocks:
            pending.extend(data)
            while len(pending) >= C.CHUNK_BYTES:
                emit(bytes(pending[:C.CHUNK_BYTES]))
                del pending[:C.CHUNK_BYTES]
        if pending:
            emit(bytes(pending))
        T.need(index > 0, "EMPTY_INPUT_STOP")
        writer.close_part()
        commit = {"version": 1, "archive_id": aid.hex(),
                  "plaintext_bytes": total, "plaintext_sha256": plain_hash.hexdigest(),
                  "chunks": index, "parts": writer.parts}
        encrypted = aes.encrypt(prefix + b"\xff" * 8, T.G.canonical(commit), aad + b"FINAL")
        final = C.COMMIT_HEADER.pack(C.COMMIT_MAGIC, len(encrypted)) + encrypted
        wire.begin("commit.bin")
        wire.write(final)
        wire.end()
        wire.finish()
    finally:
        pending[:] = b"\x00" * len(pending)
    return {"operation": "CIPHERTEXT_STREAM_EMITTED_ONLY",
            "files": len(manifest["entries"]), "plaintext_bytes": total,
            "source_epoch": manifest["epoch"], "restore": "NOT_PERFORMED",
            "cutover": "NO_GO", "oci_retirement": "STRICT_NO_GO"}


def receive_offhost_ciphertext(stream, target, *, quota_bytes):
    """Ciphertext-only offhost POSIX receiver. No decryption/recovery capability.

    Quota and existing offhost free space are independently checked before
    creating the candidate. An interrupted attempt cannot be resumed or
    silently accepted; it leaves a private, incomplete directory with no commit.
    """
    target = T.safe_path(target)
    need(not any(target == Path(p) or Path(p) in target.parents
                 for p in T.BLOCKED_ROOTS), "PROTECTED_TARGET_STOP")
    T.private_dir(target.parent)  # rejects Windows until audited NTFS ACL custody
    need(type(quota_bytes) is int and 0 < quota_bytes <= MAX_STREAM_BYTES,
         "QUOTA_STOP")
    need(not target.exists() and not target.is_symlink(), "DESTINATION_EXISTS_STOP")
    need(T.shutil.disk_usage(target.parent).free >= quota_bytes + RESERVE,
         "OFFHOST_SPACE_STOP")
    need(_exact(stream, len(MAGIC)) == MAGIC, "WIRE_MAGIC_STOP")
    target.mkdir(mode=0o700)
    received, file_index, opened, committed = 0, 0, None, False
    byte_count = 0
    try:
        while True:
            tag, count = HEADER.unpack(_exact(stream, HEADER.size))
            need(count <= MAX_DATA, "WIRE_BOUND")
            if tag == b"F":
                need(count == 0 and opened is None and committed, "WIRE_FINAL_STOP")
                need(stream.read(1) == b"", "WIRE_TRAILING_STOP")
                break
            if tag == b"S":
                need(opened is None and not committed and 0 < count <= MAX_NAME,
                     "WIRE_FILE_ORDER_STOP")
                raw_name = _exact(stream, count)
                need(raw_name.isascii(), "WIRE_NAME_STOP")
                name = raw_name.decode("ascii")
                part = f"part-{file_index - 1:04d}.bin"
                need(name == ("header.bin" if file_index == 0 else part)
                     or (name == "commit.bin" and 2 <= file_index <= C.MAX_PARTS + 1),
                     "WIRE_FILE_SEQUENCE_STOP")
                if name == "commit.bin":
                    committed = True  # any subsequent file BEGIN forbidden
                else:
                    need(file_index <= C.MAX_PARTS, "WIRE_PARTS_STOP")
                # Keep the authenticated final commit invisible until the
                # complete wire and terminal EOF have been verified.
                # An interrupted receipt must NEVER be mistaken for a usable archive.
                path = target / ("commit.bin.pending" if name == "commit.bin" else name)
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                opened = (fd, hashlib.sha256(), 0, name)
                file_index += 1
            elif tag == b"D":
                need(opened is not None and 0 < count <= MAX_DATA, "WIRE_DATA_ORDER_STOP")
                chunk = _exact(stream, count)
                fd, digest, length, name = opened
                bound = (C.HEADER.size if name == "header.bin" else
                         256 * 1024 if name == "commit.bin" else C.SHARD_LIMIT + 4096)
                need(length + count <= bound and received + count <= quota_bytes,
                     "WIRE_CAPACITY_STOP")
                cursor = 0
                while cursor < len(chunk):
                    wrote = os.write(fd, chunk[cursor:])
                    need(wrote > 0, "WIRE_DISK_STOP")
                    cursor += wrote
                digest.update(chunk)
                opened = (fd, digest, length + len(chunk), name)
                received += count
            elif tag == b"E":
                need(opened is not None and count == 40, "WIRE_END_ORDER_STOP")
                declared = _exact(stream, count)
                fd, digest, length, name = opened
                need(length > 0 and declared == struct.pack(">Q", length) +
                     digest.digest(), "WIRE_HASH_STOP")
                os.fsync(fd)
                os.close(fd)
                opened = None
                byte_count += 1
                # The final authenticated file is written only AFTER parts
                # and last in the wire sequence. AEAD verification is separate.
            else:
                raise Stop("WIRE_TYPE_STOP")
    finally:
        if opened is not None:
            os.close(opened[0])
    need(byte_count == file_index and 3 <= byte_count <= C.MAX_PARTS + 2,
         "WIRE_FINAL_COUNT_STOP")
    raw_header = (target / "header.bin").read_bytes()
    need(len(raw_header) == C.HEADER.size and
         C.HEADER.unpack(raw_header)[0] == C.HEADER_MAGIC,
         "ARCHIVE_HEADER_STOP")
    # After ALL wire checks, reveal the commit atomically, never overwrite.
    pending = target / "commit.bin.pending"
    need(pending.is_file() and not (target / "commit.bin").exists(),
         "WIRE_COMMIT_PROMOTION_STOP")
    os.link(pending, target / "commit.bin")
    os.unlink(pending)
    fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"operation": "OFFHOST_CIPHERTEXT_ONLY",
            "ciphertext_files": byte_count, "ciphertext_bytes": received,
            "aead_verified": False, "common_sqlite_epoch": "NOT_PROVEN",
            "live_restore": "NOT_PERFORMED", "cutover": "NO_GO",
            "oci_retirement": "STRICT_NO_GO"}
