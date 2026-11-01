"""Real local/offhost encrypted preservation and disarmed restore primitives.

No SSH/service/credential capability. A live transport/admission carrier remains
blocked until independently pinned destination and source authority exist.
Encryption framing is R1001, whose exact source is vendored without changes.
"""
from __future__ import annotations
import argparse
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import zlib


def load(name, leaf):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(leaf))
    obj = importlib.util.module_from_spec(spec)
    sys.modules[name] = obj
    spec.loader.exec_module(obj)
    return obj


C = load("r1066_cipher", "r1066_sealed_dependency.py")
G = load("r1066_gates", "r1063_release_gates.py")
MAX_MANIFEST = 16 * 1024**2
# R1080 real original OCI census 30,682 entries. This limit is finite and
# independently enforced both at source enumeration and at restore parsing.
MAX_ARCHIVE_ENTRIES = 100000
MAX_ARCHIVE_DEPTH = 48
HEAD = G.SOURCE_HEAD
CHUNK = C.CHUNK_BYTES
BLOCKED_ROOTS = ("/opt/technocore-safe-agent", "/var/lib/technocore-safe-agent",
                 "/opt/tradebot-k137", "/opt/tradebot-k137-private", "/opt/flop-shadow")


class Stop(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise Stop(code)


def safe_path(path):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts, "PATH_STOP")
    for p in (path, *path.parents):
        need(not p.is_symlink() and not p.is_junction(), "LINK_PATH_STOP")
    return path


def private_dir(path):
    path = safe_path(path)
    s = path.stat()
    need(stat.S_ISDIR(s.st_mode), "DIRECTORY_STOP")
    if os.name == "posix":
        need(s.st_uid == os.geteuid() and s.st_mode & 0o077 == 0, "CUSTODY_STOP")
    else:
        # Caller must establish real NTFS custody; do not mistake POSIX bits for ACL.
        raise Stop("WINDOWS_ACL_CARRIER_NOT_ENROLLED")
    return path


def offline_source(path):
    path = private_dir(path)
    need(not any(path == Path(p) or Path(p) in path.parents for p in BLOCKED_ROOTS), "LIVE_SOURCE_FENCE_UNPROVEN")
    return path


def fingerprint(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode)


def read_blocks(path, before):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        need(fingerprint(os.fstat(fd)) == before, "SOURCE_DRIFT")
        with os.fdopen(fd, "rb", closefd=False) as f:
            while data := f.read(CHUNK):
                yield data
        need(fingerprint(os.fstat(fd)) == before and fingerprint(path.lstat()) == before, "SOURCE_DRIFT")
    finally:
        os.close(fd)


def census(app, state, source_head):
    need(source_head == HEAD, "SOURCE_HEAD_STOP")
    roots = {"app": offline_source(app), "state": offline_source(state)}
    return _census_roots(roots, source_head)


def _census_roots(roots, source_head, *, epoch="PROVISIONAL_UNFENCED"):
    """Shared byte inventory; live callers must independently hold admission.

    The public census/CLI continue to enforce offline_source. R1089 supplies
    only the two fixed original roots after signed and kernel fence checks.
    """
    need(source_head == HEAD and set(roots) == {"app", "state"}, "SOURCE_HEAD_STOP")
    need(roots["app"] != roots["state"] and not any(a in b.parents for a, b in
         ((roots["app"], roots["state"]), (roots["state"], roots["app"]))), "ROOT_OVERLAP")
    rows, identities, links = [], {}, {}
    def visit(path, name, depth):
        need(len(rows) < MAX_ARCHIVE_ENTRIES and depth <= MAX_ARCHIVE_DEPTH
             and len(os.fsencode(name)) <= 4096, "CENSUS_BOUND")
        s = path.lstat()
        row = {"path": name, "mode": stat.S_IMODE(s.st_mode), "uid": s.st_uid, "gid": s.st_gid,
               "mtime_ns": s.st_mtime_ns, "kind": "", "size": 0, "sha256": None, "target": None}
        identities[name] = fingerprint(s)
        if stat.S_ISDIR(s.st_mode):
            row["kind"] = "directory"
        elif stat.S_ISLNK(s.st_mode):
            row.update(kind="symlink", target=os.readlink(path))
        elif stat.S_ISREG(s.st_mode):
            key = (s.st_dev, s.st_ino)
            if s.st_nlink > 1 and key in links:
                row.update(kind="hardlink", target=links[key])
            else:
                links[key] = name
                sha = hashlib.sha256()
                for data in read_blocks(path, identities[name]):
                    sha.update(data)
                row.update(kind="file", size=s.st_size, sha256=sha.hexdigest())
        else:
            raise Stop("SPECIAL_OBJECT_STOP")
        rows.append(row)
        if row["kind"] == "directory":
            for child in sorted(path.iterdir(), key=lambda p: os.fsencode(p.name)):
                visit(child, name + "/" + child.name, depth + 1)
    for name, path in roots.items():
        visit(path, name, 0)
    manifest = {"version": 1, "source_head": source_head, "epoch": epoch, "entries": rows}
    need(len(G.canonical(manifest)) <= MAX_MANIFEST, "MANIFEST_BOUND")
    return roots, manifest, identities


def resolve_source(roots, name):
    first, *tail = name.split("/")
    return roots[first].joinpath(*tail)


def pack(roots, manifest, identities, *, recensus=None):
    raw = G.canonical(manifest)
    yield len(raw).to_bytes(8, "big") + raw
    for row in manifest["entries"]:
        if row["kind"] == "file":
            yield from read_blocks(resolve_source(roots, row["path"]), identities[row["path"]])
    # Re-enumeration detects new/deleted files and directory/link drift too.
    _, current, again = (census(roots["app"], roots["state"], HEAD) if recensus is None
                         else recensus())
    need(current == manifest and again == identities, "SOURCE_TREE_DRIFT")


def seal(app, state, archive, recovery, *, source_head):
    """Never resume encryption: each new archive gets a fresh R1001 salt/nonce domain."""
    roots, manifest, identities = census(app, state, source_head)
    archive = safe_path(archive)
    private_dir(archive.parent)
    need(not archive.exists() and not any(p == archive or p in archive.parents for p in roots.values()), "NEW_ARCHIVE_REQUIRED")
    size = sum(r["size"] for r in manifest["entries"]) + MAX_MANIFEST
    need(size <= C.MAX_SOURCE_BYTES and shutil.disk_usage(archive.parent).free >= size + 1024**3, "SPACE_STOP")
    need(type(recovery) is bytes and len(recovery) >= 32, "RECOVERY_MISSING")
    salt, aid, prefix = os.urandom(16), os.urandom(16), os.urandom(4)
    hdr = C.HEADER.pack(C.HEADER_MAGIC, salt, aid, prefix, C.ITERATIONS, CHUNK)
    aes, aad = C.AESGCM(C.key_for(recovery, salt)), hashlib.sha256(hdr).digest()
    archive.mkdir(mode=0o700)
    C.write_new_file(archive, "header.bin", hdr)
    out = C.Writer(archive, hdr, aid)
    plain_hash, total, count, pending = hashlib.sha256(), 0, 0, bytearray()
    def emit(data):
        nonlocal count, total
        need(count < C.MAX_CHUNKS and total + len(data) <= C.MAX_SOURCE_BYTES, "STREAM_BOUND")
        seq = count.to_bytes(8, "big")
        cipher = aes.encrypt(prefix + seq, zlib.compress(data, 1), aad + seq + len(data).to_bytes(4, "big"))
        out.chunk(C.FRAME.pack(len(data), len(cipher)) + cipher)
        plain_hash.update(data); total += len(data); count += 1
    try:
        for data in pack(roots, manifest, identities):
            pending.extend(data)
            while len(pending) >= CHUNK:
                emit(bytes(pending[:CHUNK])); del pending[:CHUNK]
        if pending:
            emit(bytes(pending))
        out.close_part()
        commit = {"version": 1, "archive_id": aid.hex(), "plaintext_bytes": total,
                  "plaintext_sha256": plain_hash.hexdigest(), "chunks": count, "parts": out.parts}
        encrypted = aes.encrypt(prefix + b"\xff" * 8, G.canonical(commit), aad + b"FINAL")
        C.write_new_file(archive, "commit.bin", C.COMMIT_HEADER.pack(C.COMMIT_MAGIC, len(encrypted)) + encrypted)
    finally:
        out.close_part()
        pending[:] = b"\0" * len(pending)
    return summary("archive", files=len(manifest["entries"]), bytes_count=total)


def decrypt(archive, recovery):
    """R1001 authenticated ordered stream, bounded to one 1MiB plaintext chunk."""
    archive = private_dir(archive)
    yield from _decrypt_regular(archive, recovery,
                               lambda name, limit: C.open_regular(archive, name, limit))


def _decrypt_regular(archive, recovery, open_regular):
    """Same frozen crypto decoder with a platform-specific custody reader.

    R1089's Windows caller holds non-write/non-delete-shared NTFS handles and
    validates R1088 ACLs. The public POSIX decoder/CLI guard is unchanged.
    """
    with open_regular("header.bin", C.HEADER.size) as f:
        hdr = f.read()
    need(len(hdr) == C.HEADER.size, "HEADER_STOP")
    magic, salt, aid, prefix, iterations, chunk = C.HEADER.unpack(hdr)
    need(magic == C.HEADER_MAGIC and iterations == C.ITERATIONS and chunk == CHUNK, "HEADER_STOP")
    aes, aad = C.AESGCM(C.key_for(recovery, salt)), hashlib.sha256(hdr).digest()
    with open_regular("commit.bin", 256 * 1024) as f:
        raw = f.read()
    need(len(raw) > C.COMMIT_HEADER.size + 16, "INCOMPLETE_ARCHIVE")
    cmagic, length = C.COMMIT_HEADER.unpack(raw[:C.COMMIT_HEADER.size])
    need(cmagic == C.COMMIT_MAGIC and length == len(raw) - C.COMMIT_HEADER.size, "COMMIT_STOP")
    commit = G.decode(aes.decrypt(prefix + b"\xff" * 8, raw[C.COMMIT_HEADER.size:], aad + b"FINAL"))
    G.shape(commit, "version archive_id plaintext_bytes plaintext_sha256 chunks parts")
    need(commit["version"] == 1 and commit["archive_id"] == aid.hex(), "COMMIT_STOP")
    G.integer(commit["plaintext_bytes"], 1, C.MAX_SOURCE_BYTES); G.integer(commit["chunks"], 1, C.MAX_CHUNKS)
    need(type(commit["parts"]) is list and 1 <= len(commit["parts"]) <= C.MAX_PARTS, "PARTS_BOUND")
    expected = {"header.bin", "commit.bin"} | {f"part-{i:04d}.bin" for i in range(len(commit["parts"]))}
    need(set(p.name for p in archive.iterdir()) == expected, "ARCHIVE_SET_STOP")
    sha, total, count = hashlib.sha256(), 0, 0
    for i, row in enumerate(commit["parts"]):
        G.shape(row, "name bytes sha256")
        need(row["name"] == f"part-{i:04d}.bin", "PART_ORDER_STOP")
        G.digest(row["sha256"]); G.integer(row["bytes"], 1, C.SHARD_LIMIT + 1024)
        part_hash, read = hashlib.sha256(), 0
        with open_regular(row["name"], C.SHARD_LIMIT + 1024) as f:
            h = C.exactly(f, C.PART_HEADER.size)
            need(C.PART_HEADER.unpack(h) == (C.PART_MAGIC, aid, i), "PART_HEADER_STOP")
            part_hash.update(h); read += len(h)
            while h := f.read(C.FRAME.size):
                need(len(h) == C.FRAME.size, "FRAME_STOP")
                size, clen = C.FRAME.unpack(h)
                need(1 <= size <= CHUNK and 16 < clen <= CHUNK + 1024 and count < C.MAX_CHUNKS, "FRAME_BOUND")
                cipher = C.exactly(f, clen)
                part_hash.update(h + cipher); read += len(h) + len(cipher)
                seq = count.to_bytes(8, "big")
                compressed = aes.decrypt(prefix + seq, cipher, aad + seq + size.to_bytes(4, "big"))
                decoder = zlib.decompressobj()
                data = decoder.decompress(compressed, CHUNK + 1)
                need(len(data) == size and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail, "DECOMPRESS_STOP")
                sha.update(data); total += len(data); count += 1
                need(total <= C.MAX_SOURCE_BYTES, "STREAM_BOUND")
                yield data
        need(read == row["bytes"] and part_hash.hexdigest() == row["sha256"], "PART_HASH_STOP")
    need(count == commit["chunks"] and total == commit["plaintext_bytes"] and sha.hexdigest() == commit["plaintext_sha256"], "FINAL_HASH_STOP")


class Reader:
    def __init__(self, blocks):
        self.blocks, self.buffer = iter(blocks), bytearray()

    def read(self, size):
        need(0 <= size <= MAX_MANIFEST, "READ_BOUND")
        while len(self.buffer) < size:
            try:
                self.buffer.extend(next(self.blocks))
            except StopIteration:
                raise Stop("STREAM_TRUNCATED") from None
        value = bytes(self.buffer[:size]); del self.buffer[:size]
        return value

    def finish(self):
        need(not self.buffer, "TRAILING_DATA")
        need(next(self.blocks, None) is None, "TRAILING_DATA")


def relative(name):
    need(type(name) is str and len(os.fsencode(name)) <= 4096 and "\\" not in name, "NAME_STOP")
    parts = name.split("/")
    need(parts[0] in ("app", "state") and all(p not in ("", ".", "..") for p in parts), "NAME_STOP")
    return Path(*parts)


def restore(archive, target, recovery, *, quota):
    need(not any(Path(p).exists() for p in BLOCKED_ROOTS), "LIVE_RESTORER_AUTHORITY_NOT_ENROLLED")
    archive, target = private_dir(archive), safe_path(target)
    need(archive != target and archive not in target.parents and target not in archive.parents, "RESTORE_SCOPE_STOP")
    # Authenticate the complete archive BEFORE creating any plaintext destination.
    for _ in decrypt(archive, recovery):
        pass
    reader = Reader(decrypt(archive, recovery))
    size = int.from_bytes(reader.read(8), "big")
    need(size <= MAX_MANIFEST, "MANIFEST_BOUND")
    # Manifest can exceed the gate evaluator's 1 MiB packet limit, use strict pairs.
    m = json.loads(reader.read(size), object_pairs_hook=G._pairs)
    G.shape(m, "version source_head epoch entries")
    need(m["version"] == 1 and m["source_head"] == HEAD and m["epoch"] == "PROVISIONAL_UNFENCED", "MANIFEST_STOP")
    need(type(m["entries"]) is list and 2 <= len(m["entries"]) <= MAX_ARCHIVE_ENTRIES, "MANIFEST_BOUND")
    seen, total = {}, 0
    for row in m["entries"]:
        G.shape(row, "path mode uid gid mtime_ns kind size sha256 target")
        path = relative(row["path"])
        need(row["path"] not in seen, "DUPLICATE_PATH")
        if len(path.parts) > 1:
            need(str(path.parent).replace("\\", "/") in seen and seen[str(path.parent).replace("\\", "/")]["kind"] == "directory", "PARENT_STOP")
        need(row["kind"] in ("file", "directory", "hardlink", "symlink"), "KIND_STOP")
        G.integer(row["size"], 0, C.MAX_SOURCE_BYTES)
        if row["kind"] == "file":
            G.digest(row["sha256"]); total += row["size"]
        elif row["kind"] == "hardlink":
            need(row["target"] in seen and seen[row["target"]]["kind"] == "file", "HARDLINK_STOP")
        elif row["kind"] == "symlink":
            link = row["target"]
            need(type(link) is str and not Path(link).is_absolute() and "\\" not in link
                 and all(p != ".." for p in link.split("/")), "EXTERNAL_LINK_REVIEW_REQUIRED")
        seen[row["path"]] = row
    target = safe_path(target); private_dir(target.parent)
    need(not target.exists() and quota >= total and shutil.disk_usage(target.parent).free >= total + 1024**3, "RESTORE_SPACE_OR_EXISTS_STOP")
    need(not any(target == Path(p) or Path(p) in target.parents for p in BLOCKED_ROOTS), "LIVE_TARGET_STOP")
    target.mkdir(mode=0o700)
    # An interruption leaves a private incomplete candidate; never overwrite it.
    dbs = []
    for name, row in seen.items():
        path = target / relative(name)
        if row["kind"] == "directory":
            path.mkdir(mode=0o700)
        elif row["kind"] == "file":
            digest = hashlib.sha256()
            with path.open("xb") as f:
                os.chmod(path, 0o600)
                remaining = row["size"]
                while remaining:
                    data = reader.read(min(CHUNK, remaining)); remaining -= len(data)
                    f.write(data); digest.update(data)
                f.flush(); os.fsync(f.fileno())
            need(digest.hexdigest() == row["sha256"], "RESTORED_HASH_STOP")
            if path.name in G.DATABASES:
                dbs.append(path)
        elif row["kind"] == "hardlink":
            os.link(target / relative(row["target"]), path)
        else:
            path.symlink_to(row["target"])
    reader.finish()
    need(len(dbs) == 2 and {p.name for p in dbs} == set(G.DATABASES), "TWO_SQLITE_REQUIRED")
    cursors = []
    for db in dbs:
        with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as conn:
            conn.execute("PRAGMA trusted_schema=OFF")
            need(conn.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "SQLITE_INTEGRITY_STOP")
            cursors.append(conn.execute("SELECT count(*),coalesce(max(seq),0) FROM messages").fetchone())
    C.write_new_file(target, "DISARMED-RESTORE-RECEIPT.json", G.canonical({"schema_version": 1,
        "manifest_sha256": hashlib.sha256(G.canonical(m)).hexdigest(), "sqlite_cursors": cursors,
        "source_epoch": "PROVISIONAL_UNFENCED", "runtime_started": False}))
    return summary("restore", files=len(seen), bytes_count=total)


def copy_archive(source, destination):
    """Resumable ciphertext-only copy; never resumes encryption or trusts offsets."""
    source = private_dir(source); destination = safe_path(destination)
    private_dir(destination.parent)
    need(source != destination and source not in destination.parents, "COPY_SCOPE_STOP")
    names = sorted(source.iterdir())
    need(2 <= len(names) <= C.MAX_PARTS + 2 and {p.name for p in names} >= {"header.bin", "commit.bin"}, "INCOMPLETE_ARCHIVE")
    for p in names:
        need(p.name in ("header.bin", "commit.bin") or __import__("re").fullmatch(r"part-[0-9]{4}\.bin", p.name), "CIPHER_NAME_STOP")
        need(stat.S_ISREG(p.lstat().st_mode) and p.stat().st_nlink == 1 and p.stat().st_size <= C.SHARD_LIMIT + 1024, "CIPHER_OBJECT_STOP")
    need(shutil.disk_usage(destination.parent).free >= sum(p.stat().st_size for p in names) + 1024**3, "COPY_SPACE_STOP")
    if not destination.exists():
        destination.mkdir(mode=0o700)
    private_dir(destination)
    allowed = {p.name for p in names} | {p.name + ".partial" for p in names}
    need(set(p.name for p in destination.iterdir()) <= allowed, "COPY_UNKNOWN_STOP")
    for p in sorted(names, key=lambda p: (p.name == "commit.bin", p.name)):
        out, partial = destination / p.name, destination / (p.name + ".partial")
        if out.exists():
            need(not out.is_symlink() and out.stat().st_nlink == 1 and out.stat().st_size == p.stat().st_size, "COPY_EXISTING_STOP")
            a, b = hashlib.sha256(), hashlib.sha256()
            for path, digest in ((p, a), (out, b)):
                for data in read_blocks(path, fingerprint(path.lstat())):
                    digest.update(data)
            need(a.digest() == b.digest(), "COPY_EXISTING_STOP")
            continue
        need(not partial.is_symlink(), "COPY_LINK_STOP")
        with p.open("rb") as src, partial.open("r+b" if partial.exists() else "x+b") as dst:
            need(os.fstat(dst.fileno()).st_nlink == 1, "COPY_LINK_STOP")
            os.chmod(partial, 0o600)
            while data := dst.read(CHUNK):
                need(src.read(len(data)) == data, "RESUME_PREFIX_STOP")
            while data := src.read(CHUNK):
                dst.write(data)
            dst.flush(); os.fsync(dst.fileno())
        os.rename(partial, out)
        C.fsync_parent(destination)
    return summary("ciphertext_copy", files=len(names), bytes_count=sum(p.stat().st_size for p in names))


def summary(phase, *, files=0, bytes_count=0):
    return {"phase": phase, "operation": "verified", "files": files, "bytes": bytes_count,
            "common_sqlite_epoch": "unknown", "source_authority": "unknown", "signer_portability": "blocked",
            "protected_tradebot": "unknown", "cutover": "blocked", "oci_retirement": "STRICT_NO_GO"}


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="action", required=True)
    seal_args = sub.add_parser("archive")
    for name in ("app", "state", "archive", "source-head"):
        seal_args.add_argument("--" + name, required=True)
    cp = sub.add_parser("copy-ciphertext")
    cp.add_argument("--source", required=True); cp.add_argument("--destination", required=True)
    rs = sub.add_parser("restore")
    rs.add_argument("--archive", required=True); rs.add_argument("--target", required=True)
    rs.add_argument("--quota-bytes", type=int, required=True)
    opts = p.parse_args()
    try:
        if opts.action == "copy-ciphertext":
            result = copy_archive(Path(opts.source), Path(opts.destination))
        else:
            recovery = getpass.getpass("Independent archive recovery material (hidden): ").encode()
            if opts.action == "archive":
                result = seal(Path(opts.app), Path(opts.state), Path(opts.archive), recovery, source_head=opts.source_head)
            else:
                result = restore(Path(opts.archive), Path(opts.target), recovery, quota=opts.quota_bytes)
            recovery = b""
        print(json.dumps(result, sort_keys=True))
    except Exception:
        print(json.dumps({"operation": "failed", "code": "R1066_GUARD_OR_INTEGRITY_STOP", "oci_retirement": "STRICT_NO_GO"}))
        return 42
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
