#!/usr/bin/env python3
"""R1003 single Cloud Shell manifest witness bridge. NOT a data backup.

No source mutation: authenticated new operator key + original host pin + sudo
stream root-scoped lstat metadata, no data content. Host output exists in RAM
only, then sealed and independently verified in Cloud Shell. No signer operations.
"""
import base64
import hashlib
import io
import json
import os
import shlex
from pathlib import Path
import subprocess
import sys
import types
import zipfile
import zlib

HOST = "140.238.55.171"
ORIGINAL = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
MAX_RAW = 12 * 1024 * 1024
SEALED = "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"
SOURCE = "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"

class Stop(Exception):
    pass


def need(ok, code):
    if not ok: raise Stop(code)


def load_bundle(payload, module_name):
    compressor = zlib.decompressobj()
    data = compressor.decompress(base64.b64decode(payload), MAX_RAW + 1)
    need(compressor.eof and not compressor.unconsumed_tail and not compressor.unused_data
         and 0 < len(data) <= MAX_RAW, "CODE_BUNDLE_BOUND_STOP")
    m = types.ModuleType(module_name)
    exec(compile(data, module_name, "exec"), m.__dict__)
    return m, data


def original_manifest(code_bytes, *, executor=subprocess.run):
    # Remote -c argument contains only audited source code bytes (no secrets).
    b64 = base64.b64encode(code_bytes).decode("ascii")
    child = 'import base64;exec(base64.b64decode("' + b64 + '"))'
    remote = "sudo -n /usr/bin/python3 -c " + shlex.quote(child)
    base = Path.home() / ".flop-access-recovery-20261018"
    key, known_hosts = base / "new-operator-ecdsa", base / "known_hosts"
    need(key.is_file() and not key.is_symlink() and known_hosts.is_file()
         and not known_hosts.is_symlink() and key.stat().st_mode & 0o077 == 0,
         "ORIGINAL_NEW_OPERATOR_KEY_CUSTODY_STOP")
    cmd = ["ssh", "-F", "/dev/null", "-T", "-i", str(key),
           "-o", "UserKnownHostsFile=" + str(known_hosts),
           "-o", "StrictHostKeyChecking=yes",
           "-o", "HostKeyAlgorithms=ecdsa-sha2-nistp256",
           "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
           "-o", "IdentityAgent=none", "-o", "ConnectTimeout=7",
           "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
           "ubuntu@" + HOST, remote]
    try:
        proc = executor(cmd, capture_output=True, check=False, timeout=58)
    except (OSError, subprocess.TimeoutExpired):
        raise Stop("PINNED_SSH_SOURCE_FAILED_STOP") from None
    need(proc.returncode == 0, "ORIGINAL_GUEST_MANIFEST_STOP")
    raw = proc.stdout
    need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_RAW,
         "MANIFEST_BYTES_BOUND_STOP")
    try:
        manifest = json.loads(raw)
    except (ValueError, UnicodeError):
        raise Stop("MANIFEST_JSON_STOP") from None
    need(isinstance(manifest, dict) and manifest.get("schema") == 1
         and manifest.get("kind") == "flop-original-full-tree-metadata-v1"
         and manifest.get("source_commit") == ORIGINAL
         and manifest.get("walk_complete") is True
         and manifest.get("writer_epoch_proven") is False
         and manifest.get("sqlite_coherent_backup_proven") is False,
         "MANIFEST_PROVENANCE_SCOPE_STOP")
    entries = manifest.get("entries")
    need(isinstance(entries, list) and 100 <= len(entries) <= 22_000
         and all(isinstance(e, dict) and isinstance(e.get("path"), str)
                 and e.get("type") in ("file", "dir", "symlink")
                 for e in entries), "MANIFEST_ENTRY_SHAPE_STOP")
    paths = [e["path"] for e in entries]
    need(len(set(paths)) == len(paths)
         and all(0 < len(p) <= 2048 and not p.startswith("/")
                 and all(part not in ("", ".", "..") for part in p.split("/"))
                 for p in paths), "MANIFEST_PATH_SHAPE_STOP")
    need(manifest.get("files") == sum(e["type"] == "file" for e in entries)
         and manifest.get("symlinks") == sum(e["type"] == "symlink" for e in entries)
         and manifest.get("directories") == 1 + sum(e["type"] == "dir" for e in entries)
         and manifest.get("allocated_bytes") == sum(e.get("allocated", 0)
                    for e in entries if e["type"] == "file")
         and sum(p == "observer/lobby-capture.sqlite3" for p in paths) == 1
         and sum(p == "observer/lobby-capture-service.sqlite3" for p in paths) == 1,
         "MANIFEST_REQUIRED_STATE_STOP")
    return raw, manifest


def zip_encrypted(root, dest):
    items = list(root.iterdir())
    need(2 <= len(items) <= 258 and all(x.is_file() and not x.is_symlink()
         and (x.name in ("header.bin", "commit.bin")
              or x.name.startswith("part-") and x.name.endswith(".bin"))
         for x in items), "ENCRYPTED_PARTS_SHAPE_STOP")
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as f:
            with zipfile.ZipFile(f, mode="w", compression=zipfile.ZIP_STORED,
                                 allowZip64=True) as z:
                for x in sorted(items, key=lambda p:p.name):
                    z.write(x, arcname=x.name)
            f.flush()
            os.fsync(f.fileno())
    finally:
        os.close(fd)


def seal_manifest(raw):
    m, _ = load_bundle(SEALED, "R1001_original")
    local = Path.home() / ".flop-r1003-private"
    if not local.exists():
        os.mkdir(local, 0o700)
    m.owned_dir(local)
    secret, dirpath = local / "archive-secret", local / "encrypted-manifest"
    need(not dirpath.exists(), "PRIOR_ENCRYPTED_ARCHIVE_EXISTS_STOP")
    # New independent archive code is generated once and is NEVER printed.
    if not secret.exists():
        m.init_secret(secret)
    old = sys.stdin
    try:
        sys.stdin = io.TextIOWrapper(io.BytesIO(raw))
        m.seal(dirpath, secret)
    finally:
        sys.stdin = old
    m.verify(dirpath, secret)
    dest = local / "FLOP_R1003_SOURCE_METADATA_ENCRYPTED.zip"
    zip_encrypted(dirpath, dest)
    print("FLOP_R1003_ENCRYPTED_BUNDLE_SHA256=" + hashlib.sha256(dest.read_bytes()).hexdigest())
    print("FLOP_R1003_ENCRYPTED_BUNDLE_PATH=" + str(dest))
    print("FLOP_R1003_INDEPENDENT_ARCHIVE_AND_SECRET_CUSTODY=NOT_YET_VERIFIED")
    print("FLOP_R1003_APPLICATION_STATE_DATA_NOT_BACKED_UP=YES")
    print("FLOP_R1003_ORIGINAL_WRITER_EPOCH_NOT_PROVEN=YES")
    print("FLOP_R1003_OCI_RETIREMENT=STRICT_NO_GO")


def main():
    blocked = ("/opt/technocore-safe-agent", "/opt/tradebot-k137",
               "/opt/tradebot-k137-private", "/opt/flop-shadow")
    need(sys.platform == "linux" and os.geteuid() != 0
         and not any(Path(path).exists() for path in blocked),
         "CLOUDSHELL_NONROOT_NOT_LIVE_HOST_REQUIRED")
    # Do not touch Oracle until required crypto dependency imported and code verified.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    source, payload = load_bundle(SOURCE, "R1002_original")
    raw, doc = original_manifest(payload)
    seal_manifest(raw)
    print("FLOP_R1003_ORIGINAL_SOURCE_SHA=PASS")
    print("FLOP_R1003_METADATA_FILES=" + str(doc["files"]))
    print("FLOP_R1003_METADATA_SYMLINKS=" + str(doc["symlinks"]))
    print("FLOP_R1003_METADATA_DIRECTORIES=" + str(doc["directories"]))
    print("FLOP_R1003_NO_RAW_METADATA_SECRET_VALUES_PRINTED=YES")
    print("FLOP_R1003_SOURCE_REMOTE=READONLY_FINISHED")


if __name__ == "__main__":
    try:
        main()
    except (Stop, OSError, ValueError, TypeError, UnicodeError,
            ImportError) as exc:
        reason = str(exc) if isinstance(exc, Stop) else type(exc).__name__
        print("FLOP_R1003_STOP=" + reason)
        sys.exit(42)
