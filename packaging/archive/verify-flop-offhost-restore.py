#!/usr/bin/env python3
"""Verify downloaded FLOP retirement bundle on a SEPARATE, OFF-OCI/OFF-K137 host.

No network, secrets, services, writes, signing, or full-file RAM loads.
Requires an out-of-band pinned SHA256 of the manifest (not read from bundle).
Checks all manifest files with 128-KiB buffered reads, and both standalone
SQLite databases with read-only quick_check. This NEVER authorizes OCI removal.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from urllib.parse import quote

SOURCE_HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
KIND = "flop-retirement-offhost-v1"
REQUIRED = frozenset((
    "capture/lobby-capture.sqlite3",
    "capture/lobby-capture-service.sqlite3",
    "state/verified-did.json",
    "state/nonces.json",
    "state/activities.jsonl",
    "state/observer/observer-state.json",
    "state/observer/resident-state.json",
    "state/autopilot/autopilot-outbox.json",
    "state/signer/oracle-signer-receipts.json",
))
SQLITE_FILES = tuple(sorted(x for x in REQUIRED if x.endswith(".sqlite3")))
SMALL_JSON = (
    "state/verified-did.json", "state/nonces.json",
    "state/autopilot/autopilot-outbox.json",
    "state/signer/oracle-signer-receipts.json",
)
BUFFER = 128 * 1024
MAX_MANIFEST = 100 * 1024
MAX_SMALL_JSON = 1024 * 1024
MAX_FILES = 128
MAX_SINGLE_FILE = 3 * 1024**3
MAX_TOTAL = 6 * 1024**3
HEX64 = re.compile(r"^[a-f0-9]{64}$")

class Stop(Exception):
    pass

def require(ok, reason):
    if not ok:
        raise Stop(reason)

def no_link_path(root, relative):
    require(isinstance(relative, str) and len(relative) < 250,
            "BAD_RELATIVE_PATH")
    parts = relative.split("/")
    require(len(parts) <= 8 and parts[0] in ("state", "capture") and
            all(p and p not in (".", "..") and "\\" not in p and
                "\x00" not in p for p in parts),
            "UNSAFE_RELATIVE_PATH")
    path = root
    for part in parts:
        path = path / part
        try:
            info = path.lstat()
        except FileNotFoundError:
            raise Stop("RESTORED_ARTIFACT_ABSENT") from None
        require(not stat.S_ISLNK(info.st_mode), "SYMLINK_REJECTED")
    require(stat.S_ISREG(info.st_mode), "NOT_REGULAR_FILE")
    return path

def file_digest(path, max_size):
    # No symlink following; no large allocations, and stable identity verified.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and
                0 < before.st_size <= max_size,
                "FILE_TYPE_OR_SIZE_STOP")
        h = hashlib.sha256()
        seen = 0
        while True:
            chunk = os.read(fd, BUFFER)
            if not chunk:
                break
            seen += len(chunk)
            require(seen <= max_size, "FILE_GROWTH_STOP")
            h.update(chunk)
        after = os.fstat(fd)
        require(seen == before.st_size and
                (before.st_dev, before.st_ino, before.st_size,
                 before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns), "FILE_CHANGED_DURING_READ")
        return seen, h.hexdigest()
    finally:
        os.close(fd)

def read_manifest(root, expected):
    path = root / "RETIREMENT-MANIFEST.json"
    require(not path.is_symlink(), "MANIFEST_SYMLINK")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and
                0 < before.st_size <= MAX_MANIFEST, "MANIFEST_SIZE_STOP")
        data = os.read(fd, MAX_MANIFEST + 1)
        after = os.fstat(fd)
        require(len(data) == before.st_size and
                (before.st_size, before.st_mtime_ns) ==
                (after.st_size, after.st_mtime_ns),
                "MANIFEST_CHANGED_DURING_READ")
        require(hashlib.sha256(data).hexdigest() == expected,
                "OUT_OF_BAND_MANIFEST_HASH_MISMATCH")
    finally:
        os.close(fd)
    doc = json.loads(data.decode("utf-8"))
    require(isinstance(doc, dict) and
            set(doc) == {"schema", "kind", "source_commit", "files"},
            "MANIFEST_SCHEMA")
    require(doc["schema"] == 1 and doc["kind"] == KIND and
            doc["source_commit"] == SOURCE_HEAD, "MANIFEST_IDENTITY")
    entries = doc["files"]
    require(isinstance(entries, list) and
            len(REQUIRED) <= len(entries) <= MAX_FILES, "MANIFEST_FILE_COUNT")
    return entries

def verify_files(root, entries):
    observed = {}
    total = 0
    for entry in entries:
        require(isinstance(entry, dict) and
                set(entry) == {"path", "size", "sha256"}, "ENTRY_SCHEMA")
        name = entry["path"]
        require(isinstance(name, str) and name not in observed,
                "DUPLICATE_OR_BAD_ENTRY")
        expected = entry["sha256"]
        expected_size = entry["size"]
        require(type(expected_size) is int and 0 < expected_size <=
                MAX_SINGLE_FILE and isinstance(expected, str) and
                HEX64.fullmatch(expected), "ENTRY_SIZE_OR_DIGEST")
        path = no_link_path(root, name)
        size, actual = file_digest(path, MAX_SINGLE_FILE)
        require(size == expected_size and actual == expected,
                "ARTIFACT_SHA256_OR_SIZE_MISMATCH")
        observed[name] = path
        total += size
        require(total <= MAX_TOTAL, "BUNDLE_TOO_LARGE")
    require(REQUIRED <= set(observed), "REQUIRED_ARTIFACT_MISSING")
    for name in SQLITE_FILES:
        for suffix in ("-wal", "-shm", "-journal"):
            require(not os.path.lexists(str(observed[name]) + suffix),
                    "SQLITE_INCOMPLETE_SIDECAR_PRESENT")
    return observed, total

def verify_sqlite(path):
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True, timeout=1, cached_statements=0)
    try:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA cache_size=-512")
        result = conn.execute("PRAGMA quick_check").fetchall()
        require(result == [("ok",)], "SQLITE_QUICK_CHECK_FAILED")
        pages = conn.execute("PRAGMA page_count").fetchone()[0]
        require(type(pages) is int and pages > 0, "SQLITE_EMPTY_DB")
        return pages
    finally:
        conn.close()

def read_small_json(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and
                0 < info.st_size <= MAX_SMALL_JSON, "SMALL_JSON_TOO_LARGE")
        content = os.read(fd, MAX_SMALL_JSON + 1)
        require(len(content) == info.st_size, "SMALL_JSON_CHANGED_DURING_READ")
    finally:
        os.close(fd)
    return json.loads(content.decode("utf-8"))

def verify_ledger(files):
    """No replayable or unclassified signer/outbox entries in the restored files.

    Retain already quarantined controlled E2E test receipts verbatim. Passing
    does not prove source writer quiescence or grant Oracle retirement.
    """
    did = read_small_json(files["state/verified-did.json"])
    nonces = read_small_json(files["state/nonces.json"])
    receipt = read_small_json(files["state/signer/oracle-signer-receipts.json"])
    outbox = read_small_json(files["state/autopilot/autopilot-outbox.json"])
    require(all(isinstance(x, dict) for x in (did, nonces, receipt, outbox)),
            "LEDGER_TYPE_MISMATCH")
    identity = did.get("did")
    require(isinstance(identity, str) and identity.startswith("did:key:z"),
            "LEDGER_DID_INVALID")
    require(receipt.get("schema_version") == 1 and
            outbox.get("schema_version") == 1 and
            isinstance(receipt.get("receipts"), dict) and
            isinstance(outbox.get("outbox"), dict) and
            isinstance(outbox.get("receipts"), dict),
            "LEDGER_SCHEMA_MISMATCH")
    for key, number in nonces.items():
        require(isinstance(key, str) and "|" in key and
                type(number) is int and 0 < number <= 9999999999999999999,
                "NONCE_HIGH_WATER_SCHEMA_INVALID")
    sign = receipt["receipts"]
    queue = outbox["outbox"]
    ack = {key for key, item in sign.items()
           if isinstance(item, dict) and item.get("state") == "acknowledged"}
    qack = {key for key, item in queue.items()
            if isinstance(item, dict) and item.get("status") == "acknowledged"}
    require(ack == qack == set(outbox["receipts"]), "ACK_RECORD_IDS_MISMATCH")
    for key in ack:
        value = outbox["receipts"][key]
        require(isinstance(value, dict), "ACK_RECORD_SCHEMA_MISMATCH")
        hashes = (sign[key].get("receipt_hash"), queue[key].get("receipt_hash"),
                  value.get("receipt_hash"))
        require(all(isinstance(v, str) and HEX64.fullmatch(v) for v in hashes)
                and hashes[0] == hashes[1] == hashes[2],
                "ACK_RECEIPT_HASH_MISMATCH")
    quarantined = 0
    for key, record in sign.items():
        require(isinstance(key, str) and isinstance(record, dict),
                "SIGNER_RECEIPT_SCHEMA_INVALID")
        item = queue.get(key)
        require(isinstance(item, dict), "SIGNER_OUTBOX_LINK_MISSING")
        require(record.get("did") == identity, "SIGNER_DID_MISMATCH")
        nonce, room = record.get("nonce"), item.get("room")
        require(isinstance(nonce, str) and nonce.isascii() and
                nonce.isdecimal() and 0 < len(nonce) <= 19 and
                isinstance(room, str) and 0 < len(room) <= 48,
                "RECEIPT_NONCE_OR_ROOM_INVALID")
        floor = nonces.get(identity + "|" + room)
        require(type(floor) is int and int(nonce) <= floor,
                "NONCE_HIGH_WATER_BEHIND_RECEIPT")
        if record.get("state") == "acknowledged":
            require(item.get("status") == "acknowledged",
                    "ACK_RECORD_IDS_MISMATCH")
        elif record.get("state") == "prepared" and item.get("status") == "quarantined":
            require(item.get("category") == "controlled_e2e" and
                    item.get("quarantine_reason") in (
                        "submission_unknown", "legacy_unhandled_http_ambiguity",
                    ) and isinstance(item.get("quarantined_at"), str) and
                    bool(item["quarantined_at"]), "QUARANTINE_NOT_AUTHENTICATED")
            quarantined += 1
        else:
            raise Stop("SIGNER_UNRESOLVED_POST_STOP")
    for key, item in queue.items():
        require(isinstance(key, str) and isinstance(item, dict),
                "OUTBOX_RECORD_SCHEMA_INVALID")
        status = item.get("status")
        require(status in ("acknowledged", "quarantined", "expired"),
                "OUTBOX_PENDING_OR_UNKNOWN_STOP")
        if status == "quarantined":
            require(key in sign and sign[key].get("state") == "prepared",
                    "QUARANTINED_RECORD_LINK_MISSING")
        if status == "acknowledged":
            require(key in sign and sign[key].get("state") == "acknowledged",
                    "ACK_RECORD_IDS_MISMATCH")
        if status == "expired":
            require(key not in sign, "EXPIRED_WITH_SIGNER_RECEIPT_STOP")
    return len(ack), quarantined

def main(argv=None):
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args(argv)
    require(HEX64.fullmatch(args.manifest_sha256 or "") is not None,
            "EXTERNAL_DIGEST_REQUIRED")
    bundle = Path(args.bundle)
    require(bundle.exists() and bundle.is_dir() and not bundle.is_symlink(),
            "BAD_BUNDLE_DIRECTORY")
    # This verifier must run OFF OCI's live source and OFF AWS K137.
    require(not Path("/opt/technocore-safe-agent").exists() and
            not Path("/opt/tradebot-k137").exists(),
            "NOT_AN_INDEPENDENT_OFFHOST_VERIFIER")
    entries = read_manifest(bundle, args.manifest_sha256)
    files, total = verify_files(bundle, entries)
    sqlite_pages = [verify_sqlite(files[name]) for name in SQLITE_FILES]
    ack, quarantined = verify_ledger(files)
    print("FLOP_OFFHOST_MANIFEST_PINNED_SHA256_PASS", flush=True)
    print("FLOP_OFFHOST_FILE_SHA256_PASS count=" + str(len(files)), flush=True)
    print("FLOP_OFFHOST_SQLITE_QUICK_CHECK_PASS count=" + str(len(sqlite_pages)), flush=True)
    print("FLOP_OFFHOST_LEDGER_ACK_IDS_AND_HASHES_PASS count=" + str(ack), flush=True)
    print("FLOP_OFFHOST_QUARANTINED_HISTORY_PASS count=" + str(quarantined), flush=True)
    print("FLOP_OFFHOST_TERMINAL_OUTBOX_AND_NONCE_PASS", flush=True)
    print("FLOP_OFFHOST_WRITER_EPOCH_NOT_PROVEN", flush=True)
    print("FLOP_OFFHOST_BYTES_VERIFIED=" + str(total), flush=True)
    print("FLOP_OFFHOST_ARCHIVE_CONTENT_VERIFIED_PASS", flush=True)
    print("FLOP_OCI_DELETION_NOT_AUTHORIZED_BY_FILE_PROOF_ALONE", flush=True)

if __name__ == "__main__":
    try:
        main()
    except (Stop, OSError, ValueError, KeyError, UnicodeError,
            json.JSONDecodeError, sqlite3.Error) as error:
        print("FLOP_OFFHOST_RESTORE_VERIFY_STOP=" +
              (str(error) if isinstance(error, Stop) else type(error).__name__), flush=True)
        sys.exit(42)
