#!/usr/bin/env python3
"""R963 OFFHOST ONLY: compare independent original-source census with archive.

Two externally pinned input documents are necessary but NOT sufficient for
source authentication, writer-epoch coherency, encryption, actual restore, or
OCI retirement. No original-state contents, server contact, secrets, or writes.
A PASS MUST NEVER be interpreted as authorization to cut over or delete.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SOURCE = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
BIT = re.compile(r"[A-Za-z0-9_.-]+\Z")
SOURCE_KIND = "flop-original-source-census-v1"
ARCHIVE_KIND = "flop-retirement-offhost-v1"
DBS = frozenset(("observer/lobby-capture.sqlite3",
                 "observer/lobby-capture-service.sqlite3"))
CAPTURE_IMAGES = frozenset(("capture/lobby-capture.sqlite3",
                            "capture/lobby-capture-service.sqlite3"))
DB_SIDECARS = frozenset(db + suffix for db in DBS
                         for suffix in ("-wal", "-shm", "-journal"))
# The required source state list was already confirmed in original R861.
REQUIRED_STATE = frozenset((
    "verified-did.json", "nonces.json", "activities.jsonl",
    "observer-safety.json", "observer/observer-state.json",
    "observer/resident-state.json", "observer/observer-config.json",
    "observer/resident-config.json", "observer/observer-heartbeat.json",
    "signer/oracle-signer-receipts.json", "signer/signer-health.json",
    "signer/upstream-health.json", "autopilot/autopilot-outbox.json",
    "autopilot/autopilot-audit.jsonl",
))
MAX_SOURCE_BYTES = 12 * 1024**2
MAX_MANIFEST_BYTES = 256 * 1024
MAX_SOURCE_FILES = 25000
MAX_ARCHIVE_FILES = 512
MAX_ARCHIVE_SIZE = 6 * 1024**3
MAX_SINGLE_SIZE = 3 * 1024**3

class Stop(Exception):
    """Output only the fixed error codes; never reveal source filenames."""

def need(ok, code):
    if not ok:
        raise Stop(code)

def path_safe(name):
    need(isinstance(name, str) and 0 < len(name) <= 238,
         "SOURCE_PATH_SHAPE_STOP")
    bits = name.split("/")
    need(len(bits) <= 8 and all(BIT.fullmatch(b) and
         b not in (".", "..") for b in bits), "SOURCE_PATH_SHAPE_STOP")
    return name

def load_pin(path, external_hex, limit):
    need(isinstance(external_hex, str) and HEX64.fullmatch(external_hex),
         "INDEPENDENT_SHA256_PIN_REQUIRED")
    p = Path(path)
    need(p.is_file() and not p.is_symlink(),
         "PRIVATE_EVIDENCE_FILE_NOT_REGULAR_STOP")
    with p.open("rb") as handle:
        data = handle.read(limit + 1)
    need(0 < len(data) <= limit, "EVIDENCE_SIZE_STOP")
    need(hashlib.sha256(data).hexdigest() == external_hex,
         "EXTERNAL_SHA256_PIN_MISMATCH")
    value = json.loads(data)
    need(isinstance(value, dict), "EVIDENCE_SCHEMA_STOP")
    return value

def source_inventory(witness):
    need(set(witness) == {"kind", "source_commit", "scope", "walk_complete",
                         "unknown_roots", "symlinks", "special", "hardlinks",
                         "file_count", "logical_bytes", "files"} and
         witness["kind"] == SOURCE_KIND and
         witness["source_commit"] == SOURCE and
         witness["scope"] == "FLOP_STATE_DIR",
         "SOURCE_WITNESS_SCHEMA_STOP")
    # The old R938 source diagnostic specifically had 4 unknown directories
    # and 19 links, so it CANNOT satisfy these conditions.
    need(witness["walk_complete"] is True and
         witness["unknown_roots"] == [] and
         type(witness["symlinks"]) is int and witness["symlinks"] == 0 and
         type(witness["special"]) is int and witness["special"] == 0 and
         type(witness["hardlinks"]) is int and witness["hardlinks"] == 0,
         "SOURCE_CENSUS_NOT_EXHAUSTIVE_STOP")
    rows = witness["files"]
    need(isinstance(rows, list) and len(rows) <= MAX_SOURCE_FILES,
         "SOURCE_CENSUS_LIMIT_STOP")
    mapping = {}
    total = 0
    for row in rows:
        need(isinstance(row, dict) and set(row) ==
             {"path", "type", "size", "sha256"}, "SOURCE_FILE_SCHEMA_STOP")
        name = path_safe(row["path"])
        need(name not in mapping and row["type"] == "regular" and
             type(row["size"]) is int and 0 <= row["size"] <= 2**48,
             "SOURCE_ENTRY_DUPLICATE_OR_TYPE_STOP")
        digest = row["sha256"]
        need(digest is None or isinstance(digest, str) and
             HEX64.fullmatch(digest), "SOURCE_DIGEST_SHAPE_STOP")
        mapping[name] = (row["size"], digest)
        total += row["size"]
    need(type(witness["file_count"]) is int and
         witness["file_count"] == len(mapping) and
         type(witness["logical_bytes"]) is int and
         witness["logical_bytes"] == total,
         "SOURCE_CENSUS_SUMMARY_MISMATCH")
    need(REQUIRED_STATE | DBS <= set(mapping),
         "ORIGINAL_REQUIRED_SOURCE_MISSING_STOP")
    return mapping

def archive_inventory(manifest):
    need(set(manifest) == {"kind", "schema", "source_commit", "files"} and
         manifest["kind"] == ARCHIVE_KIND and
         manifest["schema"] == 1 and
         type(manifest["schema"]) is int and
         manifest["source_commit"] == SOURCE,
         "ARCHIVE_MANIFEST_SCHEMA_STOP")
    rows = manifest["files"]
    need(isinstance(rows, list) and len(rows) <= MAX_ARCHIVE_FILES,
         "ARCHIVE_FILE_COUNT_STOP")
    mapping = {}
    total = 0
    for row in rows:
        need(isinstance(row, dict) and set(row) ==
             {"path", "size", "sha256"}, "ARCHIVE_ROW_SCHEMA_STOP")
        name = path_safe(row["path"])
        need(name not in mapping and
             (name.startswith("state/") or name in CAPTURE_IMAGES),
             "ARCHIVE_UNEXPECTED_OR_DUPLICATE_STOP")
        size = row["size"]
        digest = row["sha256"]
        need(type(size) is int and 0 <= size <= MAX_SINGLE_SIZE and
             isinstance(digest, str) and HEX64.fullmatch(digest),
             "ARCHIVE_ROW_SIZE_OR_SHA_STOP")
        total += size
        need(total <= MAX_ARCHIVE_SIZE, "ARCHIVE_TOTAL_CAP_STOP")
        mapping[name] = (size, digest)
    need(CAPTURE_IMAGES <= set(mapping), "CAPTURE_IMAGES_MISSING_STOP")
    return mapping

def compare(source, archive):
    # SQLite backup API images deliberately differ in size/digest from the
    # LIVE database+WAL. This exception does NOT prove a common writer epoch.
    exempt = DBS | DB_SIDECARS
    state = {name[6:]: value for name, value in archive.items()
             if name.startswith("state/")}
    need(not (set(state) & exempt), "LIVE_SQLITE_COPY_FORBIDDEN_STOP")
    # Source paths not independently witnessed or missing from the archive
    # are fatal, including apparently stale log/tmp/cache and unknown Radar.
    need(set(state) <= set(source), "ARCHIVE_PATH_ABSENT_FROM_SOURCE_STOP")
    need(set(source) - exempt <= set(state),
         "ORIGINAL_SOURCE_PATH_UNARCHIVED_STOP")
    need(set(state) <= set(source) - exempt,
         "ARCHIVE_SQLITE_SIDECAR_ORIGIN_STOP")
    for name, (size, digest) in state.items():
        source_size, source_digest = source[name]
        need(source_digest is not None,
             "SOURCE_CONTENT_DIGEST_MISSING_STOP")
        need(size == source_size and digest == source_digest,
             "SOURCE_ARCHIVE_FILE_MISMATCH_STOP")
    # This is DOCUMENT PAIR consistency only, not truth of a source census.
    return len(state), len(exempt & set(source))

def check(source_doc, archive_doc):
    source = source_inventory(source_doc)
    manifest = archive_inventory(archive_doc)
    return compare(source, manifest)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source-census", required=True)
    p.add_argument("--source-census-sha256", required=True)
    p.add_argument("--archive-manifest", required=True)
    p.add_argument("--archive-manifest-sha256", required=True)
    opts = p.parse_args()
    need(not Path("/opt/technocore-safe-agent").exists() and
         not Path("/opt/tradebot-k137").exists(),
         "LIVE_HOST_EXECUTION_REFUSED")
    s = load_pin(opts.source_census, opts.source_census_sha256,
                 MAX_SOURCE_BYTES)
    m = load_pin(opts.archive_manifest, opts.archive_manifest_sha256,
                 MAX_MANIFEST_BYTES)
    retained, sqlite_origins = check(s, m)
    print("FLOP_OFFHOST_TWO_EXTERNALLY_PINNED_DOCUMENTS_MATCH")
    print("FLOP_OFFHOST_STATE_RECORDS_RECONCILED=" + str(retained))
    print("FLOP_OFFHOST_SQLITE_ORIGINS_SEPARATE=" + str(sqlite_origins))
    print("FLOP_SOURCE_AUTHENTICITY_NOT_PROVEN")
    print("FLOP_ORIGINAL_ALL_WRITER_EPOCH_NOT_PROVEN")
    print("FLOP_ORIGINAL_SQLITE_ONLINE_BACKUP_NOT_PROVEN")
    print("FLOP_ENCRYPTION_AND_RESTORE_NOT_PROVEN")
    print("FLOP_OCI_DELETION_NEVER_AUTHORIZED_BY_THIS_TOOL")

if __name__ == "__main__":
    try:
        main()
    except (Stop, ValueError, TypeError, KeyError, OSError, UnicodeError,
            json.JSONDecodeError) as error:
        print("FLOP_OFFHOST_SOURCE_COVERAGE_STOP=" +
              (str(error) if isinstance(error, Stop) else type(error).__name__))
        sys.exit(42)
