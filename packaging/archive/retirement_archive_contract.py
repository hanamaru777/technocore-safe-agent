#!/usr/bin/env python3
"""R861 offline ONLY metadata contract for eventual Flop archive assembly.

Never reads source DB/state values, copies files, invokes OCI, signs or mutates.
A PASS verifies topology metadata only, not an archived or frozen writer epoch.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SOURCE = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
DBS = (
    ("observer/lobby-capture.sqlite3", "capture-0.sqlite3",
     "capture/lobby-capture.sqlite3"),
    ("observer/lobby-capture-service.sqlite3", "capture-1.sqlite3",
     "capture/lobby-capture-service.sqlite3"),
)
REQUIRED = frozenset((
    "verified-did.json", "nonces.json", "activities.jsonl",
    "observer/observer-state.json", "observer/resident-state.json",
    "observer/observer-config.json", "observer/resident-config.json",
    "observer/observer-heartbeat.json",
    "signer/oracle-signer-receipts.json",
    "signer/signer-health.json", "signer/upstream-health.json",
    "autopilot/autopilot-outbox.json", "autopilot/autopilot-audit.jsonl",
))
ROTATED = "autopilot/autopilot-audit.jsonl."
CAPTURE_SIDECARS = frozenset(
    name + ext for name, _, _ in DBS for ext in ("-wal", "-shm", "-journal")
)
PROOF_PLAN = re.compile(r"proof-plans/[0-9a-f]{16}\.json\Z")
CURSOR = re.compile(r"cursor-[a-z0-9][a-z0-9_-]{0,47}\.json\Z")
MAX_META = 128 * 1024
MAX_PATHS = 512
MAX_STATE = 6 * 1024**3
MAX_FILE = 3 * 1024**3

class Stop(Exception):
    pass

def require(condition, reason):
    if not condition:
        raise Stop(reason)

def safe_path(path):
    require(isinstance(path, str) and 0 < len(path) <= 200, "PATH_INVALID")
    bits = path.split("/")
    require(len(bits) <= 4 and all(re.fullmatch(r"[A-Za-z0-9._-]+", b)
                                   and b not in (".", "..") for b in bits),
            "PATH_UNSAFE")
    return path

def allowed_state(path):
    if path in REQUIRED:
        return True
    if path.startswith(ROTATED):
        return path[len(ROTATED):] in ("1", "2", "3", "4")
    if CURSOR.fullmatch(path) or PROOF_PLAN.fullmatch(path):
        return True
    # Opaque subtrees such as close1, resident exports and public-proofs
    # MUST be classified before a complete retirement plan is acceptable.
    return False

def capture_plan(meta):
    require(isinstance(meta, dict) and
            meta.get("kind") == "preliminary_capture_only" and
            meta.get("source_commit") == SOURCE and
            meta.get("capture_unit_remained_inactive") is True and
            meta.get("signer_autopilot_and_nonce_not_archived") is True and
            meta.get("off_host_restored") is False and
            meta.get("sqlite_integrity_off_host_pending") is True,
            "CAPTURE_PROVENANCE_INVALID")
    records = meta.get("files")
    require(isinstance(records, list) and len(records) == len(DBS),
            "CAPTURE_COUNT_INVALID")
    mapping = []
    for row, (source, archive, target) in zip(records, DBS):
        require(isinstance(row, dict) and set(row) ==
                {"source_relative", "source_size_at_preflight",
                 "archive_file", "archive_size", "backup_steps"},
                "CAPTURE_ROW_INVALID")
        require(row["source_relative"] == source and
                row["archive_file"] == archive, "CAPTURE_MAPPING_MISMATCH")
        for key in ("source_size_at_preflight", "archive_size", "backup_steps"):
            value = row[key]
            require(type(value) is int and 0 < value <= MAX_FILE,
                    "CAPTURE_SIZE_OR_STEPS_INVALID")
        mapping.append((archive, target))
    return mapping

def state_plan(meta):
    require(isinstance(meta, dict) and meta.get("source_commit") == SOURCE and
            set(meta) == {"source_commit", "files"}, "STATE_INVENTORY_SCHEMA")
    rows = meta["files"]
    require(isinstance(rows, list) and len(rows) <= MAX_PATHS,
            "STATE_INVENTORY_COUNT")
    seen = set()
    selected = []
    total = 0
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"path", "type", "size"},
                "STATE_INVENTORY_ROW")
        path = safe_path(row["path"])
        require(path not in seen, "STATE_DUPLICATE_PATH")
        seen.add(path)
        require(row["type"] == "regular" and type(row["size"]) is int and
                0 <= row["size"] <= MAX_FILE, "STATE_FILE_TYPE_OR_SIZE")
        total += row["size"]
        require(total <= MAX_STATE, "STATE_TOTAL_EXCEEDED")
        if path in (x[0] for x in DBS) or path in CAPTURE_SIDECARS:
            # Original database and its WAL/SHM are NOT copied as ordinary
            # state. Only the SQLite backup API images enter the final bundle.
            continue
        require(not path.startswith("observer/autopilot-"),
                "LEGACY_AUTOPILOT_NEEDS_ADJUDICATION")
        require(allowed_state(path), "UNCLASSIFIED_STATE_FILE_STOP")
        selected.append(("state/" + path, row["size"]))
    require(REQUIRED.issubset(seen), "REQUIRED_STATE_MISSING")
    rotations = {int(p[len(ROTATED):]) for p in seen if p.startswith(ROTATED)}
    require(rotations == set(range(1, max(rotations, default=0) + 1)),
            "AUDIT_ROTATION_GAP")
    require(set(x[0] for x in selected) == {"state/" + p for p in
            seen if p not in CAPTURE_SIDECARS and p not in
            {d[0] for d in DBS}}, "SOURCE_MAP_INCOMPLETE")
    return tuple(sorted(selected))

def plan(capture, inventory):
    captures = capture_plan(capture)
    state = state_plan(inventory)
    destinations = [x[1] for x in captures] + [x[0] for x in state]
    require(len(destinations) == len(set(destinations)), "DESTINATION_COLLISION")
    return captures, state

def limited_json(path):
    require(path.is_file() and not path.is_symlink(), "META_FILE_INVALID")
    with path.open("rb") as handle:
        data = handle.read(MAX_META + 1)
    require(0 < len(data) <= MAX_META, "META_SIZE_INVALID")
    return json.loads(data)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--capture-metadata", required=True)
    p.add_argument("--state-inventory", required=True)
    a = p.parse_args()
    # This is metadata analysis only. Never run on either live machine.
    require(not Path("/opt/technocore-safe-agent").exists() and
            not Path("/opt/tradebot-k137").exists(), "LIVE_HOST_REFUSED")
    cap, state = plan(limited_json(Path(a.capture_metadata)),
                      limited_json(Path(a.state_inventory)))
    digest = hashlib.sha256(json.dumps(
        {"capture_map": cap, "state_map": state, "source": SOURCE},
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    print("FLOP_R861_OFFLINE_METADATA_PLAN_PASS")
    print("FLOP_R861_CAPTURE_IMAGES=" + str(len(cap)))
    print("FLOP_R861_STATE_FILES=" + str(len(state)))
    print("FLOP_R861_PLAN_FINGERPRINT_SHA256=" + digest)
    print("FLOP_R861_NO_ARCHIVE_NO_UPLOAD_NO_WRITER_EPOCH_PROOF")
    print("FLOP_R861_ORACLE_DELETION_NOT_AUTHORIZED")

if __name__ == "__main__":
    try:
        main()
    except (Stop, ValueError, TypeError, OSError, UnicodeError,
            json.JSONDecodeError) as e:
        print("FLOP_R861_PLAN_STOP=" +
              (str(e) if isinstance(e, Stop) else type(e).__name__))
        sys.exit(42)
