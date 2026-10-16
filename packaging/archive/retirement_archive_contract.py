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
    "observer-safety.json",  # original root-level safety evidence
    "observer/observer-state.json", "observer/resident-state.json",
    "observer/observer-config.json", "observer/resident-config.json",
    "observer/observer-heartbeat.json",
    "signer/oracle-signer-receipts.json",
    "signer/signer-health.json", "signer/upstream-health.json",
    "autopilot/autopilot-outbox.json", "autopilot/autopilot-audit.jsonl",
))
ROTATED = "autopilot/autopilot-audit.jsonl."
OPTIONAL = frozenset((
    "observer/resident-control.json", "observer/resident-heartbeat.json",
    "observer/close1-standalone-watch.json",
    "close1/close1-own-account.json",
    "close1/close1-autonomous-resident.json",
    "close1/close1-autonomous-stage.json",
    "close1/close1-autonomous-skips.json",
    "close1/close1-autonomous-rehearsal.json",
    "signer/close1-approved-trade.json",
    "signer/close1-approved-batch.json",
    "signer/close1-registration.json",
))
# This is a transient flock pathname, NOT a recovery or epoch proof.
TRANSIENT = frozenset(("signer/close1-approved-trade.lock",
                       "signer/close1-registration.lock"))
# The Sep 2026 one-shot registration is durable identity evidence, NOT a
# finance trade. Its flock lock is transient and must never be archived.
REGISTRATION = "signer/close1-registration.json"
ATTEMPT = re.compile(r"signer/close1-attempt-([a-f0-9]{64})\.json\Z")
RECEIPT = re.compile(r"signer/close1-receipt-([a-f0-9]{64})\.json\Z")
CAPTURE_SIDECARS = frozenset(
    name + ext for name, _, _ in DBS for ext in ("-wal", "-shm", "-journal")
)
PROOF_PLAN = re.compile(r"proof-plans/[0-9a-f]{16}\.json\Z")
CURSOR = re.compile(r"cursor-[a-z0-9][a-z0-9_-]{0,47}\.json\Z")
# R945: original pinned PROD source also writes durable challenge/radar proof
# histories. Whitelist exact known source-origin forms, never whole directories.
# This is an OFFLINE filename predicate, NOT proof the OCI inventory is complete.
RADAR_FIXED = frozenset((
    "airdrop-radar/state.json",
    "airdrop-radar/current-snapshot.json",
    "airdrop-radar/last-success.json",
    "airdrop-radar/event-index.json",
    "airdrop-radar/events.jsonl",
    "airdrop-radar/precontest-supervisor.json",
    "airdrop-radar/precontest-candidates.json",
))
RADAR_CHALLENGE_LEAVES = frozenset((
    "spec.json", "progress.json", "requests.json", "artifacts.json",
    "precontest-readiness.json", "precontest-readiness-sources.json",
    "precontest-runtime-profile.json", "precontest-runtime-compatibility.json",
    "precontest-plumbing-receipt.json",
    "precontest-active-learning-proof.json",
    "precontest-batch-rehearsal-proof.json",
    "precontest-control-path-receipts.json",
    "precontest-control-path-proof.json",
    "precontest-deadline-proof.json",
    "precontest-human-independence-receipt.json",
    "precontest-human-independence-proof.json",
    "precontest-reconciliation-proof.json",
))
RADAR_CHALLENGE = re.compile(
    r"airdrop-radar/challenges/[a-z0-9][a-z0-9_-]{0,63}/(?:"
    + "|".join(re.escape(name) for name in sorted(RADAR_CHALLENGE_LEAVES))
    + r")\Z"
)
RADAR_CANDIDATE_REVIEW = re.compile(
    r"airdrop-radar/challenge-candidate-reviews/[A-Za-z0-9_.-]{1,100}\.json\Z"
)
PUBLIC_PROOF_EXPORT = re.compile(
    r"public-proofs/proof-[a-f0-9]{16}-[0-9]{8}T[0-9]{6}Z\.json\Z"
)
# TCLK hash-lock preimages and reveal payloads are PRIVATE durable state.
# Exact 32-hex stage IDs and fixed known prefixes only; no open-ended tree.
TCLK_PUBLIC = re.compile(
    r"autopilot/tclk-pilot/(?:stages|previews|locks|work|terminal|reveal-previews)/"
    r"([a-f0-9]{32})\.json\Z"
)
TCLK_PRIVATE = re.compile(
    r"signer/tclk-pilot-(?:secrets|approvals|accepts|reveals|"
    r"reveal-approvals|reveal-publishes)/([a-f0-9]{32})\.json\Z"
)
TCLK_STAGE_PREFIX = "autopilot/tclk-pilot/stages/"
TCLK_SECRET_PREFIX = "signer/tclk-pilot-secrets/"
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
    if path in REQUIRED or path in OPTIONAL or path in TRANSIENT:
        return True
    if ATTEMPT.fullmatch(path) or RECEIPT.fullmatch(path):
        return True
    if path.startswith(ROTATED):
        return path[len(ROTATED):] in ("1", "2", "3", "4")
    if CURSOR.fullmatch(path) or PROOF_PLAN.fullmatch(path):
        return True
    if path in RADAR_FIXED or RADAR_CHALLENGE.fullmatch(path) or (
            RADAR_CANDIDATE_REVIEW.fullmatch(path)) or (
            PUBLIC_PROOF_EXPORT.fullmatch(path)):
        return True
    if TCLK_PUBLIC.fullmatch(path) or TCLK_PRIVATE.fullmatch(path):
        return True
    # Opaque subtrees such as close1, resident exports and public-proofs
    # MUST be classified before a complete retirement plan is acceptable.
    return False

def require_tclk_custody(seen):
    """Pair stage evidence and private hash-lock material without opening it."""
    secret_stages = set()
    needed_secrets = set()
    for path in seen:
        public = TCLK_PUBLIC.fullmatch(path)
        private = TCLK_PRIVATE.fullmatch(path)
        if public is None and private is None:
            continue
        stage_id = (public or private).group(1)
        if path != TCLK_STAGE_PREFIX + stage_id + ".json":
            require(TCLK_STAGE_PREFIX + stage_id + ".json" in seen,
                    "TCLK_STAGE_CUSTODY_MISSING")
        if path.startswith(TCLK_SECRET_PREFIX):
            secret_stages.add(stage_id)
        elif path != TCLK_STAGE_PREFIX + stage_id + ".json":
            needed_secrets.add(stage_id)
    require(needed_secrets <= secret_stages, "TCLK_SECRET_CUSTODY_MISSING")

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
        if path in (x[0] for x in DBS) or path in CAPTURE_SIDECARS or path in TRANSIENT:
            # Original database and its WAL/SHM are NOT copied as ordinary
            # state. Only the SQLite backup API images enter the final bundle.
            continue
        require(not path.startswith("observer/autopilot-"),
                "LEGACY_AUTOPILOT_NEEDS_ADJUDICATION")
        require(allowed_state(path), "UNCLASSIFIED_STATE_FILE_STOP")
        if TCLK_PUBLIC.fullmatch(path) or TCLK_PRIVATE.fullmatch(path):
            require(row["size"] > 0, "TCLK_EMPTY_STATE_STOP")
        selected.append(("state/" + path, row["size"]))
    require(REQUIRED.issubset(seen), "REQUIRED_STATE_MISSING")
    require_tclk_custody(seen)
    attempts = {m.group(1) for name in seen
                if (m := ATTEMPT.fullmatch(name))}
    receipts = {m.group(1) for name in seen
                if (m := RECEIPT.fullmatch(name))}
    require(receipts <= attempts, "FINANCE_RECEIPT_WITHOUT_ATTEMPT")
    # A durable fence without a confirmed receipt may have reached the
    # network already. Preserve it; never make automated replay eligible.
    require(attempts == receipts, "FINANCE_AMBIGUOUS_ATTEMPT_STOP")
    finance = {name for name in seen if name.startswith("close1/") or
               name.startswith("signer/close1-")}
    if finance - TRANSIENT - {REGISTRATION}:
        require("close1/close1-own-account.json" in seen,
                "FINANCE_ACCOUNT_LEDGER_MISSING")
    rotations = {int(p[len(ROTATED):]) for p in seen if p.startswith(ROTATED)}
    require(rotations == set(range(1, max(rotations, default=0) + 1)),
            "AUDIT_ROTATION_GAP")
    require(set(x[0] for x in selected) == {"state/" + p for p in
            seen if p not in CAPTURE_SIDECARS and p not in TRANSIENT and p not in
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
