#!/usr/bin/env python3
"""Verify downloaded FLOP retirement bundle on a SEPARATE, OFF-OCI/OFF-K137 host.

No network, secrets, services, writes, signing, or full-file RAM loads.
Requires separate out-of-band SHA256 pins for the manifest AND original DID.
Never derive either original-identity pin from the untrusted restore bundle.
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
from datetime import datetime
from urllib.parse import quote

SOURCE_HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
KIND = "flop-retirement-offhost-v1"
REQUIRED = frozenset((
    "capture/lobby-capture.sqlite3",
    "capture/lobby-capture-service.sqlite3",
    "state/verified-did.json",
    "state/observer-safety.json",  # root-level protected observer safety
    "state/nonces.json",
    "state/activities.jsonl",
    "state/observer/observer-state.json",
    "state/observer/resident-state.json",
    # The R861/R864 source inventory+sealer requires each of these too.
    # An independently pinned manifest for an incomplete restore MUST fail.
    "state/observer/observer-config.json",
    "state/observer/resident-config.json",
    "state/observer/observer-heartbeat.json",
    "state/autopilot/autopilot-outbox.json",
    "state/autopilot/autopilot-audit.jsonl",
    "state/signer/oracle-signer-receipts.json",
    "state/signer/signer-health.json",
    "state/signer/upstream-health.json",
))
SQLITE_FILES = tuple(sorted(x for x in REQUIRED if x.endswith(".sqlite3")))
# Independently enforce the R861 producer's closed file vocabulary. A
# correctly SHA-pinned manifest MUST NOT be able to include a secret, stale
# sidecar, arbitrary OCI file, or an invented source-state pathname.
OPTIONAL_STATE = frozenset((
    "observer/resident-control.json", "observer/resident-heartbeat.json",
    "observer/close1-standalone-watch.json",
    "close1/close1-own-account.json",
    "close1/close1-autonomous-resident.json",
    "close1/close1-autonomous-stage.json",
    "close1/close1-autonomous-skips.json",
    "close1/close1-autonomous-rehearsal.json",
    "signer/close1-approved-trade.json", "signer/close1-approved-batch.json",
    "signer/close1-registration.json",
))
# R946 mirrors the fixed source-writer families in R945's producer.
# Never accept an unconstrained airdrop-radar or public-proofs subtree.
RADAR_FIXED = frozenset((
    "airdrop-radar/state.json",
    "airdrop-radar/current-snapshot.json",
    "airdrop-radar/last-success.json",
    "airdrop-radar/event-index.json",
    "airdrop-radar/events.jsonl",
    "airdrop-radar/precontest-supervisor.json",
    "airdrop-radar/precontest-candidates.json",
    # R957: original notification/approval/execution operational journals.
    "airdrop-radar/monitor-config.json",
    "airdrop-radar/monitor-heartbeat.json",
    "airdrop-radar/alert-outbox.json",
    "airdrop-radar/discord-notifier-state.json",
    "airdrop-radar/action-candidates.json",
    "airdrop-radar/action-inbox.json",
    "airdrop-radar/action-executions.json",
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
# R949 mirrors R948 source producer. Challenge artifact bytes are individually
# bound to their own local artifacts.json index, not an arbitrary tree.
RADAR_ARTIFACT = re.compile(
    r"airdrop-radar/challenges/([a-z0-9][a-z0-9_-]{0,63})/artifacts/"
    r"([A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*){0,2})\Z"
)
MAX_CHALLENGE_ARTIFACT = 10 * 1024**2
MAX_CHALLENGE_INDEX = 1024**2
SOURCE_PATH_COMPONENT = re.compile(r"[A-Za-z0-9._-]+\Z")
SOURCE_ATTEMPT = re.compile(r"signer/close1-attempt-[a-f0-9]{64}\.json\Z")
SOURCE_RECEIPT = re.compile(r"signer/close1-receipt-[a-f0-9]{64}\.json\Z")
SOURCE_PROOF = re.compile(r"proof-plans/[a-f0-9]{16}\.json\Z")
SOURCE_CURSOR = re.compile(r"cursor-[a-z0-9][a-z0-9_-]{0,47}\.json\Z")
# Match R922 offline producer: fixed source stage names only, never an
# unrestricted subtree that could include unrelated private key material.
TCLK_PUBLIC = re.compile(
    r"autopilot/tclk-pilot/(?:stages|previews|locks|work|terminal|reveal-previews)/"
    r"([a-f0-9]{32})\.json\Z"
)
TCLK_PRIVATE = re.compile(
    r"signer/tclk-pilot-(?:secrets|approvals|accepts|reveals|"
    r"reveal-approvals|reveal-publishes)/([a-f0-9]{32})\.json\Z"
)
TCLK_STAGE_PREFIX = "state/autopilot/tclk-pilot/stages/"
TCLK_SECRET_PREFIX = "state/signer/tclk-pilot-secrets/"


def archive_path_allowed(path):
    if path in REQUIRED:
        return True
    if not isinstance(path, str) or not path.startswith("state/"):
        return False
    name = path[6:]
    parts = name.split("/")
    if not all(SOURCE_PATH_COMPONENT.fullmatch(part) and
               part not in (".", "..") for part in parts):
        return False
    if RADAR_ARTIFACT.fullmatch(name):
        return (0 < len(name) <= 238 and len(parts) <= 7 and
                len(name.rsplit("/artifacts/", 1)[-1]) <= 200)
    if not 0 < len(name) <= 200 or len(parts) > 4:
        return False
    if name in RADAR_FIXED or RADAR_CHALLENGE.fullmatch(name) or (
            RADAR_CANDIDATE_REVIEW.fullmatch(name)) or (
            PUBLIC_PROOF_EXPORT.fullmatch(name)):
        return True
    if name in OPTIONAL_STATE or SOURCE_ATTEMPT.fullmatch(name) or (
            SOURCE_RECEIPT.fullmatch(name)):
        return True
    if name.startswith("autopilot/autopilot-audit.jsonl."):
        return name[-1:] in ("1", "2", "3", "4") and name == (
            "autopilot/autopilot-audit.jsonl." + name[-1])
    return bool(SOURCE_PROOF.fullmatch(name) or SOURCE_CURSOR.fullmatch(name)
                or TCLK_PUBLIC.fullmatch(name) or TCLK_PRIVATE.fullmatch(name))
SMALL_JSON = (
    "state/verified-did.json", "state/nonces.json",
    "state/autopilot/autopilot-outbox.json",
    "state/signer/oracle-signer-receipts.json",
)
BUFFER = 128 * 1024
MAX_MANIFEST = 256 * 1024
MAX_SMALL_JSON = 1024 * 1024
MAX_FILES = 512
MAX_SINGLE_FILE = 3 * 1024**3
MAX_TOTAL = 6 * 1024**3
HEX64 = re.compile(r"^[a-f0-9]{64}$")
# Pinned to existing source-controlled E2E v1/v2. Never permit a user-
# invented quarantine to suppress a real pending publication.
CONTROLLED_QUARANTINE = {
    hashlib.sha256(b"controlled-e2e-v1").hexdigest()[:20]: "submission_unknown",
    hashlib.sha256(b"controlled-e2e-v2").hexdigest()[:20]:
        "legacy_unhandled_http_ambiguity",
}

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
                0 <= before.st_size <= max_size,
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

def require_exact_restored_tree(root, files):
    """Only the authenticated manifest and its exact files/ancestor dirs may exist."""
    required_files = set(files) | {"RETIREMENT-MANIFEST.json"}
    required_dirs = set()
    for relative in required_files:
        bits = relative.split("/")
        for i in range(1, len(bits)):
            required_dirs.add("/".join(bits[:i]))
    present_files = set()
    present_dirs = set()

    def visit(folder, relative, depth):
        require(depth <= 8, "RESTORED_TREE_DEPTH_STOP")
        with os.scandir(folder) as entries:
            for entry in entries:
                name = entry.name
                require(name and len(name) <= 200 and
                        name not in (".", "..") and
                        "/" not in name and chr(92) not in name and
                        chr(0) not in name, "RESTORED_TREE_NAME_STOP")
                rel = relative + "/" + name if relative else name
                require(len(rel) < 250, "RESTORED_TREE_PATH_STOP")
                info = entry.stat(follow_symlinks=False)
                require(not stat.S_ISLNK(info.st_mode),
                        "RESTORED_TREE_SYMLINK_STOP")
                if stat.S_ISDIR(info.st_mode):
                    require(rel in required_dirs, "UNMANIFESTED_DIRECTORY_STOP")
                    present_dirs.add(rel)
                    require(len(present_dirs) <= MAX_FILES,
                            "RESTORED_TREE_DIRECTORY_COUNT_STOP")
                    visit(folder / name, rel, depth + 1)
                else:
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                            "RESTORED_TREE_NONREGULAR_STOP")
                    require(rel in required_files, "UNMANIFESTED_FILE_STOP")
                    present_files.add(rel)
                    require(len(present_files) <= MAX_FILES + 1,
                            "RESTORED_TREE_FILE_COUNT_STOP")
    visit(root, "", 0)
    require(present_files == required_files and
            present_dirs == required_dirs, "RESTORED_TREE_MISSING_STOP")


def verify_tclk_custody(observed):
    """Check complete structural pairing; never decode or print preimages."""
    names = set(observed)
    secret_stages = set()
    required_secrets = set()
    for name in names:
        if not name.startswith("state/"):
            continue
        relative = name[6:]
        public = TCLK_PUBLIC.fullmatch(relative)
        private = TCLK_PRIVATE.fullmatch(relative)
        if public is None and private is None:
            continue
        stage = (public or private).group(1)
        stage_file = TCLK_STAGE_PREFIX + stage + ".json"
        if name != stage_file:
            require(stage_file in names, "TCLK_STAGE_CUSTODY_MISSING")
        if name.startswith(TCLK_SECRET_PREFIX):
            secret_stages.add(stage)
        elif name != stage_file:
            required_secrets.add(stage)
    require(required_secrets <= secret_stages, "TCLK_SECRET_CUSTODY_MISSING")


def verify_challenge_artifacts(files):
    """Independent index-to-bytes binding; never echo filenames or file data."""
    base = "state/airdrop-radar/challenges/"
    indices = {}
    artifacts = {}
    spec_ids = set()
    for path in files:
        if not path.startswith(base):
            continue
        relative = path[len(base):]
        if "/" not in relative:
            continue
        cid, suffix = relative.split("/", 1)
        if suffix == "spec.json":
            spec_ids.add(cid)
        if suffix == "artifacts.json":
            indices[cid] = path
        match = RADAR_ARTIFACT.fullmatch(path[6:])
        if match:
            artifacts.setdefault(match.group(1), set()).add(path)
    for cid in spec_ids | set(artifacts):
        require(cid in indices, "CHALLENGE_ARTIFACT_INDEX_MISSING")

    for cid, index_path in indices.items():
        index_file = files[index_path]
        require(index_file.stat().st_size <= MAX_CHALLENGE_INDEX,
                "CHALLENGE_ARTIFACT_INDEX_TOO_LARGE")
        raw = index_file.read_bytes()
        require(0 < len(raw) <= MAX_CHALLENGE_INDEX,
                "CHALLENGE_ARTIFACT_INDEX_TOO_LARGE")
        index = json.loads(raw.decode("utf-8"))
        require(isinstance(index, dict) and
                set(index) == {"schema_version", "artifacts"} and
                type(index["schema_version"]) is int and
                index["schema_version"] == 1 and
                isinstance(index["artifacts"], dict),
                "CHALLENGE_ARTIFACT_INDEX_SCHEMA")
        declared_paths = set()
        for name, row in index["artifacts"].items():
            require(isinstance(name, str) and isinstance(row, dict) and
                    set(row) == {"name", "source_url", "sha256", "bytes",
                                 "pinned_at", "relative_path"},
                    "CHALLENGE_ARTIFACT_INDEX_SCHEMA")
            path = base + cid + "/artifacts/" + name
            matched = RADAR_ARTIFACT.fullmatch(path[6:])
            require(matched is not None and matched.group(1) == cid and
                    archive_path_allowed(path) and
                    row["name"] == name and
                    row["relative_path"] == "artifacts/" + name and
                    isinstance(row["source_url"], str) and
                    row["source_url"].startswith("https://") and
                    isinstance(row["pinned_at"], str) and
                    bool(row["pinned_at"]) and
                    isinstance(row["sha256"], str) and
                    HEX64.fullmatch(row["sha256"]) and
                    type(row["bytes"]) is int and
                    0 <= row["bytes"] <= MAX_CHALLENGE_ARTIFACT,
                    "CHALLENGE_ARTIFACT_INDEX_SCHEMA")
            require(path in files, "CHALLENGE_ARTIFACT_MISSING")
            size, digest = file_digest(files[path], MAX_CHALLENGE_ARTIFACT)
            require(size == row["bytes"] and digest == row["sha256"],
                    "CHALLENGE_ARTIFACT_INDEX_HASH_MISMATCH")
            declared_paths.add(path)
        require(declared_paths == artifacts.get(cid, set()),
                "CHALLENGE_ARTIFACT_ORPHAN_STOP")



# R950: original airdrop_challenge.plan_request/mark_request saves a durable
# request journal. A source-dormant cutover must NEVER silently replay an
# ambiguous or still-in-progress send. No network or signer side effects.
CHALLENGE_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
CHALLENGE_TERMINAL_REQUESTS = frozenset((
    "accepted", "rejected", "reconciled_accepted", "reconciled_not_found",
))

def verify_challenge_request_journals(files):
    suffix = "/requests.json"
    prefix = "state/airdrop-radar/challenges/"
    for path in files:
        if not path.startswith(prefix) or not path.endswith(suffix):
            continue
        source = files[path]
        require(0 < source.stat().st_size <= MAX_CHALLENGE_INDEX,
                "CHALLENGE_REQUEST_JOURNAL_SIZE_STOP")
        value = json.loads(source.read_bytes().decode("utf-8"))
        require(isinstance(value, dict) and
                set(value) == {"schema_version", "requests"} and
                type(value["schema_version"]) is int and
                value["schema_version"] == 1 and
                isinstance(value["requests"], dict) and
                len(value["requests"]) <= MAX_FILES,
                "CHALLENGE_REQUEST_JOURNAL_SCHEMA")
        for request_id, record in value["requests"].items():
            require(isinstance(request_id, str) and
                    CHALLENGE_REQUEST_ID.fullmatch(request_id) and
                    isinstance(record, dict) and
                    set(record) == {"request_id", "action", "payload_sha256",
                                    "status", "planned_at", "updated_at",
                                    "receipt_hash"},
                    "CHALLENGE_REQUEST_ROW_SCHEMA")
            require(record["request_id"] == request_id and
                    isinstance(record["action"], str) and
                    0 < len(record["action"]) <= 100 and
                    isinstance(record["payload_sha256"], str) and
                    HEX64.fullmatch(record["payload_sha256"]) and
                    isinstance(record["planned_at"], str) and
                    bool(record["planned_at"]) and
                    isinstance(record["updated_at"], str) and
                    bool(record["updated_at"]) and
                    (record["receipt_hash"] is None or (
                        isinstance(record["receipt_hash"], str) and
                        HEX64.fullmatch(record["receipt_hash"]))),
                    "CHALLENGE_REQUEST_ROW_SCHEMA")
            # Planned, sent and ambiguous are NOT a proven terminal ledger,
            # even if the snapshot and the surrounding manifest are signed.
            require(record["status"] in CHALLENGE_TERMINAL_REQUESTS,
                    "CHALLENGE_REQUEST_NONTERMINAL_STOP")
            if record["status"] in ("accepted", "reconciled_accepted"):
                require(isinstance(record["receipt_hash"], str) and
                        HEX64.fullmatch(record["receipt_hash"]),
                        "CHALLENGE_ACCEPTED_RECEIPT_MISSING")



# R954: cross-check Radar's own material event hash-chain against its index.
# The archive manifest SHA alone cannot establish historical source integrity.
# Stream bounded lines, never print original event content or identifiers.
MAX_RADAR_LEDGER_BYTES = 32 * 1024**2
MAX_RADAR_INDEX_BYTES = 16 * 1024**2
MAX_RADAR_EVENTS = 50000

def _radar_hash(value, *, ascii_only=False):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=ascii_only).encode("utf-8")).hexdigest()


def verify_radar_ledger(files):
    base = "state/airdrop-radar/"
    ledger_path = base + "events.jsonl"
    index_path = base + "event-index.json"
    if ledger_path not in files and index_path not in files:
        return {}
    require(index_path in files, "RADAR_LEDGER_INDEX_MISSING")
    index_file = files[index_path]
    require(0 < index_file.stat().st_size <= MAX_RADAR_INDEX_BYTES,
            "RADAR_INDEX_SIZE_STOP")
    index = json.loads(index_file.read_bytes().decode("utf-8"))
    require(isinstance(index, dict) and
            index.get("schema_version") == 1 and
            type(index.get("ledger_count")) is int and
            0 <= index["ledger_count"] <= MAX_RADAR_EVENTS and
            isinstance(index.get("ledger_tip_hash"), str) and
            isinstance(index.get("events"), dict),
            "RADAR_INDEX_SCHEMA")
    previous = ""
    count = 0
    latest = {}
    if ledger_path in files:
        ledger_file = files[ledger_path]
        require(0 <= ledger_file.stat().st_size <= MAX_RADAR_LEDGER_BYTES,
                "RADAR_LEDGER_SIZE_STOP")
        with ledger_file.open("r", encoding="utf-8", newline="") as stream:
            for line in stream:
                count += 1
                require(count <= MAX_RADAR_EVENTS, "RADAR_LEDGER_COUNT_STOP")
                require(0 < len(line) <= MAX_RADAR_LEDGER_BYTES and line.strip(),
                        "RADAR_LEDGER_LINE_INVALID")
                row = json.loads(line)
                require(isinstance(row, dict) and
                        type(row.get("schema_version")) is int and
                        row["schema_version"] == 1 and
                        type(row.get("sequence")) is int and
                        row["sequence"] == count and
                        row.get("record_type") == "material_event" and
                        row.get("previous_hash") == previous and
                        isinstance(row.get("source_evidence"), list),
                        "RADAR_LEDGER_LINK_OR_SCHEMA_INVALID")
                event = row.get("event")
                require(isinstance(event, dict) and
                        isinstance(row.get("event_id"), str) and
                        isinstance(row.get("hash"), str) and
                        HEX64.fullmatch(row["hash"]),
                        "RADAR_LEDGER_EVENT_SCHEMA")
                computed_id = _radar_hash({
                    "type": event.get("type"), "key": event.get("key"),
                    "before": event.get("before"), "after": event.get("after"),
                }, ascii_only=True)[:24]
                require(row["event_id"] == event.get("event_id") == computed_id,
                        "RADAR_EVENT_ID_MISMATCH")
                for field in ("first_seen", "last_seen", "observed_at"):
                    timestamp = row.get(field)
                    require(isinstance(timestamp, str),
                            "RADAR_TIMESTAMP_INVALID")
                    value = datetime.fromisoformat(
                        timestamp.replace("Z", "+00:00"))
                    require(value.tzinfo is not None, "RADAR_TIMESTAMP_INVALID")
                unsigned = dict(row)
                unsigned.pop("hash")
                require(_radar_hash(unsigned) == row["hash"],
                        "RADAR_CHAIN_HASH_MISMATCH")
                previous = row["hash"]
                latest[row["event_id"]] = (count, previous)
    require(index["ledger_count"] == count and
            index["ledger_tip_hash"] == previous,
            "RADAR_INDEX_TIP_MISMATCH")
    indexed = index["events"]
    # The original source reconciler rebuilds index only from the chain.
    # A second invented/stale event row must never be implicitly trusted.
    require(set(indexed) == set(latest), "RADAR_INDEX_ORPHAN_EVENT_STOP")
    for event_id, (seq, hash_value) in latest.items():
        row = indexed.get(event_id)
        require(isinstance(row, dict) and
                row.get("event_id") == event_id and
                row.get("ledger_sequence") == seq and
                row.get("ledger_hash") == hash_value,
                "RADAR_INDEX_EVENT_MISMATCH")
    # Immutable source ledger event IDs are the trust binding for restored
    # automatically staged actions and Discord alerts. Do not expose IDs.
    return {event_id: pair[1] for event_id, pair in latest.items()}


# R957: a signed archive with lost/pending network-delivery journal entries
# is NOT safe for active cutover. Original source can send before recording a
# receipt, so "pending" does not prove no prior network delivery.
MAX_OPERATIONAL_JSON = 4 * 1024**2
OPERATIONAL_STATES = {
    "monitor-config.json": ("schema_version", None, 0),
    "monitor-heartbeat.json": ("schema_version", None, 0),
    "discord-notifier-state.json": ("schema_version", None, 0),
    "action-candidates.json": ("schema_version", "candidates", 256),
    "alert-outbox.json": ("schema_version", "events", 10000),
    "action-inbox.json": ("schema_version", "requests", 256),
    "action-executions.json": ("schema_version", "executions", 256),
}
HEX32_ID = re.compile(r"[a-f0-9]{32}\Z")


def verify_radar_operational_state(files, radar_hashes):
    base = "state/airdrop-radar/"
    present = {}
    for basename, (_version, collection, limit) in OPERATIONAL_STATES.items():
        name = base + basename
        if name not in files:
            continue
        path = files[name]
        size = path.stat().st_size
        require(0 < size <= MAX_OPERATIONAL_JSON,
                "RADAR_OPERATIONAL_STATE_SIZE_STOP")
        data = json.loads(path.read_bytes().decode("utf-8"))
        require(isinstance(data, dict) and
                type(data.get("schema_version")) is int and
                data["schema_version"] == 1, "RADAR_OPERATIONAL_SCHEMA_STOP")
        if collection is not None:
            items = data.get(collection)
            require(isinstance(items, dict) and len(items) <= limit,
                    "RADAR_OPERATIONAL_COLLECTION_STOP")
        present[basename] = data

    # Do not treat a copied-but-unacknowledged Discord alert as safe to
    # deliver. Its original HTTP side effect might already have happened.
    if "alert-outbox.json" in present:
        for event_id, row in present["alert-outbox.json"]["events"].items():
            require(isinstance(event_id, str) and 0 < len(event_id) <= 128 and
                    isinstance(row, dict) and row.get("event_id") == event_id,
                    "RADAR_ALERT_ROW_INVALID")
            require(row.get("delivery_state") == "delivered",
                    "RADAR_ALERT_DELIVERY_UNCERTAIN_STOP")
            require(isinstance(row.get("delivery_receipt"), str) and
                    bool(row["delivery_receipt"]) and
                    len(row["delivery_receipt"]) <= 200 and
                    isinstance(row.get("delivered_at"), str) and
                    bool(row["delivered_at"]),
                    "RADAR_ALERT_DELIVERY_RECEIPT_MISSING")
            require(isinstance(event_id, str) and event_id in radar_hashes and
                    isinstance(row.get("payload"), dict) and
                    row["payload"].get("event_id") == event_id,
                    "RADAR_ALERT_SOURCE_EVENT_MISMATCH")

    if "action-inbox.json" in present:
        for request_id, row in present["action-inbox.json"]["requests"].items():
            require(isinstance(request_id, str) and HEX32_ID.fullmatch(request_id)
                    and isinstance(row, dict) and
                    row.get("request_id") == request_id,
                    "RADAR_ACTION_APPROVAL_ROW_INVALID")
            require(row.get("status") in ("rejected", "expired", "consumed"),
                    "RADAR_ACTION_APPROVAL_NOT_TERMINAL_STOP")
            if row["status"] == "consumed":
                require(isinstance(row.get("consumption_receipt"), str) and
                        bool(row["consumption_receipt"]) and
                        isinstance(row.get("consumed_at"), str) and
                        bool(row["consumed_at"]),
                        "RADAR_ACTION_CONSUMPTION_RECEIPT_MISSING")

    if "action-executions.json" in present:
        for request_id, row in present["action-executions.json"]["executions"].items():
            require(isinstance(request_id, str) and HEX32_ID.fullmatch(request_id)
                    and isinstance(row, dict) and
                    row.get("request_id") == request_id,
                    "RADAR_ACTION_EXECUTION_ROW_INVALID")
            require(row.get("status") in ("succeeded", "failed_before_write", "blocked"),
                    "RADAR_ACTION_EXECUTION_UNCERTAIN_STOP")
            require(isinstance(row.get("terminal_at"), str) and
                    bool(row["terminal_at"]),
                    "RADAR_ACTION_TERMINAL_PROOF_MISSING")
            if row["status"] == "succeeded":
                require(isinstance(row.get("receipt"), str) and
                        bool(row["receipt"]), "RADAR_ACTION_SUCCESS_RECEIPT_MISSING")
            else:
                require(isinstance(row.get("error_code"), str) and
                        bool(row["error_code"]), "RADAR_ACTION_TERMINAL_PROOF_MISSING")

    # A self-signed archive that retains actionable rows while omitting
    # their original Radar evidence cannot be accepted as a cutover state.
    # This still DOES NOT prove files omitted entirely from the source.
    has_actions = any(present.get(f, {}).get(k) for f, k in (
        ("alert-outbox.json", "events"),
        ("action-candidates.json", "candidates"),
        ("action-inbox.json", "requests"),
        ("action-executions.json", "executions"),
    ))
    if has_actions:
        require("state/airdrop-radar/events.jsonl" in files and
                "state/airdrop-radar/event-index.json" in files,
                "RADAR_ACTION_EVIDENCE_MISSING_STOP")
    inbox = present.get("action-inbox.json", {}).get("requests", {})
    candidates = present.get("action-candidates.json", {}).get("candidates", {})
    for candidate_id, row in candidates.items():
        require(isinstance(candidate_id, str) and HEX32_ID.fullmatch(candidate_id)
                and isinstance(row, dict) and
                row.get("candidate_id") == candidate_id,
                "RADAR_ACTION_CANDIDATE_ROW_INVALID")
        request_id = row.get("request_id")
        # Original source reconcile_incomplete() can resume any candidate
        # without request binding. Even if the same bytes were SHA-pinned,
        # such a mid-write cutover cannot automatically become active.
        require(isinstance(request_id, str) and
                HEX32_ID.fullmatch(request_id) and
                isinstance(row.get("approval_digest"), str) and
                HEX64.fullmatch(row["approval_digest"]),
                "RADAR_ACTION_UNBOUND_CANDIDATE_STOP")
        require(isinstance(row.get("source_event_id"), str) and
                radar_hashes.get(row["source_event_id"]) ==
                row.get("source_ledger_hash") and
                isinstance(row.get("source_ledger_hash"), str) and
                HEX64.fullmatch(row["source_ledger_hash"]),
                "RADAR_CANDIDATE_SOURCE_HASH_MISMATCH")
        approval = inbox.get(request_id)
        require(isinstance(approval, dict) and
                approval.get("status") in ("rejected", "expired", "consumed") and
                approval.get("approval_digest") == row["approval_digest"],
                "RADAR_ACTION_CANDIDATE_APPROVAL_MISMATCH")
        require(all(approval.get(field) == row.get(field) for field in (
                "source_event_id", "payload_sha256", "action_class")),
                "RADAR_ACTION_CANDIDATE_REQUEST_BINDING_MISMATCH")
    by_id = {row.get("request_id"): row for row in candidates.values()
             if isinstance(row, dict) and isinstance(row.get("request_id"), str)}
    for request_id, row in present.get("action-executions.json", {}).get(
            "executions", {}).items():
        candidate = by_id.get(request_id)
        require(isinstance(candidate, dict) and
                candidate.get("candidate_id") == row.get("candidate_id") and
                isinstance(row.get("source_event_id"), str) and
                radar_hashes.get(row["source_event_id"]) ==
                row.get("source_ledger_hash") and
                all(row.get(field) == candidate.get(field) for field in (
                    "source_event_id", "source_ledger_hash",
                    "payload_sha256", "action_class", "approval_digest")),
                "RADAR_EXECUTION_SOURCE_CANDIDATE_MISMATCH")
        if row.get("status") != "succeeded":
            continue
        approval = inbox.get(request_id)
        require(isinstance(approval, dict) and
                approval.get("status") == "consumed" and
                approval.get("consumption_receipt") == row.get("receipt") and
                approval.get("approval_digest") == row.get("approval_digest"),
                "RADAR_ACTION_SUCCESS_APPROVAL_MISMATCH")

def verify_files(root, entries):
    observed = {}
    total = 0
    for entry in entries:
        require(isinstance(entry, dict) and
                set(entry) == {"path", "size", "sha256"}, "ENTRY_SCHEMA")
        name = entry["path"]
        require(isinstance(name, str) and name not in observed,
                "DUPLICATE_OR_BAD_ENTRY")
        require(name not in ("state/signer/close1-approved-trade.lock",
                             "state/signer/close1-registration.lock"),
                "TRANSIENT_FINANCE_LOCK_IN_ARCHIVE_STOP")
        require(archive_path_allowed(name), "UNCLASSIFIED_ARCHIVE_PATH_STOP")
        expected = entry["sha256"]
        expected_size = entry["size"]
        require(type(expected_size) is int and 0 <= expected_size <=
                MAX_SINGLE_FILE and isinstance(expected, str) and
                HEX64.fullmatch(expected), "ENTRY_SIZE_OR_DIGEST")
        path = no_link_path(root, name)
        if name.startswith("state/") and TCLK_PRIVATE.fullmatch(name[6:]):
            require((path.stat().st_mode & 0o077) == 0,
                    "TCLK_PRIVATE_MODE_EXPOSED")
            require(expected_size > 0, "TCLK_EMPTY_STATE_STOP")
        elif name.startswith("state/") and TCLK_PUBLIC.fullmatch(name[6:]):
            require(expected_size > 0, "TCLK_EMPTY_STATE_STOP")
        size, actual = file_digest(path, MAX_SINGLE_FILE)
        require(size == expected_size and actual == expected,
                "ARTIFACT_SHA256_OR_SIZE_MISMATCH")
        observed[name] = path
        total += size
        require(total <= MAX_TOTAL, "BUNDLE_TOO_LARGE")
    require(REQUIRED <= set(observed), "REQUIRED_ARTIFACT_MISSING")
    verify_tclk_custody(observed)
    for name in SQLITE_FILES:
        for suffix in ("-wal", "-shm", "-journal"):
            require(not os.path.lexists(str(observed[name]) + suffix),
                    "SQLITE_INCOMPLETE_SIDECAR_PRESENT")
    require_exact_restored_tree(root, set(observed))
    verify_finance_fence_files(observed)
    verify_challenge_artifacts(observed)
    verify_challenge_request_journals(observed)
    source_radar_hashes = verify_radar_ledger(observed)
    verify_radar_operational_state(observed, source_radar_hashes)
    return observed, total

# Exact financial attempt/receipt pairing mirrors the R861/R864 archive
# contract. This checks FILE PRESENCE ONLY, not whether a transaction settled.
FINANCE_ATTEMPT = re.compile(r"^state/signer/close1-attempt-([a-f0-9]{64})[.]json$")
FINANCE_RECEIPT = re.compile(r"^state/signer/close1-receipt-([a-f0-9]{64})[.]json$")


def verify_finance_fence_files(observed):
    attempts = set()
    receipts = set()
    finance = False
    for name in observed:
        if name.startswith("state/close1/") or (name.startswith(
                "state/signer/close1-") and
                name != "state/signer/close1-registration.json"):
            finance = True
        if match := FINANCE_ATTEMPT.fullmatch(name):
            attempts.add(match.group(1))
        if match := FINANCE_RECEIPT.fullmatch(name):
            receipts.add(match.group(1))
    require(receipts <= attempts, "FINANCE_RECEIPT_WITHOUT_ATTEMPT_STOP")
    require(attempts == receipts, "FINANCE_AMBIGUOUS_ATTEMPT_STOP")
    require(not finance or
            "state/close1/close1-own-account.json" in observed,
            "FINANCE_ACCOUNT_LEDGER_MISSING_STOP")
    require("state/signer/close1-approved-trade.lock" not in observed,
            "TRANSIENT_FINANCE_LOCK_IN_ARCHIVE_STOP")


def verify_historic_registration(files, identity, nonces):
    """Validate one-shot 2026 Close1 registration without permitting a replay.

    File provenance is pinned to the original DID plus the archive hash. This
    structure-only check is NOT a cryptographic signature verification.
    """
    name = "state/signer/close1-registration.json"
    if name not in files:
        return False
    value = read_small_json(files[name])
    require(isinstance(value, dict) and set(value) == {
        "schema_version", "room", "did", "text", "state", "nonce",
        "attempted_at", "seq", "ts", "posted_record",
    }, "CLOSE1_REGISTRATION_SCHEMA_STOP")
    text = json.dumps({"key": identity, "season": "close-1", "t": "owner"},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    nonce = value.get("nonce")
    require(value.get("schema_version") == 1 and
            value.get("room") == "close1" and
            value.get("did") == identity and
            value.get("state") == "posted" and
            value.get("text") == text and
            isinstance(nonce, str) and nonce.isascii() and
            nonce.isdecimal() and 0 < len(nonce) <= 19 and int(nonce) > 0,
            "CLOSE1_REGISTRATION_NOT_TERMINAL_STOP")
    floor = nonces.get(identity + "|close1")
    require(type(floor) is int and int(nonce) <= floor,
            "CLOSE1_REGISTRATION_NONCE_ROLLBACK_STOP")
    row = value.get("posted_record")
    require(isinstance(row, dict) and row.get("from") == identity and
            row.get("text") == text and str(row.get("nonce")) == nonce and
            type(row.get("nonce")) in (str, int) and
            type(row.get("seq")) is int and row["seq"] >= 0 and
            row.get("seq") == value.get("seq") and
            isinstance(row.get("ts"), str) and bool(row["ts"]) and
            row.get("ts") == value.get("ts") and
            isinstance(row.get("sig"), str) and bool(row["sig"]) and
            (value.get("attempted_at") is None or
             (isinstance(value["attempted_at"], str) and
              bool(value["attempted_at"]))),
            "CLOSE1_REGISTRATION_RECEIPT_MISMATCH_STOP")
    return True


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

def verify_ledger(files, expected_did_sha256):
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
    # Original DID continuity requires a separate trusted pre-migration pin.
    require(hashlib.sha256(identity.encode("utf-8")).hexdigest() ==
            expected_did_sha256, "EXTERNAL_ORIGINAL_DID_MISMATCH")
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
    seen_did_room_nonces = set()
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
        # A high-water counter alone does not detect two independently
        # prepared/published intents reusing the same signed room nonce.
        nonce_tuple = (identity, room, nonce)
        require(nonce_tuple not in seen_did_room_nonces,
                "SIGNER_NONCE_REUSE_DETECTED")
        seen_did_room_nonces.add(nonce_tuple)
        if record.get("state") == "acknowledged":
            require(item.get("status") == "acknowledged",
                    "ACK_RECORD_IDS_MISMATCH")
        elif record.get("state") == "prepared" and item.get("status") == "quarantined":
            require(key in CONTROLLED_QUARANTINE and
                    item.get("category") == "controlled_e2e" and
                    item.get("room") == "lobby" and
                    item.get("quarantine_reason") == CONTROLLED_QUARANTINE[key] and
                    isinstance(item.get("quarantined_at"), str) and
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
    verify_historic_registration(files, identity, nonces)
    return len(ack), quarantined

def main(argv=None):
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--expected-did-sha256", required=True)
    args = parser.parse_args(argv)
    require(HEX64.fullmatch(args.manifest_sha256 or "") is not None,
            "EXTERNAL_DIGEST_REQUIRED")
    require(HEX64.fullmatch(args.expected_did_sha256 or "") is not None,
            "EXTERNAL_ORIGINAL_DID_SHA256_REQUIRED")
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
    ack, quarantined = verify_ledger(files, args.expected_did_sha256)
    print("FLOP_OFFHOST_MANIFEST_PINNED_SHA256_PASS", flush=True)
    print("FLOP_OFFHOST_FILE_SHA256_PASS count=" + str(len(files)), flush=True)
    print("FLOP_OFFHOST_SQLITE_QUICK_CHECK_PASS count=" + str(len(sqlite_pages)), flush=True)
    print("FLOP_OFFHOST_EXTERNAL_ORIGINAL_DID_PIN_PASS", flush=True)
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
