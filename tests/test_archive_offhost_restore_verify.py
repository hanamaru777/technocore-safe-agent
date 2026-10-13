"""Fully local synthetic bundle recovery tests; no cloud, no production files."""
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging/archive/verify-flop-offhost-restore.py"
SOURCE_HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
REQUIRED = (
    "capture/lobby-capture.sqlite3",
    "capture/lobby-capture-service.sqlite3",
    "state/verified-did.json",
    "state/nonces.json",
    "state/activities.jsonl",
    "state/observer/observer-state.json",
    "state/observer/resident-state.json",
    "state/autopilot/autopilot-outbox.json",
    "state/signer/oracle-signer-receipts.json",
)


def build(tmp_path):
    bundle = tmp_path / "offhost"
    bundle.mkdir()
    digest = hashlib.sha256(b"receipt").hexdigest()
    did = "did:key:z" + "x" * 48
    values = {
        "state/verified-did.json": {"did": did},
        "state/nonces.json": {did + "|public-room": 123},
        "state/observer/observer-state.json": {"completed": True},
        "state/observer/resident-state.json": {"idle": True},
        "state/autopilot/autopilot-outbox.json": {
            "schema_version": 1,
            "enabled": False, "paused": True,
            "outbox": {"a": {"status": "acknowledged", "room": "public-room",
                              "receipt_hash": digest}},
            "receipts": {"a": {"receipt_hash": digest}},
        },
        "state/signer/oracle-signer-receipts.json": {
            "schema_version": 1, "receipts": {
                "a": {"state": "acknowledged", "did": did, "nonce": "123",
                      "receipt_hash": digest}
            },
        },
    }
    for name in REQUIRED:
        f = bundle / name
        f.parent.mkdir(exist_ok=True, parents=True)
        if name.endswith(".sqlite3"):
            with sqlite3.connect(str(f)) as db:
                db.execute("create table sample (id integer, value text)")
                db.execute("insert into sample values (1,'ok')")
                db.commit()
        elif name.endswith(".json"):
            f.write_text(json.dumps(values[name]), encoding="utf-8")
        else:
            f.write_text("history\n", encoding="utf-8")
    return bundle


def manifest(bundle, *, remove=(), tamper=False, extras=()):
    entries = []
    for name in REQUIRED + tuple(extras):
        if name in remove:
            continue
        raw = (bundle/name).read_bytes()
        entries.append({"path":name, "size":len(raw),
                        "sha256":hashlib.sha256(raw).hexdigest()})
    doc = {"schema":1, "kind":"flop-retirement-offhost-v1",
           "source_commit": SOURCE_HEAD, "files":entries}
    if tamper:
        doc["source_commit"] = "0" * 40
    raw = json.dumps(doc, sort_keys=True, separators=(",",":")).encode()
    (bundle/"RETIREMENT-MANIFEST.json").write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def verify(bundle,sha):
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--bundle",str(bundle),
         "--manifest-sha256",sha],
        capture_output=True, text=True, timeout=20
    )


def test_frozen_complete_bundle_verifies_no_secret_values_leaked(tmp_path):
    b = build(tmp_path)
    sha = manifest(b)
    p = verify(b,sha)
    assert p.returncode == 0, p.stderr + p.stdout
    assert "FLOP_OFFHOST_ARCHIVE_CONTENT_VERIFIED_PASS" in p.stdout
    assert "FLOP_OCI_DELETION_NOT_AUTHORIZED_BY_FILE_PROOF_ALONE" in p.stdout
    assert "FLOP_OFFHOST_SQLITE_QUICK_CHECK_PASS count=2" in p.stdout
    assert "FLOP_OFFHOST_LEDGER_ACK_IDS_AND_HASHES_PASS count=1" in p.stdout
    assert "did:key:" not in p.stdout
    assert "public-room" not in p.stdout


def test_tampered_capture_db_rejected_even_if_sqlite_still_valid(tmp_path):
    b = build(tmp_path)
    sha = manifest(b)
    with sqlite3.connect(b/"capture/lobby-capture.sqlite3") as db:
        db.execute("insert into sample values(2,'changed')")
        db.commit()
    p = verify(b,sha)
    assert p.returncode == 42
    assert "ARTIFACT_SHA256_OR_SIZE_MISMATCH" in p.stdout


def test_wrong_external_manifest_pin_is_rejected(tmp_path):
    b = build(tmp_path)
    manifest(b)
    p = verify(b,"0" * 64)
    assert p.returncode == 42
    assert "OUT_OF_BAND_MANIFEST_HASH_MISMATCH" in p.stdout


def test_missing_required_data_is_rejected(tmp_path):
    b = build(tmp_path)
    sha = manifest(b,remove=("state/nonces.json",))
    assert "MANIFEST_FILE_COUNT" in verify(b,sha).stdout


def test_symlink_artifact_rejected(tmp_path):
    b = build(tmp_path)
    sha = manifest(b)
    file = b/"state/nonces.json"
    file.unlink()
    file.symlink_to(b/"state/verified-did.json")
    p = verify(b,sha)
    assert p.returncode == 42
    assert "SYMLINK_REJECTED" in p.stdout


def test_uncheckpointed_wal_sidecar_is_rejected(tmp_path):
    b = build(tmp_path)
    sha = manifest(b)
    (b/"capture/lobby-capture.sqlite3-wal").write_bytes(b"WAL")
    p = verify(b,sha)
    assert p.returncode == 42
    assert "SQLITE_INCOMPLETE_SIDECAR_PRESENT" in p.stdout


def test_cross_ledger_ack_receipt_mismatch_is_rejected(tmp_path):
    b = build(tmp_path)
    f = b/"state/autopilot/autopilot-outbox.json"
    ob = json.loads(f.read_text())
    ob["receipts"]["a"]["receipt_hash"] = "a"*64
    f.write_text(json.dumps(ob))
    sha = manifest(b)
    p = verify(b,sha)
    assert p.returncode == 42
    assert "ACK_RECEIPT_HASH_MISMATCH" in p.stdout


def test_manifest_with_wrong_source_rejected_despite_matching_sha(tmp_path):
    b = build(tmp_path)
    sha = manifest(b,tamper=True)
    p = verify(b,sha)
    assert p.returncode == 42
    assert "MANIFEST_IDENTITY" in p.stdout



def rewrite(bundle, name, update):
    file = bundle / name
    value = json.loads(file.read_text())
    update(value)
    file.write_text(json.dumps(value))
    return value


def test_pending_queue_without_signer_receipt_blocks_restore(tmp_path):
    b = build(tmp_path)
    rewrite(b, "state/autopilot/autopilot-outbox.json",
            lambda d: d["outbox"].update(
                {"pending": {"status": "queued", "room": "public-room"}}))
    p = verify(b, manifest(b))
    assert p.returncode == 42
    assert "OUTBOX_PENDING_OR_UNKNOWN_STOP" in p.stdout


def test_signer_posted_receipt_is_not_terminal(tmp_path):
    b = build(tmp_path)
    rewrite(b, "state/signer/oracle-signer-receipts.json",
            lambda d: d["receipts"]["a"].update(state="posted"))
    def set_unsettled(d):
        d["outbox"]["a"]["status"] = "posted"
        d["receipts"].clear()
    rewrite(b, "state/autopilot/autopilot-outbox.json", set_unsettled)
    p = verify(b, manifest(b))
    assert p.returncode == 42
    assert "SIGNER_UNRESOLVED_POST_STOP" in p.stdout


def set_controlled_quarantine(bundle, version, category="controlled_e2e"):
    key = hashlib.sha256(("controlled-e2e-" + version).encode()).hexdigest()[:20]
    reason = ("submission_unknown" if version == "v1"
              else "legacy_unhandled_http_ambiguity")
    def set_outbox(d):
        row = d["outbox"].pop("a")
        row.update(status="quarantined", room="lobby", category=category,
            quarantine_reason=reason, quarantined_at="2026-10-12T00:00:00+00:00")
        row.pop("receipt_hash")
        d["outbox"][key] = row
        d["receipts"].clear()
    rewrite(bundle, "state/autopilot/autopilot-outbox.json", set_outbox)
    def set_signer(d):
        row = d["receipts"].pop("a")
        row["state"] = "prepared"
        d["receipts"][key] = row
    rewrite(bundle, "state/signer/oracle-signer-receipts.json", set_signer)
    def set_nonce(d):
        original = next(iter(d))
        identity = original.split("|", 1)[0]
        d[identity + "|lobby"] = 123
    rewrite(bundle, "state/nonces.json", set_nonce)


def test_quarantined_controlled_history_is_preserved_without_retry(tmp_path):
    for version in ("v1", "v2"):
        b = build(tmp_path / version)
        set_controlled_quarantine(b, version)
        p = verify(b, manifest(b))
        assert p.returncode == 0, p.stdout
        assert "FLOP_OFFHOST_QUARANTINED_HISTORY_PASS count=1" in p.stdout
        assert "FLOP_OFFHOST_WRITER_EPOCH_NOT_PROVEN" in p.stdout


def test_untrusted_quarantine_cannot_hide_replayable_prepared_receipt(tmp_path):
    b = build(tmp_path)
    set_controlled_quarantine(b, "v1", category="unknown")
    p = verify(b, manifest(b))
    assert p.returncode == 42
    assert "QUARANTINE_NOT_AUTHENTICATED" in p.stdout


def test_noncontrolled_fake_quarantine_id_rejected(tmp_path):
    b = build(tmp_path)
    key = "f" * 20
    def fake_outbox(d):
        row = d["outbox"].pop("a")
        row.update(status="quarantined", room="lobby", category="controlled_e2e",
            quarantine_reason="submission_unknown",
            quarantined_at="2026-10-12T00:00:00+00:00")
        d["outbox"][key] = row
        d["receipts"].clear()
    rewrite(b, "state/autopilot/autopilot-outbox.json", fake_outbox)
    def fake_signer(d):
        row = d["receipts"].pop("a")
        row["state"] = "prepared"
        d["receipts"][key] = row
    rewrite(b, "state/signer/oracle-signer-receipts.json", fake_signer)
    def fake_nonce(d):
        identity = next(iter(d)).split("|", 1)[0]
        d[identity + "|lobby"] = 123
    rewrite(b, "state/nonces.json", fake_nonce)
    p = verify(b, manifest(b))
    assert p.returncode == 42
    assert "QUARANTINE_NOT_AUTHENTICATED" in p.stdout


def test_manifest_over_previous_128_limit_is_supported_offhost(tmp_path):
    b = build(tmp_path)
    extra = []
    for n in range(130):
        name = "state/extra/file-" + str(n).zfill(3) + ".txt"
        path = b / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"bounded content")
        extra.append(name)
    p = verify(b, manifest(b, extras=extra))
    assert p.returncode == 0, p.stdout
    assert "FLOP_OFFHOST_FILE_SHA256_PASS count=139" in p.stdout

def test_nonce_rollback_is_rejected_even_when_manifest_hash_matches(tmp_path):
    b = build(tmp_path)
    rewrite(b, "state/nonces.json", lambda d: d.update(
        {next(iter(d)): 122}))
    p = verify(b, manifest(b))
    assert p.returncode == 42
    assert "NONCE_HIGH_WATER_BEHIND_RECEIPT" in p.stdout


def test_invalid_nonce_type_is_rejected(tmp_path):
    b = build(tmp_path)
    rewrite(b, "state/nonces.json", lambda d: d.update(
        {next(iter(d)): True}))
    p = verify(b, manifest(b))
    assert p.returncode == 42
    assert "NONCE_HIGH_WATER_SCHEMA_INVALID" in p.stdout


def test_signer_did_must_match_pinned_verified_did(tmp_path):
    b = build(tmp_path)
    rewrite(b, "state/signer/oracle-signer-receipts.json",
            lambda d: d["receipts"]["a"].update(did="did:key:zOTHER"))
    p = verify(b, manifest(b))
    assert p.returncode == 42
    assert "SIGNER_DID_MISMATCH" in p.stdout


def test_missing_signer_nonce_binding_is_rejected(tmp_path):
    b = build(tmp_path)
    rewrite(b, "state/autopilot/autopilot-outbox.json",
            lambda d: d["outbox"]["a"].update(room="different-room"))
    p = verify(b, manifest(b))
    assert p.returncode == 42
    assert "NONCE_HIGH_WATER_BEHIND_RECEIPT" in p.stdout


def test_expired_intent_without_receipt_is_terminal(tmp_path):
    b = build(tmp_path)
    rewrite(b, "state/autopilot/autopilot-outbox.json",
            lambda d: d["outbox"].update(
                {"expired": {"status": "expired", "room": "public-room"}}))
    p = verify(b, manifest(b))
    assert p.returncode == 0, p.stdout

def test_source_never_contacts_network_or_updates_services():
    code=SCRIPT.read_text()
    compile(code,str(SCRIPT),"exec")
    assert "BUFFER = 128 * 1024" in code
    for marker in ("sqlite3.connect", "sha256", "FLOP_OCI_DELETION_NOT_AUTHORIZED_BY_FILE_PROOF_ALONE"):
        assert marker in code
    for forbidden in ("import requests", "import httpx", "urlopen(",
                      "subprocess.run", "os.system", "systemctl stop",
                      "systemctl start", "shutil.copy", "write_bytes(",
                      "write_text(", "os.unlink", "os.remove", "OCI_VAULT_SECRET_OCID",
                      "SIGN_SEED"):
        assert forbidden not in code
