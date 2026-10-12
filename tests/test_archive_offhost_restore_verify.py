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
        "state/nonces.json": {"key-one": "opaque"},
        "state/observer/observer-state.json": {"completed": True},
        "state/observer/resident-state.json": {"idle": True},
        "state/autopilot/autopilot-outbox.json": {
            "schema_version": 1,
            "enabled": False, "paused": True,
            "outbox": {"a": {"status": "acknowledged", "receipt_hash": digest}},
            "receipts": {"a": {"receipt_hash": digest}},
        },
        "state/signer/oracle-signer-receipts.json": {
            "schema_version": 1, "receipts": {
                "a": {"state": "acknowledged", "did": did, "receipt_hash": digest}
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


def manifest(bundle, *, remove=(), tamper=False):
    entries = []
    for name in REQUIRED:
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
    assert "key-one" not in p.stdout


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
