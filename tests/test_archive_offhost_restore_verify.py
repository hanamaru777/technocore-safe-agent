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
# Independent synthetic pin: never obtained from the restore bundle.
SYNTHETIC_ORIGINAL_DID = "did:key:z" + "x" * 48
SYNTHETIC_ORIGINAL_DID_SHA256 = hashlib.sha256(
    SYNTHETIC_ORIGINAL_DID.encode("utf-8")).hexdigest()
REQUIRED = (
    "capture/lobby-capture.sqlite3",
    "capture/lobby-capture-service.sqlite3",
    "state/verified-did.json",
    "state/observer-safety.json",
    "state/nonces.json",
    "state/activities.jsonl",
    "state/observer/observer-state.json",
    "state/observer/resident-state.json",
    "state/observer/observer-config.json",
    "state/observer/resident-config.json",
    "state/observer/observer-heartbeat.json",
    "state/autopilot/autopilot-outbox.json",
    "state/autopilot/autopilot-audit.jsonl",
    "state/signer/oracle-signer-receipts.json",
    "state/signer/signer-health.json",
    "state/signer/upstream-health.json",
)


def build(tmp_path):
    bundle = tmp_path / "offhost"
    bundle.mkdir()
    digest = hashlib.sha256(b"receipt").hexdigest()
    did = SYNTHETIC_ORIGINAL_DID
    values = {
        "state/verified-did.json": {"did": did},
        "state/observer-safety.json": {"schema_version": 1, "health": "degraded"},
        "state/nonces.json": {did + "|public-room": 123},
        "state/observer/observer-state.json": {"completed": True},
        "state/observer/resident-state.json": {"idle": True},
        "state/observer/observer-config.json": {"synthetic": True},
        "state/observer/resident-config.json": {"synthetic": True},
        "state/observer/observer-heartbeat.json": {"synthetic": True},
        "state/signer/signer-health.json": {"synthetic": True},
        "state/signer/upstream-health.json": {"synthetic": True},
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


def verify(bundle,sha, *, did_pin=SYNTHETIC_ORIGINAL_DID_SHA256):
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--bundle",str(bundle),
         "--manifest-sha256",sha, "--expected-did-sha256",did_pin],
        capture_output=True, text=True, timeout=20
    )


def test_frozen_complete_bundle_verifies_no_secret_values_leaked(tmp_path):
    b = build(tmp_path)
    sha = manifest(b)
    p = verify(b,sha)
    assert p.returncode == 0, p.stderr + p.stdout
    assert "FLOP_OFFHOST_ARCHIVE_CONTENT_VERIFIED_PASS" in p.stdout
    assert "FLOP_OFFHOST_EXTERNAL_ORIGINAL_DID_PIN_PASS" in p.stdout
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


def test_self_consistent_wrong_did_rejected_even_with_new_manifest_pin(tmp_path):
    bundle = build(tmp_path)
    replacement = "did:key:z" + "y" * 48
    rewrite(bundle, "state/verified-did.json",
            lambda value: value.update(did=replacement))
    def rekey(value):
        old_key = next(iter(value))
        prior_nonce = value.pop(old_key)
        value[replacement + "|public-room"] = prior_nonce
    rewrite(bundle, "state/nonces.json", rekey)
    rewrite(bundle, "state/signer/oracle-signer-receipts.json",
            lambda value: value["receipts"]["a"].update(did=replacement))
    pinned_manifest = manifest(bundle)
    forged_pin = hashlib.sha256(replacement.encode("utf-8")).hexdigest()
    assert verify(bundle, pinned_manifest, did_pin=forged_pin).returncode == 0
    result = verify(bundle, pinned_manifest)
    assert result.returncode == 42
    assert "EXTERNAL_ORIGINAL_DID_MISMATCH" in result.stdout
    assert replacement not in result.stdout


def test_invalid_or_missing_original_did_anchor_fails_closed(tmp_path):
    bundle = build(tmp_path)
    pinned_manifest = manifest(bundle)
    result = verify(bundle, pinned_manifest, did_pin="bad")
    assert result.returncode == 42
    assert "EXTERNAL_ORIGINAL_DID_SHA256_REQUIRED" in result.stdout
    missing = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--bundle", str(bundle),
         "--manifest-sha256", pinned_manifest],
        capture_output=True, text=True, timeout=20)
    assert missing.returncode != 0
    assert "FLOP_OFFHOST_ARCHIVE_CONTENT_VERIFIED_PASS" not in missing.stdout


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
        (tmp_path / version).mkdir()
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
        name = "state/proof-plans/" + format(n, "016x") + ".json"
        path = b / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"bounded content")
        extra.append(name)
    p = verify(b, manifest(b, extras=extra))
    assert p.returncode == 0, p.stdout
    assert "FLOP_OFFHOST_FILE_SHA256_PASS count=146" in p.stdout

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


def test_unmanifested_extra_file_is_never_silently_accepted(tmp_path):
    bundle = build(tmp_path)
    digest = manifest(bundle)
    (bundle / "state" / "unexpected.json").write_text("unreviewed", encoding="utf-8")
    result = verify(bundle, digest)
    assert result.returncode == 42
    assert "UNMANIFESTED_FILE_STOP" in result.stdout


def test_unmanifested_empty_directory_is_rejected(tmp_path):
    bundle = build(tmp_path)
    digest = manifest(bundle)
    (bundle / "state" / "untracked").mkdir()
    result = verify(bundle, digest)
    assert result.returncode == 42
    assert "UNMANIFESTED_DIRECTORY_STOP" in result.stdout


def test_unmanifested_symlink_dir_rejected_without_following(tmp_path):
    bundle = build(tmp_path)
    digest = manifest(bundle)
    (bundle / "unexpected").symlink_to(tmp_path, target_is_directory=True)
    result = verify(bundle, digest)
    assert result.returncode == 42
    assert "RESTORED_TREE_SYMLINK_STOP" in result.stdout


def test_unmanifested_root_level_file_rejected(tmp_path):
    bundle = build(tmp_path)
    digest = manifest(bundle)
    (bundle / "hidden-extra").write_bytes(b"unexpected")
    result = verify(bundle, digest)
    assert result.returncode == 42
    assert "UNMANIFESTED_FILE_STOP" in result.stdout

# R872: R861/R864 REQUIRE thirteen state artifacts, not just the seven
# originally required by the independent offhost verifier.
R861_ADDITIONAL_REQUIRED = (
    "state/observer-safety.json",
    "state/observer/observer-config.json",
    "state/observer/resident-config.json",
    "state/observer/observer-heartbeat.json",
    "state/autopilot/autopilot-audit.jsonl",
    "state/signer/signer-health.json",
    "state/signer/upstream-health.json",
)


@pytest.mark.parametrize("missing", R861_ADDITIONAL_REQUIRED)
def test_r861_required_state_cannot_be_omitted_even_with_valid_pin_and_filler(
    tmp_path, missing
):
    bundle = build(tmp_path)
    filler = "state/proof-plans/ffffffffffffffff.json"
    fake = bundle / filler
    fake.parent.mkdir(parents=True, exist_ok=True)
    fake.write_bytes(b"not a required source artifact")
    # Keep total file count valid: missing canonical state cannot be replaced
    # by an arbitrary filler even if an externally pinned manifest hash matches.
    digest = manifest(bundle, remove=(missing,), extras=(filler,))
    result = verify(bundle, digest)
    assert result.returncode == 42
    assert "REQUIRED_ARTIFACT_MISSING" in result.stdout



def archive_files(bundle, names):
    for name in names:
        path = bundle / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'{"synthetic":true}')
    return manifest(bundle, extras=names)


def add_synthetic_historic_registration(bundle, *, state="posted", nonce="123"):
    did = SYNTHETIC_ORIGINAL_DID
    text = json.dumps({"key": did, "season": "close-1", "t": "owner"},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    receipt = {"from": did, "text": text, "nonce": nonce,
               "seq": 1241872, "ts": "2026-09-26T03:40:55.463293Z",
               "sig": "synthetic-only-no-real-key"}
    name = "state/signer/close1-registration.json"
    file = bundle / name
    file.write_text(json.dumps({
        "schema_version": 1, "room": "close1", "did": did,
        "text": text, "state": state, "nonce": nonce,
        "attempted_at": "2026-09-26T03:40:54Z",
        "seq": receipt["seq"], "ts": receipt["ts"],
        "posted_record": receipt,
    }))
    rewrite(bundle, "state/nonces.json",
            lambda item: item.update({did + "|close1": 123}))
    return name


def test_completed_historic_registration_survives_without_trade_ledger(tmp_path):
    bundle = build(tmp_path)
    record = add_synthetic_historic_registration(bundle)
    result = verify(bundle, manifest(bundle, extras=(record,)))
    assert result.returncode == 0, result.stdout
    assert "FLOP_OFFHOST_ARCHIVE_CONTENT_VERIFIED_PASS" in result.stdout
    assert SYNTHETIC_ORIGINAL_DID not in result.stdout


def test_reconciled_existing_registration_allows_null_attempted_at(tmp_path):
    # Original one-shot mark_posted(initial_state(), existing_valid_row)
    # saves posted + verified record without ever attempting a new POST.
    bundle = build(tmp_path)
    record = add_synthetic_historic_registration(bundle)
    rewrite(bundle, record, lambda value: value.update(attempted_at=None))
    result = verify(bundle, manifest(bundle, extras=(record,)))
    assert result.returncode == 0, result.stdout
    assert "FLOP_OFFHOST_ARCHIVE_CONTENT_VERIFIED_PASS" in result.stdout
    # Inconsistent timestamps cannot masquerade as a valid reconciliation.
    rewrite(bundle, record, lambda value: value.update(attempted_at=1234))
    result = verify(bundle, manifest(bundle, extras=(record,)))
    assert result.returncode == 42
    assert "CLOSE1_REGISTRATION_RECEIPT_MISMATCH_STOP" in result.stdout


def test_historic_registration_inflight_and_nonce_rollback_stop(tmp_path):
    bundle = build(tmp_path)
    record = add_synthetic_historic_registration(bundle, state="attempting")
    result = verify(bundle, manifest(bundle, extras=(record,)))
    assert result.returncode == 42
    assert "CLOSE1_REGISTRATION_NOT_TERMINAL_STOP" in result.stdout
    rewrite(bundle, record, lambda value: value.update(state="posted", nonce="124"))
    result = verify(bundle, manifest(bundle, extras=(record,)))
    assert result.returncode == 42
    assert "CLOSE1_REGISTRATION_NONCE_ROLLBACK_STOP" in result.stdout


def test_historic_registration_identity_and_receipt_mismatch_stop(tmp_path):
    bundle = build(tmp_path)
    record = add_synthetic_historic_registration(bundle)
    rewrite(bundle, record, lambda value: value.update(did="did:key:zOTHER"))
    result = verify(bundle, manifest(bundle, extras=(record,)))
    assert result.returncode == 42
    assert "CLOSE1_REGISTRATION_NOT_TERMINAL_STOP" in result.stdout
    rewrite(bundle, record, lambda value: value.update(did=SYNTHETIC_ORIGINAL_DID))
    rewrite(bundle, record,
            lambda value: value["posted_record"].update(seq=1241873))
    result = verify(bundle, manifest(bundle, extras=(record,)))
    assert result.returncode == 42
    assert "CLOSE1_REGISTRATION_RECEIPT_MISMATCH_STOP" in result.stdout


def test_transient_historic_registration_lock_is_not_an_archive_file(tmp_path):
    bundle = build(tmp_path)
    lock = "state/signer/close1-registration.lock"
    result = verify(bundle, archive_files(bundle, (lock,)))
    assert result.returncode == 42
    assert "TRANSIENT_FINANCE_LOCK_IN_ARCHIVE_STOP" in result.stdout


def test_close1_receipt_without_durable_attempt_is_rejected(tmp_path):
    b = build(tmp_path)
    receipt = "state/signer/close1-receipt-" + "a" * 64 + ".json"
    account = "state/close1/close1-own-account.json"
    p = verify(b, archive_files(b, (receipt, account)))
    assert p.returncode == 42
    assert "FINANCE_RECEIPT_WITHOUT_ATTEMPT_STOP" in p.stdout


def test_close1_attempt_without_receipt_is_rejected_as_ambiguous(tmp_path):
    b = build(tmp_path)
    attempt = "state/signer/close1-attempt-" + "a" * 64 + ".json"
    account = "state/close1/close1-own-account.json"
    p = verify(b, archive_files(b, (attempt, account)))
    assert p.returncode == 42
    assert "FINANCE_AMBIGUOUS_ATTEMPT_STOP" in p.stdout


def test_close1_paired_fence_without_account_ledger_is_rejected(tmp_path):
    b = build(tmp_path)
    attempt = "state/signer/close1-attempt-" + "a" * 64 + ".json"
    receipt = "state/signer/close1-receipt-" + "a" * 64 + ".json"
    p = verify(b, archive_files(b, (attempt, receipt)))
    assert p.returncode == 42
    assert "FINANCE_ACCOUNT_LEDGER_MISSING_STOP" in p.stdout


def test_close1_matching_fences_and_account_allow_structural_restoration(tmp_path):
    b = build(tmp_path)
    attempt = "state/signer/close1-attempt-" + "a" * 64 + ".json"
    receipt = "state/signer/close1-receipt-" + "a" * 64 + ".json"
    account = "state/close1/close1-own-account.json"
    p = verify(b, archive_files(b, (attempt, receipt, account)))
    assert p.returncode == 0, p.stdout
    # This is presence/hash validation only, not finance settlement proof.
    assert "FLOP_OCI_DELETION_NOT_AUTHORIZED_BY_FILE_PROOF_ALONE" in p.stdout


def test_close1_transient_lock_must_not_be_in_restored_manifest(tmp_path):
    b = build(tmp_path)
    lock = "state/signer/close1-approved-trade.lock"
    account = "state/close1/close1-own-account.json"
    p = verify(b, archive_files(b, (lock, account)))
    assert p.returncode == 42
    assert "TRANSIENT_FINANCE_LOCK_IN_ARCHIVE_STOP" in p.stdout


def test_two_acknowledged_signer_intents_cannot_reuse_same_room_nonce(tmp_path):
    b = build(tmp_path)
    def clone_outbox(value):
        value["outbox"]["b"] = dict(value["outbox"]["a"])
        value["receipts"]["b"] = dict(value["receipts"]["a"])
    rewrite(b, "state/autopilot/autopilot-outbox.json", clone_outbox)
    def clone_signer(value):
        value["receipts"]["b"] = dict(value["receipts"]["a"])
    rewrite(b, "state/signer/oracle-signer-receipts.json", clone_signer)
    p = verify(b, manifest(b))
    assert p.returncode == 42
    assert "SIGNER_NONCE_REUSE_DETECTED" in p.stdout


def test_empty_audit_log_has_valid_stable_sha256_and_can_be_restored(tmp_path):
    b = build(tmp_path)
    (b / "state/autopilot/autopilot-audit.jsonl").write_bytes(b"")
    digest = manifest(b)
    p = verify(b, digest)
    assert p.returncode == 0, p.stdout
    assert "FLOP_OFFHOST_ARCHIVE_CONTENT_VERIFIED_PASS" in p.stdout


@pytest.mark.parametrize("rogue", (
    "state/signer/private-seed.json",
    "state/observer/lobby-capture.sqlite3-wal",
    "state/extra/unreviewed.json",
    "capture/unsigned-third-database.sqlite3",
    "state/autopilot/autopilot-audit.jsonl.5",
))
def test_manifest_cannot_authorize_unclassified_source_file_even_with_valid_external_pin(
    tmp_path, rogue
):
    b = build(tmp_path)
    path = b / rogue
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"nonempty-secret-like-test-fixture")
    result = verify(b, manifest(b, extras=(rogue,)))
    assert result.returncode == 42
    assert "UNCLASSIFIED_ARCHIVE_PATH_STOP" in result.stdout


def test_r861_valid_optional_source_paths_remain_supported(tmp_path):
    b = build(tmp_path)
    extras = (
        "state/autopilot/autopilot-audit.jsonl.1",
        "state/proof-plans/1111111111111111.json",
        "state/cursor-lobby.json",
        "state/observer/resident-control.json",
    )
    p = verify(b, archive_files(b, extras))
    assert p.returncode == 0, p.stdout
    assert "FLOP_OFFHOST_ARCHIVE_CONTENT_VERIFIED_PASS" in p.stdout


def test_r924_tclk_private_hashlock_reveal_and_approval_archive_verified(tmp_path):
    bundle = build(tmp_path)
    stage = "a" * 32
    records = (
        "state/autopilot/tclk-pilot/stages/" + stage + ".json",
        "state/autopilot/tclk-pilot/previews/" + stage + ".json",
        "state/autopilot/tclk-pilot/locks/" + stage + ".json",
        "state/autopilot/tclk-pilot/work/" + stage + ".json",
        "state/autopilot/tclk-pilot/reveal-previews/" + stage + ".json",
        "state/autopilot/tclk-pilot/terminal/" + stage + ".json",
        "state/signer/tclk-pilot-secrets/" + stage + ".json",
        "state/signer/tclk-pilot-approvals/" + stage + ".json",
        "state/signer/tclk-pilot-accepts/" + stage + ".json",
        "state/signer/tclk-pilot-reveals/" + stage + ".json",
        "state/signer/tclk-pilot-reveal-approvals/" + stage + ".json",
        "state/signer/tclk-pilot-reveal-publishes/" + stage + ".json",
    )
    for name in records:
        file = bundle / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text('{"synthetic":"not a preimage"}', encoding="utf-8")
        if name.startswith("state/signer/tclk-pilot-"):
            file.chmod(0o600)
    result = verify(bundle, manifest(bundle, extras=records))
    assert result.returncode == 0, result.stdout
    assert "FLOP_OFFHOST_ARCHIVE_CONTENT_VERIFIED_PASS" in result.stdout
    assert "not a preimage" not in result.stdout


def test_r924_tclk_stage_with_preview_missing_private_preimage_is_rejected(tmp_path):
    bundle = build(tmp_path)
    stage = "b" * 32
    records = (
        "state/autopilot/tclk-pilot/stages/" + stage + ".json",
        "state/autopilot/tclk-pilot/previews/" + stage + ".json",
    )
    result = verify(bundle, archive_files(bundle, records))
    assert result.returncode == 42
    assert "TCLK_SECRET_CUSTODY_MISSING" in result.stdout


def test_r924_tclk_private_reveal_without_public_stage_rejected(tmp_path):
    bundle = build(tmp_path)
    name = "state/signer/tclk-pilot-reveals/" + "c" * 32 + ".json"
    sha = archive_files(bundle, (name,))
    (bundle / name).chmod(0o600)
    result = verify(bundle, sha)
    assert result.returncode == 42
    assert "TCLK_STAGE_CUSTODY_MISSING" in result.stdout


def test_r924_tclk_group_readable_secret_rejected_even_with_manifest_pin(tmp_path):
    bundle = build(tmp_path)
    stage = "d" * 32
    records = (
        "state/autopilot/tclk-pilot/stages/" + stage + ".json",
        "state/signer/tclk-pilot-secrets/" + stage + ".json",
    )
    result = verify(bundle, archive_files(bundle, records))
    assert result.returncode == 42
    assert "TCLK_PRIVATE_MODE_EXPOSED" in result.stdout


def test_r924_tclk_unknown_secret_prefix_is_rejected(tmp_path):
    bundle = build(tmp_path)
    name = "state/signer/tclk-pilot-unreviewed/" + "e" * 32 + ".json"
    result = verify(bundle, archive_files(bundle, (name,)))
    assert result.returncode == 42
    assert "UNCLASSIFIED_ARCHIVE_PATH_STOP" in result.stdout


def test_r946_source_radar_challenge_and_public_proof_paths_verify(tmp_path):
    """Mirrored R945 allowlist must retain evidence without revealing values."""
    bundle = build(tmp_path)
    additions = (
        "state/airdrop-radar/state.json",
        "state/airdrop-radar/events.jsonl",
        "state/airdrop-radar/event-index.json",
        "state/airdrop-radar/precontest-candidates.json",
        "state/airdrop-radar/challenges/contest_2026/spec.json",
        "state/airdrop-radar/challenges/contest_2026/progress.json",
        "state/airdrop-radar/challenges/contest_2026/artifacts.json",
        "state/airdrop-radar/challenges/contest_2026/precontest-readiness-sources.json",
        "state/airdrop-radar/challenges/contest_2026/precontest-control-path-proof.json",
        "state/airdrop-radar/challenge-candidate-reviews/challenge_repo.json",
        "state/public-proofs/proof-" + "b" * 16 + "-20261017T080200Z.json",
    )
    archive_files(bundle, additions)
    index = bundle / "state/airdrop-radar/challenges/contest_2026/artifacts.json"
    index.write_text(json.dumps({"schema_version": 1, "artifacts": {}}))
    (bundle / "state/airdrop-radar/events.jsonl").write_bytes(b"")
    (bundle / "state/airdrop-radar/event-index.json").write_text(json.dumps({
        "schema_version": 1, "ledger_count": 0,
        "ledger_tip_hash": "", "events": {}
    }))
    outcome = verify(bundle, manifest(bundle, extras=additions))
    assert outcome.returncode == 0, outcome.stdout
    assert "FLOP_OFFHOST_ARCHIVE_CONTENT_VERIFIED_PASS" in outcome.stdout
    assert "challenge_repo" not in outcome.stdout


@pytest.mark.parametrize("rogue", (
    "state/airdrop-radar/challenges/Contest/spec.json",
    "state/airdrop-radar/challenges/contest/unknown.json",
    "state/airdrop-radar/challenge-candidate-reviews/unknown.bin",
    "state/airdrop-radar/challenges/contest/extra.json",
    "state/airdrop-radar/uv-cache/unsafe.txt",
    "state/public-proofs/private-seed.json",
    "state/public-proofs/proof-wrong-20261017T080200Z.json",
))
def test_r946_unclassified_radar_proofs_stay_fail_closed(tmp_path, rogue):
    bundle = build(tmp_path)
    digest = archive_files(bundle, (rogue,))
    outcome = verify(bundle, digest)
    assert outcome.returncode == 42
    assert "UNCLASSIFIED_ARCHIVE_PATH_STOP" in outcome.stdout


def test_r946_nested_unindexed_payload_rejected_even_when_hash_pinned(tmp_path):
    bundle = build(tmp_path)
    rogue = "state/airdrop-radar/challenges/contest/artifacts/secret.bin"
    digest = archive_files(bundle, (rogue,))
    result = verify(bundle, digest)
    assert result.returncode == 42
    assert "CHALLENGE_ARTIFACT_INDEX_MISSING" in result.stdout


def test_r949_indexed_challenge_artifact_hash_and_bytes_verified(tmp_path):
    bundle = build(tmp_path)
    prefix = "state/airdrop-radar/challenges/challenge_1/"
    index_path = prefix + "artifacts.json"
    payload_path = prefix + "artifacts/rules/v1.pdf"
    archive_files(bundle, (index_path, payload_path))
    payload = b"synthetic PDF-like bytes - no secrets"
    (bundle / payload_path).write_bytes(payload)
    record = {
        "name": "rules/v1.pdf",
        "source_url": "https://raw.githubusercontent.com/flop-labs/example/ref/rules/v1.pdf",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "pinned_at": "2026-10-17T00:00:00+00:00",
        "relative_path": "artifacts/rules/v1.pdf",
    }
    index = bundle / index_path
    index.write_text(json.dumps({"schema_version": 1, "artifacts": {
        record["name"]: record
    }}), encoding="utf-8")
    names = (index_path, payload_path)
    good = verify(bundle, manifest(bundle, extras=names))
    assert good.returncode == 0, good.stdout
    assert "FLOP_OFFHOST_ARCHIVE_CONTENT_VERIFIED_PASS" in good.stdout
    assert "rules/v1.pdf" not in good.stdout
    record["sha256"] = "0" * 64
    index.write_text(json.dumps({"schema_version": 1, "artifacts": {
        record["name"]: record
    }}), encoding="utf-8")
    bad = verify(bundle, manifest(bundle, extras=names))
    assert bad.returncode == 42
    assert "CHALLENGE_ARTIFACT_INDEX_HASH_MISMATCH" in bad.stdout


def test_r949_empty_index_rejects_orphan_artifact(tmp_path):
    bundle = build(tmp_path)
    prefix = "state/airdrop-radar/challenges/challenge_2/"
    index_path = prefix + "artifacts.json"
    file_path = prefix + "artifacts/data.txt"
    archive_files(bundle, (index_path, file_path))
    (bundle / index_path).write_text(json.dumps({
        "schema_version": 1, "artifacts": {}
    }))
    result = verify(bundle, manifest(bundle, extras=(index_path, file_path)))
    assert result.returncode == 42
    assert "CHALLENGE_ARTIFACT_ORPHAN_STOP" in result.stdout


def test_r949_index_referencing_missing_payload_fails_closed(tmp_path):
    bundle = build(tmp_path)
    index_path = "state/airdrop-radar/challenges/c/artifacts.json"
    archive_files(bundle, (index_path,))
    name = "lost.bin"
    (bundle / index_path).write_text(json.dumps({
        "schema_version": 1, "artifacts": {
            name: {"name": name, "source_url": "https://flop.finance/x",
                   "sha256": "a" * 64, "bytes": 7,
                   "pinned_at": "2026-10-17T00:00:00+00:00",
                   "relative_path": "artifacts/" + name}
        }
    }))
    result = verify(bundle, manifest(bundle, extras=(index_path,)))
    assert result.returncode == 42
    assert "CHALLENGE_ARTIFACT_MISSING" in result.stdout


def test_r949_spec_without_artifact_index_cannot_claim_coherent_bundle(tmp_path):
    bundle = build(tmp_path)
    spec = "state/airdrop-radar/challenges/c/spec.json"
    result = verify(bundle, archive_files(bundle, (spec,)))
    assert result.returncode == 42
    assert "CHALLENGE_ARTIFACT_INDEX_MISSING" in result.stdout


def test_r949_unsafe_artifact_name_not_accepted_even_when_manifest_pinned(tmp_path):
    bundle = build(tmp_path)
    illegal = "state/airdrop-radar/challenges/c/artifacts/.secret"
    result = verify(bundle, archive_files(bundle, (illegal,)))
    assert result.returncode == 42
    assert "UNCLASSIFIED_ARCHIVE_PATH_STOP" in result.stdout


def _r950_journal(bundle, *, status, receipt_hash=None):
    journal = "state/airdrop-radar/challenges/contest/requests.json"
    row = {
        "request_id": "request-one", "action": "submit",
        "payload_sha256": "a" * 64, "status": status,
        "planned_at": "2026-10-17T00:00:00+00:00",
        "updated_at": "2026-10-17T00:00:00+00:00",
        "receipt_hash": receipt_hash,
    }
    archive_files(bundle, (journal,))
    (bundle / journal).write_text(json.dumps({
        "schema_version": 1, "requests": {"request-one": row}
    }), encoding="utf-8")
    return manifest(bundle, extras=(journal,))


@pytest.mark.parametrize("status", ("planned", "sent", "ambiguous"))
def test_r950_pending_or_ambiguous_challenge_journal_blocks_cutover(tmp_path, status):
    bundle = build(tmp_path)
    result = verify(bundle, _r950_journal(bundle, status=status))
    assert result.returncode == 42
    assert "CHALLENGE_REQUEST_NONTERMINAL_STOP" in result.stdout
    assert "request-one" not in result.stdout


@pytest.mark.parametrize("status,receipt", (
    ("accepted", "a" * 64),
    ("rejected", None),
    ("reconciled_accepted", "b" * 64),
    ("reconciled_not_found", None),
))
def test_r950_only_terminal_challenge_journals_verify(tmp_path, status, receipt):
    bundle = build(tmp_path)
    result = verify(bundle, _r950_journal(bundle, status=status, receipt_hash=receipt))
    assert result.returncode == 0, result.stdout
    assert "FLOP_OFFHOST_ARCHIVE_CONTENT_VERIFIED_PASS" in result.stdout


def test_r950_accepted_without_verifiable_receipt_rejected(tmp_path):
    bundle = build(tmp_path)
    result = verify(bundle, _r950_journal(bundle, status="accepted"))
    assert result.returncode == 42
    assert "CHALLENGE_ACCEPTED_RECEIPT_MISSING" in result.stdout


def _r954_ledger(bundle, *, tamper=None):
    base = "state/airdrop-radar/"
    events = base + "events.jsonl"
    index = base + "event-index.json"
    from datetime import datetime
    _ = datetime(2026, 10, 17)
    event = {
        "type": "CHANGED", "key": "synthetic_metric",
        "before": None, "after": "ok",
    }
    canon = lambda value, ascii_only=False: json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=ascii_only,
    ).encode("utf-8")
    event["event_id"] = hashlib.sha256(canon({
        "type": event["type"], "key": event["key"],
        "before": event["before"], "after": event["after"],
    }, True)).hexdigest()[:24]
    stamp = "2026-10-17T00:00:00+00:00"
    row = {
        "schema_version": 1, "sequence": 1,
        "record_type": "material_event",
        "event_id": event["event_id"], "first_seen": stamp,
        "last_seen": stamp, "observed_at": stamp,
        "previous_hash": "", "event": event, "source_evidence": [],
    }
    row["hash"] = hashlib.sha256(canon(row)).hexdigest()
    doc = {
        "schema_version": 1, "ledger_count": 1,
        "ledger_tip_hash": row["hash"],
        "events": {
            row["event_id"]: {
                "event_id": row["event_id"],
                "ledger_sequence": 1,
                "ledger_hash": row["hash"],
            }
        },
    }
    archive_files(bundle, (events, index))
    if tamper == "hash":
        row["hash"] = "0" * 64
    if tamper == "prev":
        row["previous_hash"] = "b" * 64
    if tamper == "index":
        doc["ledger_tip_hash"] = "c" * 64
    (bundle / events).write_text(json.dumps(row, ensure_ascii=False) + "\n")
    (bundle / index).write_text(json.dumps(doc))
    return manifest(bundle, extras=(events, index))


def test_r954_pinned_radar_chain_and_index_verify_without_echo(tmp_path):
    bundle = build(tmp_path)
    result = verify(bundle, _r954_ledger(bundle))
    assert result.returncode == 0, result.stdout
    assert "FLOP_OFFHOST_ARCHIVE_CONTENT_VERIFIED_PASS" in result.stdout
    assert "synthetic_metric" not in result.stdout


@pytest.mark.parametrize("tamper,reason", (
    ("hash", "RADAR_CHAIN_HASH_MISMATCH"),
    ("prev", "RADAR_LEDGER_LINK_OR_SCHEMA_INVALID"),
    ("index", "RADAR_INDEX_TIP_MISMATCH"),
))
def test_r954_sha_pinned_but_internal_radar_history_corrupted_stops(
    tmp_path, tamper, reason
):
    bundle = build(tmp_path)
    result = verify(bundle, _r954_ledger(bundle, tamper=tamper))
    assert result.returncode == 42
    assert reason in result.stdout
    assert "synthetic_metric" not in result.stdout


def test_r954_radar_events_without_index_stop(tmp_path):
    bundle = build(tmp_path)
    path = "state/airdrop-radar/events.jsonl"
    result = verify(bundle, archive_files(bundle, (path,)))
    assert result.returncode == 42
    assert "RADAR_LEDGER_INDEX_MISSING" in result.stdout



def _r957_operational_state(bundle, filename, root, key, item=None):
    path = "state/airdrop-radar/" + filename
    archive_files(bundle, (path,))
    value = {"schema_version": 1}
    if root is not None:
        value[root] = {} if key is None else {key: item}
    (bundle / path).write_text(json.dumps(value), encoding="utf-8")
    # Synthetic cross-file test cases were originally single-record. Include
    # a coherent empty Radar history witness only when a record is inserted.
    # This is not an original source census or authentic ledger proof.
    if key is not None:
        ev = "state/airdrop-radar/events.jsonl"
        ix = "state/airdrop-radar/event-index.json"
        (bundle / ev).parent.mkdir(parents=True, exist_ok=True)
        (bundle / ev).write_bytes(b"")
        (bundle / ix).write_text(json.dumps({
            "schema_version": 1, "ledger_count": 0,
            "ledger_tip_hash": "", "events": {}
        }), encoding="utf-8")
        return manifest(bundle, extras=(path, ev, ix))
    return manifest(bundle, extras=(path,))


@pytest.mark.parametrize("filename,root,key,row,reason", (
    ("alert-outbox.json", "events", "alert-1",
     {"event_id": "alert-1", "delivery_state": "pending"},
     "RADAR_ALERT_DELIVERY_UNCERTAIN_STOP"),
    ("action-inbox.json", "requests", "a" * 32,
     {"request_id": "a" * 32, "status": "approved"},
     "RADAR_ACTION_APPROVAL_NOT_TERMINAL_STOP"),
    ("action-inbox.json", "requests", "a" * 32,
     {"request_id": "a" * 32, "status": "pending"},
     "RADAR_ACTION_APPROVAL_NOT_TERMINAL_STOP"),
    ("action-executions.json", "executions", "a" * 32,
     {"request_id": "a" * 32, "status": "attempting"},
     "RADAR_ACTION_EXECUTION_UNCERTAIN_STOP"),
    ("action-executions.json", "executions", "a" * 32,
     {"request_id": "a" * 32, "status": "ambiguous"},
     "RADAR_ACTION_EXECUTION_UNCERTAIN_STOP"),
    ("action-executions.json", "executions", "a" * 32,
     {"request_id": "a" * 32, "status": "execution_prepared"},
     "RADAR_ACTION_EXECUTION_UNCERTAIN_STOP"),
))
def test_r957_inflight_delivery_and_action_states_refuse_active_restore(
    tmp_path, filename, root, key, row, reason
):
    bundle = build(tmp_path)
    digest = _r957_operational_state(bundle, filename, root, key, row)
    result = verify(bundle, digest)
    assert result.returncode == 42
    assert reason in result.stdout
    assert key not in result.stdout


@pytest.mark.parametrize("filename,root,key,row", (
    ("alert-outbox.json", "events", "alert-1",
     {"event_id": "alert-1", "delivery_state": "delivered",
      "delivery_receipt": "example-receipt", "delivered_at": "2026-10-17T00:00Z"}),
    ("action-inbox.json", "requests", "a" * 32,
     {"request_id": "a" * 32, "status": "consumed",
      "consumption_receipt": "example-receipt", "consumed_at": "2026-10-17T00:00Z"}),
    ("action-executions.json", "executions", "a" * 32,
     {"request_id": "a" * 32, "status": "failed_before_write",
      "error_code": "no_external_attempt", "terminal_at": "2026-10-17T00:00Z"}),
))
def test_r957_terminal_operational_state_keeps_historic_receipts(
    tmp_path, filename, root, key, row
):
    bundle = build(tmp_path)
    digest = _r957_operational_state(bundle, filename, root, key, row)
    result = verify(bundle, digest)
    assert result.returncode == 0, result.stdout
    assert "FLOP_OFFHOST_ARCHIVE_CONTENT_VERIFIED_PASS" in result.stdout


@pytest.mark.parametrize("name", (
    "monitor-config.json", "monitor-heartbeat.json",
    "discord-notifier-state.json", "action-candidates.json",
))
def test_r957_other_operational_source_documents_preserved(name, tmp_path):
    bundle = build(tmp_path)
    root = "candidates" if name == "action-candidates.json" else None
    result = verify(bundle, _r957_operational_state(bundle, name, root, None))
    assert result.returncode == 0, result.stdout



def test_r957_unbound_candidate_never_auto_restaged_after_restore(tmp_path):
    bundle = build(tmp_path)
    path = "state/airdrop-radar/action-candidates.json"
    archive_files(bundle, (path,))
    candidate_id = "b" * 32
    (bundle / path).write_text(json.dumps({
        "schema_version": 1, "candidates": {
            candidate_id: {"candidate_id": candidate_id,
                           "request_id": None, "approval_digest": None}
        }
    }))
    result = verify(bundle, manifest(bundle, extras=(path,)))
    assert result.returncode == 42
    assert "RADAR_ACTION_UNBOUND_CANDIDATE_STOP" in result.stdout


def test_r957_success_requires_consumed_approval_with_same_receipt(tmp_path):
    bundle = build(tmp_path)
    prefix = "state/airdrop-radar/"
    e, a = prefix + "action-executions.json", prefix + "action-inbox.json"
    ids = (e, a)
    archive_files(bundle, ids)
    rid = "c" * 32
    receipt = "synthetic-confirmed-receipt"
    (bundle / e).write_text(json.dumps({
        "schema_version": 1,
        "executions": {rid: {
            "request_id": rid, "status": "succeeded",
            "receipt": receipt, "approval_digest": "d" * 64,
            "terminal_at": "2026-10-17T00:00:00+00:00",
        }},
    }))
    approvals = {
        "schema_version": 1,
        "requests": {rid: {
            "request_id": rid, "status": "consumed",
            "approval_digest": "d" * 64,
            "consumed_at": "2026-10-17T00:00:00+00:00",
            "consumption_receipt": receipt,
        }},
    }
    (bundle / a).write_text(json.dumps(approvals))
    ev, ix = prefix + "events.jsonl", prefix + "event-index.json"
    (bundle / ev).write_bytes(b"")
    (bundle / ix).write_text(json.dumps({
        "schema_version": 1, "ledger_count": 0,
        "ledger_tip_hash": "", "events": {}
    }), encoding="utf-8")
    ids = (e, a, ev, ix)
    valid = verify(bundle, manifest(bundle, extras=ids))
    assert valid.returncode == 0, valid.stdout
    approvals["requests"][rid]["consumption_receipt"] = "wrong-receipt"
    (bundle / a).write_text(json.dumps(approvals))
    invalid = verify(bundle, manifest(bundle, extras=ids))
    assert invalid.returncode == 42
    assert "RADAR_ACTION_SUCCESS_APPROVAL_MISMATCH" in invalid.stdout


def test_r959_radar_extra_index_event_not_in_hashchain_stops(tmp_path):
    bundle = build(tmp_path)
    source_hash = _r954_ledger(bundle)
    _ = source_hash
    idx = "state/airdrop-radar/event-index.json"
    data = json.loads((bundle / idx).read_text())
    data["events"]["f" * 24] = {
        "event_id": "f" * 24,
        "ledger_sequence": 999,
        "ledger_hash": "a" * 64,
    }
    (bundle / idx).write_text(json.dumps(data))
    newpin = manifest(bundle, extras=(
        "state/airdrop-radar/events.jsonl", idx))
    result = verify(bundle, newpin)
    assert result.returncode == 42
    assert "RADAR_INDEX_ORPHAN_EVENT_STOP" in result.stdout
    assert "f" * 24 not in result.stdout


def test_r959_action_row_with_omitted_radar_source_history_stops(tmp_path):
    bundle = build(tmp_path)
    path = "state/airdrop-radar/alert-outbox.json"
    raw = {"schema_version": 1, "events": {
        "e": {"event_id": "e", "delivery_state": "delivered",
              "delivery_receipt": "synthetic", "delivered_at": "2026-10-17T00:00Z"}
    }}
    archive_files(bundle, (path,))
    (bundle / path).write_text(json.dumps(raw), encoding="utf-8")
    result = verify(bundle, manifest(bundle, extras=(path,)))
    assert result.returncode == 42
    assert "RADAR_ACTION_EVIDENCE_MISSING_STOP" in result.stdout


def test_r959_empty_operational_metadata_requires_no_imaginary_ledger(tmp_path):
    bundle = build(tmp_path)
    result = verify(bundle, _r957_operational_state(
        bundle, "discord-notifier-state.json", None, None))
    assert result.returncode == 0, result.stdout
