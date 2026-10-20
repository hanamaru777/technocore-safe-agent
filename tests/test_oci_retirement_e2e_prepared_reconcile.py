"""Offline-only read-only audit for Flop OCI controlled E2E signer reconciliation.

Does not execute the OCI utility against a host or inspect any private files.
"""
import hashlib
import importlib.util
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "packaging/oracle/retirement-e2e-prepared-reconcile.py"

def load():
    spec = importlib.util.spec_from_file_location("flop_e2e_signer_reconcile", SRC)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def fixture():
    did = "did:key:z" + "a" * 52
    receipt = "b" * 64
    def key(version):
        return hashlib.sha256(("controlled-e2e-" + version).encode()).hexdigest()[:20]
    r = {
        "ack-id": {"state": "acknowledged", "did": did, "receipt_hash": receipt, "nonce": "21"},
        key("v1"): {"state": "prepared", "did": did, "nonce": "22", "last_error_code": "submission_unknown", "attempts": 1},
        key("v2"): {"state": "prepared", "did": did, "nonce": "23", "last_error_code": None, "attempts": 0},
    }
    ob = {
        "ack-id": {"status": "acknowledged", "receipt_hash": receipt, "room": "lobby"},
        key("v1"): {"status": "quarantined", "room": "lobby", "category": "controlled_e2e",
                    "topic": "prompt_injection_safety", "source_candidate_id": "controlled-e2e-v1",
                    "quarantine_reason": "submission_unknown"},
        key("v2"): {"status": "quarantined", "room": "lobby", "category": "controlled_e2e",
                    "topic": "prompt_injection_safety", "source_candidate_id": "controlled-e2e-v2",
                    "quarantine_reason": "legacy_unhandled_http_ambiguity"},
    }
    return (
        {"schema_version": 1, "receipts": r},
        {"schema_version": 1, "enabled": True, "paused": False,
         "outbox": ob, "receipts": {"ack-id": {"receipt_hash": receipt}}},
        {did + "|lobby": 23, "nonce-key": "not-for-output"}, {"did": did}
    )

def test_all_prepared_are_exact_quarantined_controlled_e2e_without_printing_sensitive_data():
    m = load()
    data = fixture()
    val = m.pairing(*data)
    assert val["prepared_total"] == val["quarantined_total"] == 2
    assert val["recognized_quarantined_e2e"] == 2
    assert val["unreconciled_prepared"] == val["unreconciled_quarantined"] == 0
    assert val["ack_ids_consistent"] is True
    assert val["nonce_binding_consistent"] is True
    assert val["autopilot_enabled"] is True and val["autopilot_paused"] is False
    for sensitive in ("not-for-output", data[3]["did"], "nonce-key", "ack-id"):
        assert sensitive not in str(val)

def test_unrelated_prepared_is_not_marked_safe():
    m = load()
    data = list(fixture())
    data[0]["receipts"]["unexpected"] = {
        "state": "prepared", "did": data[3]["did"], "attempts": 0
    }
    val = m.pairing(*data)
    assert val["unreconciled_prepared"] == 1

def test_quarantined_with_unexpected_receipt_error_is_unreconciled():
    m = load()
    data = list(fixture())
    version = hashlib.sha256(b"controlled-e2e-v1").hexdigest()[:20]
    data[0]["receipts"][version]["last_error_code"] = None
    val = m.pairing(*data)
    assert val["recognized_quarantined_e2e"] == 1
    assert val["unreconciled_prepared"] == 1
    assert val["unreconciled_quarantined"] == 1

def test_quarantined_wrong_intent_metadata_is_not_assumed_valid():
    m = load()
    data = list(fixture())
    version = hashlib.sha256(b"controlled-e2e-v2").hexdigest()[:20]
    data[1]["outbox"][version]["category"] = "not-test"
    val = m.pairing(*data)
    assert val["unreconciled_quarantined"] == 1

def test_acknowledged_ids_and_hashes_must_match():
    m = load()
    data = list(fixture())
    assert m.pairing(*data)["ack_ids_consistent"]
    data[1]["receipts"]["ack-id"]["receipt_hash"] = "c" * 64
    assert not m.pairing(*data)["ack_ids_consistent"]
    data[1]["receipts"]["ack-id"]["receipt_hash"] = "b" * 64
    data[1]["outbox"]["ack-id"]["receipt_hash"] = "c" * 64
    assert not m.pairing(*data)["ack_ids_consistent"]

def test_missing_acknowledged_hash_never_passes_even_when_ids_equal():
    # Previously three missing strings compared equal and reported a false PASS.
    for record in ("signer", "outbox", "acknowledged"):
        m = load()
        data = list(fixture())
        if record == "signer":
            target = data[0]["receipts"]["ack-id"]
        elif record == "outbox":
            target = data[1]["outbox"]["ack-id"]
        else:
            target = data[1]["receipts"]["ack-id"]
        del target["receipt_hash"]
        assert m.pairing(*data)["ack_ids_consistent"] is False

    m = load()
    data = list(fixture())
    del data[0]["receipts"]["ack-id"]["receipt_hash"]
    del data[1]["outbox"]["ack-id"]["receipt_hash"]
    del data[1]["receipts"]["ack-id"]["receipt_hash"]
    assert m.pairing(*data)["ack_ids_consistent"] is False


def test_blank_non_hex_or_non_string_receipt_hash_rejected():
    m = load()
    for value in ("", "not-hex", "g" * 64, "A" * 64, None, 123):
        data = list(fixture())
        for record in (data[0]["receipts"]["ack-id"],
                       data[1]["outbox"]["ack-id"],
                       data[1]["receipts"]["ack-id"]):
            record["receipt_hash"] = value
        assert m.pairing(*data)["ack_ids_consistent"] is False


def test_nonce_binding_detects_missing_watermark_outbox_or_receipt_nonce():
    m = load()
    cases = (
        lambda d: d[2].clear(),
        lambda d: d[0]["receipts"]["ack-id"].pop("nonce"),
        lambda d: d[1]["outbox"]["ack-id"].pop("room"),
        lambda d: d[1]["outbox"].pop("ack-id"),
    )
    for mutate in cases:
        d = list(fixture())
        mutate(d)
        assert m.pairing(*d)["nonce_binding_consistent"] is False


def test_nonce_binding_rejects_reused_future_malformed_and_wrong_room_nonce():
    m = load()
    for change in ("duplicate", "future", "zero", "unicode", "wrong_room",
                   "non_integer_watermark", "bool_watermark"):
        d = list(fixture())
        if change == "duplicate":
            d[0]["receipts"]["ack-id"]["nonce"] = "22"
        elif change == "future":
            d[0]["receipts"]["ack-id"]["nonce"] = "24"
        elif change == "zero":
            d[0]["receipts"]["ack-id"]["nonce"] = "0"
        elif change == "unicode":
            d[0]["receipts"]["ack-id"]["nonce"] = "２１"
        elif change == "wrong_room":
            d[1]["outbox"]["ack-id"]["room"] = "other"
        elif change == "non_integer_watermark":
            d[2][d[3]["did"] + "|lobby"] = "23"
        else:
            d[2][d[3]["did"] + "|lobby"] = True
        assert m.pairing(*d)["nonce_binding_consistent"] is False


def test_nonce_binding_per_room_high_watermarks_and_no_remote_proof_claim():
    m = load()
    d = list(fixture())
    d[1]["outbox"]["ack-id"]["room"] = "other"
    d[2][d[3]["did"] + "|other"] = 21
    assert m.pairing(*d)["nonce_binding_consistent"] is True
    assert "external" not in str(m.pairing(*d))
    assert m.nonce_binding({"receipts": {}}, d[1], d[2], d[3]["did"]) is False


def test_live_scope_no_service_mutation_no_large_file_reads():
    s = SRC.read_text()
    compile(s, str(SRC), "exec")
    m = load()
    assert len(m.INPUTS) == 4
    assert m.MAX_JSON <= 1024 * 1024
    assert "FLOP_OCI_SIGNER_CUTOVER_NOT_AUTHORIZED_WHILE_LIVE" in s
    assert "FLOP_OCI_E2E_ONLY_AGGREGATES_PRINTED_PASS" in s
    assert "FLOP_OCI_E2E_READ_ONLY_RECONCILIATION_PASS" in s
    for unsafe in ("sqlite3.connect", "import httpx", "import requests",
                   "systemctl start", "systemctl stop", "systemctl disable",
                   "subprocess.Popen", "os.walk", "rglob(", "unlink(",
                   "write_text(", "write_bytes(", "SIGN_SEED", "OCI_VAULT_SECRET_OCID",
                   "/etc/technocore-safe-agent/signer.env"):
        assert unsafe not in s
