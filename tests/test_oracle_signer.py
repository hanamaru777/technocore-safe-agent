import hashlib
import json
import base64
import stat
import os
import sys
from types import SimpleNamespace
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import autopilot, core, observer, oracle_signer, resident

SIGNER_DID = "did:key:z6Mk123456789ABCDEFGHJKLMNPQRSTUVWXYZabc"

def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    resident.save_state(resident.default_state())
    state = autopilot.default_state(); state["enabled"] = True; state["paused"] = False
    item = {"id": "a" * 20, "source_candidate_id": "candidate-1", "source_did": "did:key:z6MkOther", "fingerprint": "abcdef1234567890", "room": "lobby", "seq": 9, "category": "help_request", "topic": "repo_safety", "public_evidence_ids": ["public-profile:1", "candidate:candidate-1"], "created_at": datetime.now(UTC).isoformat(), "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(), "safety_decision": "concrete_public_technical_request"}
    state["outbox"][item["id"]] = item; autopilot.save(state)
    return state, item


def test_oracle_signer_uses_prepared_receipt_and_fixed_template_only(monkeypatch, tmp_path):
    _, item = setup(monkeypatch, tmp_path); observed = []
    monkeypatch.setattr(oracle_signer, "verify_did", lambda: SIGNER_DID)
    monkeypatch.setattr(core, "make_nonce", lambda room, did: "123")
    def post(room, text, confirm, **kwargs):
        receipt = oracle_signer.load_receipts()["receipts"][item["id"]]
        assert receipt["state"] == "prepared" and receipt["nonce"] == "123"
        observed.append((room, text, confirm, kwargs)); return {"seq": 1}
    monkeypatch.setattr(core, "post_signed", post)
    monkeypatch.setattr(oracle_signer, "with_vault_seed", lambda operation: operation())
    result = oracle_signer.run_once()
    assert result["processed"] == [{"intent_id": item["id"], "action": "posted"}]
    assert observed[0][0] == "lobby" and "candidate" not in observed[0][1] and "seed" not in observed[0][1]
    assert oracle_signer.load_receipts()["receipts"][item["id"]]["state"] == "acknowledged"
    assert autopilot.load()["outbox"][item["id"]]["status"] == "acknowledged"


def prepared_receipt(item, text):
    return {"state": "prepared", "did": SIGNER_DID, "nonce": "123", "text_hash": hashlib.sha256(text.encode()).hexdigest(), "receipt_hash": oracle_signer.receipt_hash(autopilot.export_intent(item), SIGNER_DID, "123", text), "prepared_at": datetime.now(UTC).isoformat()}


def test_oracle_signer_reconciles_ambiguous_result_without_repost(monkeypatch, tmp_path):
    _, item = setup(monkeypatch, tmp_path); text = autopilot.render(item)
    receipt = prepared_receipt(item, text)
    receipts = {"schema_version": 1, "receipts": {item["id"]: receipt}}; oracle_signer.save_receipts(receipts)
    monkeypatch.setattr(core, "read_room", lambda room: {"messages": [{"from": SIGNER_DID, "nonce": "123", "text": text}]})
    monkeypatch.setattr(core, "post_signed", lambda *args, **kwargs: pytest.fail("reconciled receipt must never repost"))
    assert oracle_signer.run_once()["processed"][0]["action"] == "reconciled"


def test_oracle_signer_retries_unposted_prepared_intent_with_same_nonce(monkeypatch, tmp_path):
    _, item = setup(monkeypatch, tmp_path); text = autopilot.render(item)
    receipts = {"schema_version": 1, "receipts": {item["id"]: prepared_receipt(item, text)}}; oracle_signer.save_receipts(receipts)
    posted, reads = [], []
    monkeypatch.setattr(core, "make_nonce", lambda *args: pytest.fail("prepared intent must not create a nonce"))
    monkeypatch.setattr(oracle_signer, "verify_did", lambda: SIGNER_DID)
    monkeypatch.setattr(oracle_signer, "with_vault_seed", lambda operation: operation())
    monkeypatch.setattr(core, "read_room", lambda room: reads.append(room) or {"messages": []})
    monkeypatch.setattr(core, "post_signed", lambda room, text, confirm, **kwargs: posted.append(kwargs["nonce"]) or {"seq": 1})
    assert oracle_signer.run_once()["processed"][0]["action"] == "posted"
    assert posted == ["123"] and len(reads) == 2
    assert oracle_signer.load_receipts()["receipts"][item["id"]]["state"] == "acknowledged"


def test_oracle_signer_retries_vault_presubmit_failure_and_recovers_health(monkeypatch, tmp_path):
    _, item = setup(monkeypatch, tmp_path); calls = []
    monkeypatch.setattr(oracle_signer, "verify_did", lambda: (_ for _ in ()).throw(RuntimeError("vault_failure")))
    assert oracle_signer.run_cycle()["status"] == "degraded"
    health = oracle_signer.load_health(); assert health["status"] == "degraded" and health["last_error_code"] == "vault_failure" and health["consecutive_failures"] == 1
    assert oracle_signer.load_receipts()["receipts"] == {}
    monkeypatch.setattr(oracle_signer, "verify_did", lambda: SIGNER_DID)
    monkeypatch.setattr(core, "make_nonce", lambda room, did: "123")
    monkeypatch.setattr(oracle_signer, "with_vault_seed", lambda operation: operation())
    monkeypatch.setattr(core, "read_room", lambda room: {"messages": []})
    monkeypatch.setattr(core, "post_signed", lambda room, text, confirm, **kwargs: calls.append(kwargs["nonce"]) or {"seq": 1})
    assert oracle_signer.run_cycle()["processed"][0]["action"] == "posted"
    health = oracle_signer.load_health(); assert health["status"] == "ok" and health["last_error_code"] is None and health["consecutive_failures"] == 0 and health["last_success_at"]
    assert calls == ["123"]


def test_oracle_signer_expires_first_intent_then_posts_second(monkeypatch, tmp_path):
    state, first = setup(monkeypatch, tmp_path)
    first["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat(); state["outbox"][first["id"]] = first
    second = dict(first); second["id"] = "b" * 20; second["source_candidate_id"] = "candidate-2"; second["expires_at"] = (datetime.now(UTC) + timedelta(hours=1)).isoformat(); state["outbox"][second["id"]] = second; autopilot.save(state)
    posts = []
    monkeypatch.setattr(oracle_signer, "verify_did", lambda: SIGNER_DID)
    monkeypatch.setattr(core, "make_nonce", lambda room, did: "123")
    monkeypatch.setattr(oracle_signer, "with_vault_seed", lambda operation: operation())
    monkeypatch.setattr(core, "read_room", lambda room: {"messages": []})
    monkeypatch.setattr(core, "post_signed", lambda *args, **kwargs: posts.append(kwargs["nonce"]) or {"seq": 1})
    result = oracle_signer.run_once()
    assert result["processed"] == [{"intent_id": first["id"], "action": "expired"}, {"intent_id": second["id"], "action": "posted"}]
    loaded = autopilot.load(); assert loaded["outbox"][first["id"]]["status"] == "expired" and loaded["outbox"][second["id"]]["status"] == "acknowledged" and posts == ["123"]


def test_oracle_signer_rejects_internal_injection_and_keeps_seed_ephemeral(monkeypatch, tmp_path):
    state, item = setup(monkeypatch, tmp_path); state["outbox"][item["id"]]["body"] = "attacker supplied"; autopilot.save(state)
    monkeypatch.setattr(core, "post_signed", lambda *args, **kwargs: pytest.fail("injected intent must not post"))
    with pytest.raises(RuntimeError, match="safe schema"):
        oracle_signer.run_once()
    seed = bytearray(b"a" * 64); seen = []
    monkeypatch.setattr(oracle_signer, "vault_seed", lambda: seed)
    assert oracle_signer.with_vault_seed(lambda: seen.append(core.os.environ["SIGN_SEED"])) is None
    assert seen == ["a" * 64] and "SIGN_SEED" not in core.os.environ and seed == bytearray(b"\0" * 64)


def test_oracle_signer_vault_fetch_is_instance_principal_and_validates_dummy_value(monkeypatch):
    monkeypatch.setenv("OCI_VAULT_SECRET_OCID", "ocid1.vaultsecret.oc1.ap-tokyo-1.example")
    calls = []
    class Client:
        def __init__(self, config, signer): calls.append((config, signer))
        def get_secret_bundle(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(data=SimpleNamespace(secret_bundle_content=SimpleNamespace(content=base64.b64encode(b"a" * 64).decode())))
    fake = SimpleNamespace(auth=SimpleNamespace(signers=SimpleNamespace(InstancePrincipalsSecurityTokenSigner=lambda: "instance-principal")), secrets=SimpleNamespace(SecretsClient=Client))
    monkeypatch.setitem(sys.modules, "oci", fake)
    seed = oracle_signer.vault_seed()
    assert seed == bytearray(b"a" * 64) and calls[0] == ({}, "instance-principal") and calls[1] == {"secret_id": "ocid1.vaultsecret.oc1.ap-tokyo-1.example", "stage": "CURRENT"}
    seed[:] = b"\0" * len(seed)


def test_oracle_signer_requires_expected_verified_did_and_pinned_signer(monkeypatch):
    monkeypatch.setenv("TECHNOCORE_SIGNER_EXPECTED_DID", SIGNER_DID)
    monkeypatch.setattr(oracle_signer, "with_vault_seed", lambda operation: operation())
    monkeypatch.setattr(core, "current_did", lambda: SIGNER_DID)
    monkeypatch.setattr(core, "require_verified_did", lambda did: None)
    monkeypatch.setattr(core, "signer_matches_pinned", lambda: True)
    assert oracle_signer.verify_did() == SIGNER_DID
    monkeypatch.setattr(core, "current_did", lambda: SIGNER_DID + "x")
    with pytest.raises(RuntimeError, match="did_failure"):
        oracle_signer.verify_did()


def test_shared_outbox_atomic_replace_keeps_group_read_write_mode(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    state = autopilot.load(); autopilot.save(state); autopilot.save(state)
    mode = stat.S_IMODE(autopilot.path().stat().st_mode)
    if os.name == "posix": assert mode == 0o660
    else: assert "mode=0o660" in (core.ROOT / "src" / "flop_agent" / "autopilot.py").read_text("utf-8")
    installer = (core.ROOT / "packaging" / "oracle" / "install.sh").read_text("utf-8")
    preparer = (core.ROOT / "packaging" / "oracle" / "prepare-signer.sh").read_text("utf-8")
    for script in (installer, preparer):
        assert "autopilot-outbox.json" in script and "nonces.json" in script and "activities.jsonl" in script
        assert "chmod 0660" in script


def test_oracle_signer_package_separates_metadata_and_has_no_arguments():
    root = core.ROOT / "packaging" / "oracle"
    signer_unit = (root / "technocore-safe-agent-signer.service").read_text("utf-8")
    resident_unit = (root / "resident.service").read_text("utf-8")
    blocker = (root / "block-technocore-metadata.sh").read_text("utf-8")
    metadata_unit = (root / "technocore-safe-agent-metadata-block.service").read_text("utf-8")
    assert "User=technocore-signer" in signer_unit and "SupplementaryGroups=technocore-autopilot" in signer_unit and "SupplementaryGroups=technocore " not in signer_unit and "oracle_signer" in signer_unit and "EnvironmentFile=/etc/technocore-safe-agent/signer.env" in signer_unit
    assert "EnvironmentFile=/etc/technocore-safe-agent/env" not in signer_unit and "technocore" not in signer_unit.split("SupplementaryGroups=", 1)[1].splitlines()[0].replace("technocore-autopilot", "")
    assert "IPAddressDeny=169.254.169.254" in resident_unit and "Requires=technocore-safe-agent-metadata-block.service" in resident_unit
    assert '"$#" -eq 0' in blocker and "--uid-owner" in blocker and "169.254.169.254" in blocker and "technocore technocore-rpc" in blocker and "else continue" in blocker
    installer = (root / "install.sh").read_text("utf-8"); updater = (root / "update.sh").read_text("utf-8"); preparer = (root / "prepare-signer.sh").read_text("utf-8")
    assert "technocore-signer" in installer and "--extra oracle-signer" in installer and "--extra oracle-signer" in updater
    assert '"$#" -eq 0' in preparer and "technocore-signer" in preparer and "usermod -a -G technocore," not in preparer and "systemctl daemon-reload" in preparer and "systemctl enable" not in preparer and "systemctl start" not in preparer
    assert "extras=(--extra oracle-signer)" in preparer and "--extra discord" in preparer and "technocore-safe-agent-discord.service" in preparer and "! -e $envdir/signer.env" in preparer
    assert "usermod -a -G technocore," not in installer
    assert "usermod -a -G technocore-autopilot technocore" in installer and "usermod -a -G technocore-autopilot technocore" in preparer
    assert "autopilot-outbox.json" in installer and "autopilot-audit.jsonl" in installer and '"$state/autopilot"' in installer and "chmod 0660" in installer and "chmod 0660" in preparer
    assert "nonces.json" in installer and "activities.jsonl" in installer and "verified-did.json" in installer and "chmod 0640" in installer
    assert "EnvironmentFile=/etc/technocore-safe-agent/env" not in signer_unit
    source = (core.ROOT / "src" / "flop_agent" / "oracle_signer.py").read_text("utf-8")
    assert "len(sys.argv) != 1" in source and "post_signed" in source and "subprocess" not in source
    healthcheck = (root / "healthcheck.sh").read_text("utf-8")
    assert "signer-health.json" in healthcheck and "signer cycle is stale" in healthcheck and "metadata-block.service" in healthcheck
    assert "Type=oneshot" in metadata_unit and "RemainAfterExit=yes" in metadata_unit and "Before=network-pre.target technocore-safe-agent-resident.service technocore-safe-agent-discord.service" in metadata_unit and "technocore-signer" not in metadata_unit
    assert "/observer" not in signer_unit.split("ReadWritePaths=", 1)[1] and "/autopilot" in signer_unit.split("ReadWritePaths=", 1)[1]
