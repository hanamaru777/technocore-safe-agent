import hashlib
import json

import pytest

from flop_agent import core, tclk_pilot_work


STAGE_ID = "1" * 32
STAGE_DIGEST = "2" * 64
OFFER_ID = "0x" + "3" * 64
FRAME_HASH = "4" * 64
PAYER = "did:key:z6Mk" + "5" * 44
PAYEE = "did:key:z6Mk" + "6" * 44
CONTRACT = "0x" + "7" * 64
DEAL_ROOM = "mb-p-tclk-" + "7" * 16
ACCEPT_HASH = "a" * 64
LOCK_HASH = "8" * 64
PAPER_HASH = "9" * 64


def note(value):
    data = value.encode()
    return {"namespace": "x", "key": "k", "value": value, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def fixture_set(material='{"a":1,"b":[2,3]}', *, spec=None):
    material_note = note(material)
    if spec is None:
        spec = f"Verify JSON material integrity. sha256:{material_note['sha256']} /kv/tclk-mat-en/k"
    full_note = note(spec)
    stage = {
        "stage_id": STAGE_ID,
        "stage_digest": STAGE_DIGEST,
        "offer_id": OFFER_ID,
        "counterpart_did": PAYER,
        "our_did": PAYEE,
        "job_id": "job-1",
        "frame_sha256": FRAME_HASH,
        "full_spec_sha256": full_note["sha256"],
        "material_sha256": material_note["sha256"],
    }
    preview = {"contract_id": CONTRACT, "deal_room": DEAL_ROOM, "accept_sha256": ACCEPT_HASH}
    review = {
        "offer_id": OFFER_ID,
        "job_id": "job-1",
        "frame_sha256": FRAME_HASH,
        "external_url_present": False,
        "full_spec": full_note,
        "material": material_note,
    }
    lock = {
        "status": "lock_verified",
        "stage_id": STAGE_ID,
        "stage_digest": STAGE_DIGEST,
        "offer_id": OFFER_ID,
        "counterpart_did": PAYER,
        "our_did": PAYEE,
        "job_id": "job-1",
        "contract_id": CONTRACT,
        "deal_room": DEAL_ROOM,
        "accept_line_sha256": ACCEPT_HASH,
        "lock_from": PAYER,
        "lock_ref": CONTRACT,
        "lock_seq": 3,
        "lock_timestamp_ms": 2_000_000_000_000,
        "lock_line_sha256": LOCK_HASH,
        "paper_note_namespace": f"tclk-paper-{CONTRACT[2:4]}",
        "paper_note_key": CONTRACT[4:18],
        "paper_note_sha256": PAPER_HASH,
    }
    return stage, preview, review, lock


def bind(monkeypatch, stage, preview, review, lock):
    monkeypatch.setattr(tclk_pilot_work.tclk_pilot, "load_stage", lambda *_a, **_k: stage)
    monkeypatch.setattr(tclk_pilot_work.tclk_pilot_signer, "_load_preview", lambda *_a, **_k: preview)
    monkeypatch.setattr(tclk_pilot_work.tclk_pilot_signer, "_require_preview_binding", lambda *_a, **_k: None)
    monkeypatch.setattr(tclk_pilot_work.tclk_review_evidence, "get", lambda *_a, **_k: review)
    monkeypatch.setattr(tclk_pilot_work.tclk_pilot_lock, "load_evidence", lambda *_a, **_k: lock)


def test_hash_and_json_work_persists_public_safe_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    stage, preview, review, lock = fixture_set()
    bind(monkeypatch, stage, preview, review, lock)

    result = tclk_pilot_work.run_stage(STAGE_ID)
    assert result["action"] == "work_ready"
    evidence = result["evidence"]
    assert evidence["work_family"] == "public_material_sha256_json_v1"
    assert evidence["result"]["sha256_match"] is True
    assert evidence["result"]["json_valid"] is True
    assert evidence["result"]["json_top_level"] == "object"
    assert evidence["result"]["json_items"] == 2
    assert evidence["contract_id"] == CONTRACT
    assert evidence["deal_room"] == DEAL_ROOM
    assert evidence["our_did"] == PAYEE
    assert evidence["accept_sha256"] == ACCEPT_HASH
    assert evidence["lock_line_sha256"] == LOCK_HASH
    assert evidence["paper_note_sha256"] == PAPER_HASH
    assert tclk_pilot_work.evidence_path(STAGE_ID).is_file()
    serialized = json.dumps(evidence)
    assert review["material"]["value"] not in serialized
    assert not any(word in evidence for word in ("secret", "preimage", "private_key", "material_value"))


def test_hash_mismatch_is_durable_failed_work_and_never_ready(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    stage, preview, review, lock = fixture_set(spec=f"Check artifact sha256:{'b' * 64} /kv/tclk-mat-en/k")
    bind(monkeypatch, stage, preview, review, lock)
    result = tclk_pilot_work.run_stage(STAGE_ID)
    assert result["action"] == "work_failed"
    assert result["evidence"]["status"] == "work_failed"
    assert result["evidence"]["result"]["sha256_match"] is False


def test_json_only_validation_is_supported(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    stage, preview, review, lock = fixture_set(spec="Validate this JSON data /kv/tclk-mat-en/k")
    bind(monkeypatch, stage, preview, review, lock)
    result = tclk_pilot_work.run_stage(STAGE_ID)
    assert result["action"] == "work_ready"
    assert result["evidence"]["work_family"] == "public_material_json_v1"
    assert result["evidence"]["result"]["json_valid"] is True


def test_invalid_or_nonfinite_json_is_failed_not_claimed_complete(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    for material in ("not-json", '{"value":NaN}'):
        stage, preview, review, lock = fixture_set(material=material, spec="Verify JSON data /kv/tclk-mat-en/k")
        bind(monkeypatch, stage, preview, review, lock)
        result = tclk_pilot_work.run_stage(STAGE_ID)
        assert result["action"] == "work_failed"
        assert result["evidence"]["result"]["json_valid"] is False
        tclk_pilot_work.evidence_path(STAGE_ID).unlink()


@pytest.mark.parametrize(
    "spec",
    [
        "Summarize this document /kv/tclk-mat-en/k",
        "Compare this artifact /kv/tclk-mat-en/k",
        "Verify JSON from https://example.invalid/data.json /kv/tclk-mat-en/k",
        "Run shell command to verify JSON /kv/tclk-mat-en/k",
        "Verify public repository /kv/tclk-mat-en/k",
    ],
)
def test_unsupported_or_executable_work_fails_closed(monkeypatch, tmp_path, spec):
    monkeypatch.setattr(core, "STATE", tmp_path)
    stage, preview, review, lock = fixture_set(spec=spec)
    if "https://" in spec:
        review["external_url_present"] = True
    bind(monkeypatch, stage, preview, review, lock)
    with pytest.raises(tclk_pilot_work.WorkError, match="work_policy_unsupported"):
        tclk_pilot_work.run_stage(STAGE_ID)
    assert not tclk_pilot_work.evidence_path(STAGE_ID).exists()


def test_changed_review_lock_or_public_accept_binding_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    stage, preview, review, lock = fixture_set()
    review["frame_sha256"] = "f" * 64
    bind(monkeypatch, stage, preview, review, lock)
    with pytest.raises(tclk_pilot_work.WorkError, match="review_binding_changed"):
        tclk_pilot_work.run_stage(STAGE_ID)

    stage, preview, review, lock = fixture_set()
    lock["lock_ref"] = "0x" + "e" * 64
    bind(monkeypatch, stage, preview, review, lock)
    with pytest.raises(tclk_pilot_work.WorkError, match="lock_binding_changed"):
        tclk_pilot_work.run_stage(STAGE_ID)

    stage, preview, review, lock = fixture_set()
    preview["deal_room"] = "mb-p-tclk-" + "e" * 16
    lock["deal_room"] = preview["deal_room"]
    bind(monkeypatch, stage, preview, review, lock)
    with pytest.raises(tclk_pilot_work.WorkError, match="public_accept_binding_invalid"):
        tclk_pilot_work.run_stage(STAGE_ID)

    stage, preview, review, lock = fixture_set()
    lock["accept_line_sha256"] = "e" * 64
    bind(monkeypatch, stage, preview, review, lock)
    with pytest.raises(tclk_pilot_work.WorkError, match="lock_binding_changed"):
        tclk_pilot_work.run_stage(STAGE_ID)


def test_existing_exact_work_is_idempotent_and_tamper_never_replaces(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    stage, preview, review, lock = fixture_set()
    bind(monkeypatch, stage, preview, review, lock)
    first = tclk_pilot_work.run_stage(STAGE_ID)
    second = tclk_pilot_work.run_stage(STAGE_ID)
    assert second["action"] == "already_recorded"
    assert second["evidence"]["work_evidence_sha256"] == first["evidence"]["work_evidence_sha256"]

    path = tclk_pilot_work.evidence_path(STAGE_ID)
    tampered = json.loads(path.read_text())
    tampered["result"]["material_bytes"] += 1
    path.write_text(json.dumps(tampered))
    with pytest.raises(tclk_pilot_work.WorkError, match="work_evidence_invalid"):
        tclk_pilot_work.run_stage(STAGE_ID)


def test_work_slice_never_reads_signer_private_protocol_path(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    stage, preview, review, lock = fixture_set()
    bind(monkeypatch, stage, preview, review, lock)
    monkeypatch.setattr(
        tclk_pilot_work.tclk_pilot,
        "secret_path",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("signer-private path must never be touched")),
    )
    assert tclk_pilot_work.run_stage(STAGE_ID)["action"] == "work_ready"


def test_work_watcher_service_has_no_network_or_signer_boundary():
    service = (core.ROOT / "packaging" / "oracle" / "technocore-safe-agent-tclk-work-watcher.service").read_text("utf-8")
    timer = (core.ROOT / "packaging" / "oracle" / "technocore-safe-agent-tclk-work-watcher.timer").read_text("utf-8")
    source = (core.ROOT / "src" / "flop_agent" / "tclk_pilot_work.py").read_text("utf-8")
    assert "Type=oneshot" in service
    assert "User=technocore" in service
    assert "RestrictAddressFamilies=AF_UNIX" in service
    assert "EnvironmentFile=/etc/technocore-safe-agent/signer.env" not in service
    assert "ReadWritePaths=/var/lib/technocore-safe-agent/autopilot" in service
    assert "-m flop_agent.tclk_pilot_work" in service
    assert "subprocess" not in source
    assert "httpx" not in source
    assert "requests" not in source
    assert "core.read_note" not in source
    assert "secret_path(" not in source
    assert "OnUnitActiveSec=30" in timer
