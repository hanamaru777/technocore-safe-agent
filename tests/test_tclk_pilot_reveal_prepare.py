import hashlib
import json
import os
import subprocess

import pytest

from flop_agent import core, tclk_pilot_reveal


STAGE_ID = "1" * 32
STAGE_DIGEST = "2" * 64
OFFER_ID = "0x" + "3" * 64
PAYER = "did:key:z6Mk" + "4" * 44
PAYEE = "did:key:z6Mk" + "5" * 44
CONTRACT = "0x" + "6" * 64
DEAL_ROOM = "mb-p-tclk-" + "6" * 16
ACCEPT_LINE = 'tclk1 {"type":"accept"}'
ACCEPT_HASH = hashlib.sha256(ACCEPT_LINE.encode()).hexdigest()
LOCK_HASH = "7" * 64
PAPER_HASH = "8" * 64
WORK_HASH = "9" * 64
FULL_HASH = "a" * 64
MATERIAL_HASH = "b" * 64


def fixtures():
    stage = {
        "stage_id": STAGE_ID,
        "stage_digest": STAGE_DIGEST,
        "offer_id": OFFER_ID,
        "offer_line": 'tclk1 {"type":"offer"}',
        "our_did": PAYEE,
        "counterpart_did": PAYER,
        "job_id": "job-1",
        "full_spec_sha256": FULL_HASH,
        "material_sha256": MATERIAL_HASH,
        "expires_ms": 2_000_000_500_000,
    }
    accept = {
        "stage_id": STAGE_ID,
        "stage_digest": STAGE_DIGEST,
        "offer_id": OFFER_ID,
        "accept_line": ACCEPT_LINE,
        "accept_sha256": ACCEPT_HASH,
        "contract_id": CONTRACT,
        "deal_room": DEAL_ROOM,
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
        "lock_line_sha256": LOCK_HASH,
        "paper_note_sha256": PAPER_HASH,
    }
    work = {
        "status": "work_ready",
        "stage_id": STAGE_ID,
        "stage_digest": STAGE_DIGEST,
        "offer_id": OFFER_ID,
        "counterpart_did": PAYER,
        "our_did": PAYEE,
        "job_id": "job-1",
        "contract_id": CONTRACT,
        "deal_room": DEAL_ROOM,
        "accept_sha256": ACCEPT_HASH,
        "lock_line_sha256": LOCK_HASH,
        "lock_ref": CONTRACT,
        "paper_note_sha256": PAPER_HASH,
        "full_spec_sha256": FULL_HASH,
        "material_sha256": MATERIAL_HASH,
        "work_evidence_sha256": WORK_HASH,
    }
    return stage, accept, lock, work


def bind(monkeypatch, stage, accept, lock, work):
    monkeypatch.setattr(tclk_pilot_reveal.tclk_pilot, "load_stage", lambda *_a, **_k: stage)
    monkeypatch.setattr(tclk_pilot_reveal.tclk_pilot_signer, "_load_preview", lambda *_a, **_k: accept)
    monkeypatch.setattr(tclk_pilot_reveal.tclk_pilot_signer, "_require_preview_binding", lambda *_a, **_k: None)
    monkeypatch.setattr(tclk_pilot_reveal.tclk_pilot_signer, "_expected_did", lambda: PAYEE)
    monkeypatch.setattr(tclk_pilot_reveal.tclk_pilot_lock, "load_evidence", lambda *_a, **_k: lock)
    monkeypatch.setattr(tclk_pilot_reveal.tclk_pilot_work, "load_evidence", lambda *_a, **_k: work)
    monkeypatch.setattr(
        tclk_pilot_reveal.tclk_pilot_lock,
        "inspect_stage",
        lambda *_a, **_k: {"action": "already_verified", "evidence": lock},
    )


def bridge_result(request, *, claim_by=2_000_000_400_000):
    return {
        "stage_id": request["stage_id"],
        "stage_digest": request["stage_digest"],
        "offer_id": request["offer_id"],
        "counterpart_did": request["counterpart_did"],
        "our_did": request["our_did"],
        "job_id": request["job_id"],
        "contract_id": request["contract_id"],
        "deal_room": request["deal_room"],
        "accept_sha256": request["accept_sha256"],
        "lock_line_sha256": request["lock_line_sha256"],
        "lock_ref": request["lock_ref"],
        "paper_note_sha256": request["paper_note_sha256"],
        "work_evidence_sha256": request["work_evidence_sha256"],
        "expires_ms": request["expires_ms"],
        "claim_by_ms": claim_by,
        "refund_after_ms": claim_by + 300_000,
        "reveal_sha256": "c" * 64,
    }


def test_prepare_persists_hash_only_public_preview(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    stage, accept, lock, work = fixtures()
    bind(monkeypatch, stage, accept, lock, work)

    def fake_bridge(request):
        private = tclk_pilot_reveal.private_reveal_path(STAGE_ID)
        private.parent.mkdir(parents=True, mode=0o700)
        private.write_text('{"reveal_line":"tclk1 private-secret-material"}\n')
        os.chmod(private, 0o600)
        return bridge_result(request)

    monkeypatch.setattr(tclk_pilot_reveal, "_run_bridge", fake_bridge)
    result = tclk_pilot_reveal.prepare_stage(STAGE_ID, now_ms=2_000_000_000_000)
    assert result["action"] == "prepared"
    preview = result["preview"]
    assert preview["reveal_sha256"] == "c" * 64
    assert preview["work_evidence_sha256"] == WORK_HASH
    assert preview["counterpart_did"] == PAYER
    assert preview["our_did"] == PAYEE
    assert preview["job_id"] == "job-1"
    assert not any(key in preview for key in ("secret", "preimage", "reveal_line", "private_key"))
    public_bytes = tclk_pilot_reveal.preview_path(STAGE_ID).read_text()
    assert "private-secret-material" not in public_bytes
    assert "reveal_line" not in public_bytes
    public_result = tclk_pilot_reveal.public_result(result)
    assert "reveal_line" not in public_result and "secret" not in public_result
    assert (tclk_pilot_reveal.private_reveal_path(STAGE_ID).stat().st_mode & 0o777) == 0o600


def test_changed_work_or_live_lock_fails_before_private_prepare(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    stage, accept, lock, work = fixtures()
    work["status"] = "work_failed"
    bind(monkeypatch, stage, accept, lock, work)
    monkeypatch.setattr(tclk_pilot_reveal, "_run_bridge", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("bridge must not run")))
    with pytest.raises(tclk_pilot_reveal.RevealPrepareError, match="work_binding_invalid"):
        tclk_pilot_reveal.prepare_stage(STAGE_ID, now_ms=2_000_000_000_000)

    stage, accept, lock, work = fixtures()
    bind(monkeypatch, stage, accept, lock, work)
    bad = dict(lock)
    bad["paper_note_sha256"] = "d" * 64
    monkeypatch.setattr(
        tclk_pilot_reveal.tclk_pilot_lock,
        "inspect_stage",
        lambda *_a, **_k: {"action": "already_verified", "evidence": bad},
    )
    with pytest.raises(tclk_pilot_reveal.RevealPrepareError, match="live_lock_binding_changed"):
        tclk_pilot_reveal.prepare_stage(STAGE_ID, now_ms=2_000_000_000_000)


def test_prepare_window_is_fail_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    stage, accept, lock, work = fixtures()
    bind(monkeypatch, stage, accept, lock, work)

    def fake_bridge(request):
        private = tclk_pilot_reveal.private_reveal_path(STAGE_ID)
        private.parent.mkdir(parents=True, mode=0o700)
        private.write_text("{}\n")
        os.chmod(private, 0o600)
        return bridge_result(request, claim_by=2_000_000_100_000)

    monkeypatch.setattr(tclk_pilot_reveal, "_run_bridge", fake_bridge)
    with pytest.raises(tclk_pilot_reveal.RevealPrepareError, match="reveal_prepare_window_elapsed"):
        tclk_pilot_reveal.prepare_stage(STAGE_ID, now_ms=2_000_000_000_000)
    assert not tclk_pilot_reveal.preview_path(STAGE_ID).exists()


def test_existing_public_preview_requires_private_state(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    stage, accept, lock, work = fixtures()
    bind(monkeypatch, stage, accept, lock, work)
    request = tclk_pilot_reveal._require_bindings(stage, accept, lock, work)
    preview = {
        "schema_version": 1,
        "status": "prepared",
        "prepared_at": "2033-05-18T03:33:20+00:00",
        **bridge_result(request),
    }
    tclk_pilot_reveal.preview_dir().mkdir(parents=True)
    tclk_pilot_reveal.preview_path(STAGE_ID).write_text(json.dumps(preview))
    with pytest.raises(tclk_pilot_reveal.RevealPrepareError, match="private_reveal_missing"):
        tclk_pilot_reveal.prepare_stage(STAGE_ID, now_ms=2_000_000_000_000)


def test_wrong_expected_did_is_normalized_fail_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    stage, accept, lock, work = fixtures()
    bind(monkeypatch, stage, accept, lock, work)
    monkeypatch.setattr(tclk_pilot_reveal.tclk_pilot_signer, "_expected_did", lambda: PAYER)
    with pytest.raises(tclk_pilot_reveal.RevealPrepareError, match="stage_did_mismatch"):
        tclk_pilot_reveal.prepare_stage(STAGE_ID, now_ms=2_000_000_000_000)


def test_pinned_bridge_rejects_wrong_private_preimage_and_never_prints_reveal(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    source = r"""
import { makeOffer, makeAccept, encodeFrame, dealRoom, hashLockFromPreimage } from '@flop-labs/tclk';
let raw = ''; for await (const chunk of process.stdin) raw += chunk;
const input = JSON.parse(raw);
const preimage = '0x' + '11'.repeat(32);
const now = Date.now();
const offer = makeOffer({
  from: input.payer, role: 'payer', amount: '1', asset: 'PAPER', lock: 'hash', rails: ['paper'],
  claimByMs: now + 600000, refundAfterMs: now + 900000, expiresMs: now + 300000,
  job: {proto: 'a2a', id: 'job-reveal-1'}, nonce: 'abcdef12',
});
const accept = makeAccept(offer, {from: input.payee, statement: hashLockFromPreimage(preimage).hash, nonce: '12345678'});
process.stdout.write(JSON.stringify({offer: encodeFrame(offer), offerId: offer.id, accept: encodeFrame(accept), contract: accept.contract, room: dealRoom(accept.contract), preimage, expires: offer.expiresMs}));
"""
    built = subprocess.run(
        ["node", "--input-type=module", "--eval", source],
        input=json.dumps({"payer": PAYER, "payee": PAYEE}),
        text=True,
        capture_output=True,
        check=True,
    )
    values = json.loads(built.stdout)
    accept_hash = hashlib.sha256(values["accept"].encode()).hexdigest()
    private = core.STATE / "signer" / "tclk-pilot-secrets" / f"{STAGE_ID}.json"
    private.parent.mkdir(parents=True, mode=0o700)
    stored = {
        "schema_version": 1,
        "stage_id": STAGE_ID,
        "offer_id": values["offerId"],
        "contract_id": values["contract"],
        "accept_nonce": "12345678",
        "preimage": values["preimage"],
    }
    private.write_text(json.dumps(stored))
    os.chmod(private, 0o600)

    request = {
        "stage_id": STAGE_ID,
        "stage_digest": STAGE_DIGEST,
        "offer_id": values["offerId"],
        "offer_line": values["offer"],
        "counterpart_did": PAYER,
        "our_did": PAYEE,
        "job_id": "job-reveal-1",
        "accept_line": values["accept"],
        "accept_sha256": accept_hash,
        "contract_id": values["contract"],
        "deal_room": values["room"],
        "lock_line_sha256": LOCK_HASH,
        "lock_ref": values["contract"],
        "paper_note_sha256": PAPER_HASH,
        "work_evidence_sha256": WORK_HASH,
        "expires_ms": values["expires"],
    }
    output = tclk_pilot_reveal._run_bridge(request)
    assert output["reveal_sha256"]
    assert output["counterpart_did"] == PAYER
    assert output["job_id"] == "job-reveal-1"
    assert not any(key in output for key in ("secret", "preimage", "reveal_line"))
    reveal_private = json.loads(tclk_pilot_reveal.private_reveal_path(STAGE_ID).read_text())
    assert values["preimage"] in reveal_private["reveal_line"]
    assert output["reveal_sha256"] == hashlib.sha256(reveal_private["reveal_line"].encode()).hexdigest()

    tclk_pilot_reveal.private_reveal_path(STAGE_ID).unlink()
    stored["preimage"] = "0x" + "22" * 32
    private.write_text(json.dumps(stored))
    os.chmod(private, 0o600)
    with pytest.raises(tclk_pilot_reveal.RevealPrepareError, match="reveal_bridge_failed"):
        tclk_pilot_reveal._run_bridge(request)

    stored["preimage"] = values["preimage"]
    private.write_text(json.dumps(stored))
    os.chmod(private, 0o600)
    wrong_job = dict(request)
    wrong_job["job_id"] = "job-wrong"
    with pytest.raises(tclk_pilot_reveal.RevealPrepareError, match="reveal_bridge_failed"):
        tclk_pilot_reveal._run_bridge(wrong_job)


def test_reveal_service_has_no_vault_and_metadata_is_denied():
    service = (core.ROOT / "packaging" / "oracle" / "technocore-safe-agent-tclk-reveal-preparer.service").read_text("utf-8")
    timer = (core.ROOT / "packaging" / "oracle" / "technocore-safe-agent-tclk-reveal-preparer.timer").read_text("utf-8")
    assert "Type=oneshot" in service
    assert "User=technocore-signer" in service
    assert "EnvironmentFile=/etc/technocore-safe-agent/tclk-prepare.env" in service
    assert "EnvironmentFile=/etc/technocore-safe-agent/signer.env" not in service
    assert "IPAddressDeny=169.254.169.254" in service
    assert "-m flop_agent.tclk_pilot_reveal" in service
    assert "ReadWritePaths=/var/lib/technocore-safe-agent/autopilot /var/lib/technocore-safe-agent/signer" in service
    assert "OnUnitActiveSec=30" in timer
