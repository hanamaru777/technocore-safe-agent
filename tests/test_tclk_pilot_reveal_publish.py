import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from flop_agent import tclk_pilot_reveal, tclk_pilot_reveal_approval as approval
from flop_agent import tclk_pilot_reveal_publish as publish

STAGE = "1" * 32
PAYER = "did:key:z6Mk" + "4" * 44
PAYEE = "did:key:z6Mk" + "5" * 44
CONTRACT = "0x" + "6" * 64


def reveal_preview():
    return {
        "schema_version": 1, "status": "prepared", "prepared_at": "2033-05-18T03:33:20+00:00",
        "stage_id": STAGE, "stage_digest": "2" * 64, "offer_id": "0x" + "3" * 64,
        "counterpart_did": PAYER, "our_did": PAYEE, "job_id": "job-1", "contract_id": CONTRACT,
        "deal_room": "mb-p-tclk-" + "6" * 16, "accept_sha256": "7" * 64,
        "lock_line_sha256": "8" * 64, "lock_ref": CONTRACT, "paper_note_sha256": "9" * 64,
        "work_evidence_sha256": "a" * 64, "expires_ms": 2_000_001_000_000,
        "claim_by_ms": 2_000_000_900_000, "refund_after_ms": 2_000_001_200_000,
        "reveal_sha256": "b" * 64,
    }


def test_reveal_approval_is_distinct_and_public_only(monkeypatch):
    preview = reveal_preview()
    monkeypatch.setattr(tclk_pilot_reveal, "load_preview", lambda *_a, **_k: preview)
    result = approval.public_prepared_approval(STAGE, now_ms=2_000_000_000_000)
    assert result["approval_digest"] == approval.approval_digest(preview)
    assert len(result["approval_digest"]) == 64
    assert all(key not in json.dumps(result) for key in ("reveal_line", "preimage", "private_key"))
    changed = dict(preview); changed["work_evidence_sha256"] = "c" * 64
    assert approval.approval_digest(changed) != result["approval_digest"]


def test_reveal_approval_window_fails_closed(monkeypatch):
    preview = reveal_preview()
    monkeypatch.setattr(tclk_pilot_reveal, "load_preview", lambda *_a, **_k: preview)
    with pytest.raises(approval.RevealApprovalError, match="window_elapsed"):
        approval.public_prepared_approval(STAGE, now_ms=preview["claim_by_ms"] - 10_000)


def test_ambiguous_reveal_never_reposts(monkeypatch):
    state = {"state": "reveal_ambiguous", "stage_id": STAGE, "deal_room": "mb-p-tclk-" + "6" * 16, "did": PAYEE, "nonce": "123", "sig": "A" * 86}
    monkeypatch.setattr(publish, "_load_state", lambda *_a, **_k: state)
    monkeypatch.setattr(tclk_pilot_reveal, "load_preview", lambda *_a, **_k: reveal_preview())
    monkeypatch.setattr(publish, "_load_private_reveal", lambda *_a, **_k: {"reveal_line": "tclk1 {}"})
    monkeypatch.setattr(publish, "_reconcile_reveal", lambda *_a, **_k: False)
    monkeypatch.setattr(publish, "_post_reveal_once", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must never repost")))
    assert publish.publish_stage(STAGE, now_ms=2_000_000_000_000)["action"] == "reveal_ambiguous"


def test_write_interlock_runs_before_any_new_source_or_sign(monkeypatch):
    monkeypatch.setattr(publish, "_load_state", lambda *_a, **_k: None)
    monkeypatch.setattr(publish.tclk_pilot_accept, "_require_write_interlock", lambda: (_ for _ in ()).throw(publish.tclk_pilot_accept.AcceptError("observer_health_not_ok")))
    monkeypatch.setattr(publish, "_exact_sources", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("sources must not run")))
    with pytest.raises(publish.tclk_pilot_accept.AcceptError, match="observer_health_not_ok"):
        publish.publish_stage(STAGE, now_ms=2_000_000_000_000)


def test_pinned_paper_claim_bridge_builds_exact_claim_without_reveal_ref():
    source = r"""
import { makeOffer, makeAccept, encodeFrame, encodePaperRecord, hashLockFromPreimage } from '@flop-labs/tclk';
let raw=''; for await (const c of process.stdin) raw += c; const i=JSON.parse(raw);
const now=Date.now(); const witness='0x'+'11'.repeat(32);
const offer=makeOffer({from:i.payer,role:'payer',amount:'1',asset:'PAPER',lock:'hash',rails:['paper'],claimByMs:now+600000,refundAfterMs:now+900000,expiresMs:now+300000,job:{proto:'a2a',id:'job-1'},nonce:'abcdef12'});
const accept=makeAccept(offer,{from:i.payee,statement:hashLockFromPreimage(witness).hash,nonce:'12345678'});
const revealObj={contract:accept.contract,from:i.payee,type:'reveal'}; revealObj["secret"]=witness;
const reveal='tclk1 '+JSON.stringify(revealObj,Object.keys(revealObj).sort());
const locked=encodePaperRecord({status:'locked',lock:'hash',statement:accept.statement,refundAfterMs:offer.refundAfterMs});
process.stdout.write(JSON.stringify({accept:encodeFrame(accept),reveal,contract:accept.contract,locked,refund:offer.refundAfterMs,now,witness}));
"""
    built = subprocess.run(["node", "--input-type=module", "--eval", source], input=json.dumps({"payer": PAYER, "payee": PAYEE}), text=True, capture_output=True, check=True)
    v = json.loads(built.stdout)
    request = {"contract_id": v["contract"], "our_did": PAYEE, "accept_line": v["accept"], "reveal_line": v["reveal"], "current_note": v["locked"], "refund_after_ms": v["refund"], "now_ms": v["now"]}
    result = subprocess.run(["node", str(Path("tools/tclk_prepare_paper_claim.mjs"))], input=json.dumps(request), text=True, capture_output=True, check=True)
    out = json.loads(result.stdout)
    assert out["status"] == "ready"
    assert " claimed hash " in out["claimed_line"]
    assert v["witness"] in out["claimed_line"]
    assert out["claimed_sha256"] == hashlib.sha256(out["claimed_line"].encode()).hexdigest()


def test_reveal_wrapper_and_unit_are_fixed_shape_without_timer():
    wrapper = Path("packaging/oracle/technocore-tclk-reveal-approve").read_text("utf-8")
    unit = Path("packaging/oracle/technocore-safe-agent-tclk-reveal@.service").read_text("utf-8")
    assert "APPROVE_REVEAL" in wrapper and "systemctl start" in wrapper
    assert "EnvironmentFile=/etc/technocore-safe-agent/signer.env" in unit
    assert "tclk_pilot_reveal_publish %i" in unit
    assert "IPAddressDeny=169.254.169.254" in unit
    assert not Path("packaging/oracle/technocore-safe-agent-tclk-reveal.timer").exists()


def test_public_result_never_exposes_private_material():
    state = {"stage_id": STAGE, "contract_id": CONTRACT, "deal_room": "mb-p-tclk-" + "6" * 16, "reveal_sha256": "a" * 64, "state": "claimed", "claimed_note_sha256": "b" * 64, "reveal_line": "must-not-leak", "preimage": "must-not-leak"}
    text = json.dumps(publish.public_result({"action": "claimed", "state": state}))
    assert "reveal_line" not in text and "preimage" not in text and "must-not-leak" not in text
