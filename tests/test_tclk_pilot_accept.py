import json
from pathlib import Path

import pytest

from flop_agent import core, tclk_pilot_accept, tclk_pilot_approval, tclk_pilot_signer


NOW = 2_000_000_000_000
DID = "did:key:z6Mk" + "1" * 44
STAGE_ID = "1" * 32
STAGE_DIGEST = "2" * 64
OFFER_ID = "0x" + "3" * 64
FRAME_HASH = "4" * 64
SPEC_HASH = "5" * 64
MATERIAL_HASH = "6" * 64
ACCEPT_LINE = "tclk1 {\"type\":\"accept\"}"
ACCEPT_HASH = __import__("hashlib").sha256(ACCEPT_LINE.encode()).hexdigest()
CONTRACT_ID = "0x" + "8" * 64
DEAL_ROOM = "mb-p-tclk-" + "9" * 16
SIG = "A" * 86


def stage():
    return {
        "stage_id": STAGE_ID,
        "stage_digest": STAGE_DIGEST,
        "offer_id": OFFER_ID,
        "frame_sha256": FRAME_HASH,
        "full_spec_sha256": SPEC_HASH,
        "material_sha256": MATERIAL_HASH,
        "expires_ms": NOW + 600_000,
        "our_did": DID,
        "rail": "paper",
        "lock": "hash",
        "job_proto": "a2a",
    }


def preview():
    return {
        "stage_id": STAGE_ID,
        "stage_digest": STAGE_DIGEST,
        "offer_id": OFFER_ID,
        "frame_sha256": FRAME_HASH,
        "full_spec_sha256": SPEC_HASH,
        "material_sha256": MATERIAL_HASH,
        "expires_ms": NOW + 600_000,
        "accept_line": ACCEPT_LINE,
        "accept_sha256": ACCEPT_HASH,
        "contract_id": CONTRACT_ID,
        "deal_room": DEAL_ROOM,
        "accepted": False,
    }


def approval_record():
    s, p = stage(), preview()
    digest = tclk_pilot_approval.approval_digest(s, p)
    return {
        "schema_version": 1,
        "status": "approved",
        "approved_at": "2033-05-18T03:33:20+00:00",
        "approval_digest": digest,
        "stage_id": STAGE_ID,
        "stage_digest": STAGE_DIGEST,
        "offer_id": OFFER_ID,
        "frame_sha256": FRAME_HASH,
        "full_spec_sha256": SPEC_HASH,
        "material_sha256": MATERIAL_HASH,
        "accept_sha256": ACCEPT_HASH,
        "contract_id": CONTRACT_ID,
        "deal_room": DEAL_ROOM,
        "expires_ms": NOW + 600_000,
    }


def accept_state(state_name="prepared"):
    return {
        "schema_version": 1,
        "state": state_name,
        "stage_id": STAGE_ID,
        "approval_digest": approval_record()["approval_digest"],
        "offer_id": OFFER_ID,
        "accept_line": ACCEPT_LINE,
        "accept_sha256": ACCEPT_HASH,
        "contract_id": CONTRACT_ID,
        "deal_room": DEAL_ROOM,
        "did": DID,
        "nonce": "2000000000000",
        "sig": SIG,
        "prepared_at": "2033-05-18T03:33:20+00:00",
        "attempted_at": None if state_name == "prepared" else "2033-05-18T03:33:21+00:00",
        "posted_at": None,
        "seq": None,
        "ts": None,
        "last_error": None,
        "git_commit_sha": "a" * 64,
        "executed_at": "2033-05-18T03:33:20+00:00",
    }


def test_approval_digest_binds_exact_preview_and_wrong_digest_fails(monkeypatch):
    s, p = stage(), preview()
    digest = tclk_pilot_approval.approval_digest(s, p)
    changed = dict(p)
    changed["accept_sha256"] = "f" * 64
    assert tclk_pilot_approval.approval_digest(s, changed) != digest

    monkeypatch.setattr(tclk_pilot_approval.tclk_pilot, "load_stage", lambda *_a, **_k: s)
    monkeypatch.setattr(tclk_pilot_signer, "_load_preview", lambda *_a, **_k: p)
    monkeypatch.setattr(tclk_pilot_signer, "_require_preview_binding", lambda *_a, **_k: None)
    monkeypatch.setattr(tclk_pilot_signer, "_require_protocol_file", lambda *_a, **_k: Path("/tmp/private"))

    record = tclk_pilot_approval.build_approval(STAGE_ID, digest, now_ms=NOW)
    assert record["approval_digest"] == digest
    with pytest.raises(tclk_pilot_approval.ApprovalError, match="approval_digest_mismatch"):
        tclk_pilot_approval.build_approval(STAGE_ID, "0" * 64, now_ms=NOW)


def test_expired_or_rushed_approval_is_blocked(monkeypatch):
    s, p = stage(), preview()
    s["expires_ms"] = p["expires_ms"] = NOW + 30_000
    monkeypatch.setattr(tclk_pilot_approval.tclk_pilot, "load_stage", lambda *_a, **_k: s)
    with pytest.raises(tclk_pilot_approval.ApprovalError, match="approval_window_elapsed"):
        tclk_pilot_approval.prepared_approval(STAGE_ID, now_ms=NOW)


def test_approval_file_must_be_root_owned_and_mode_bound(monkeypatch, tmp_path):
    path = tmp_path / f"{STAGE_ID}.json"
    path.write_text(json.dumps(approval_record()), encoding="utf-8")
    path.chmod(0o640)
    monkeypatch.setattr(tclk_pilot_approval, "approval_path", lambda _stage_id: path)
    monkeypatch.setattr(tclk_pilot_accept, "_approval_file_secure", lambda _path: False)
    with pytest.raises(tclk_pilot_accept.AcceptError, match="approval_file_unsafe"):
        tclk_pilot_accept._load_approval(STAGE_ID, stage(), preview(), now_ms=NOW)


def test_exact_prepared_revalidates_note_and_reconstructs_before_write(monkeypatch):
    s, p, approval = stage(), preview(), approval_record()
    reconstructed = {key: p[key] for key in (
        "stage_id", "stage_digest", "offer_id", "frame_sha256", "full_spec_sha256",
        "material_sha256", "expires_ms", "accept_line", "accept_sha256", "contract_id", "deal_room",
    )}
    monkeypatch.setattr(tclk_pilot_accept.tclk_pilot, "load_stage", lambda *_a, **_k: s)
    monkeypatch.setattr(tclk_pilot_signer, "_load_preview", lambda *_a, **_k: p)
    monkeypatch.setattr(tclk_pilot_signer, "_require_preview_binding", lambda *_a, **_k: None)
    monkeypatch.setattr(tclk_pilot_signer, "_require_protocol_file", lambda *_a, **_k: Path("/tmp/private"))
    monkeypatch.setattr(tclk_pilot_accept, "_load_approval", lambda *_a, **_k: approval)
    monkeypatch.setattr(tclk_pilot_signer, "_resolve_and_bind", lambda *_a, **_k: {"ok": True})
    monkeypatch.setattr(tclk_pilot_signer, "_run_bridge", lambda *_a, **_k: reconstructed)
    out = tclk_pilot_accept._exact_prepared(STAGE_ID, now_ms=NOW)
    assert out[3]["accept_sha256"] == ACCEPT_HASH

    monkeypatch.setattr(
        tclk_pilot_signer,
        "_resolve_and_bind",
        lambda *_a, **_k: (_ for _ in ()).throw(tclk_pilot_signer.PrepareError("note_hash_changed")),
    )
    with pytest.raises(tclk_pilot_accept.AcceptError, match="note_hash_changed"):
        tclk_pilot_accept._exact_prepared(STAGE_ID, now_ms=NOW)


def test_signer_can_only_sign_exact_reconstructed_accept(monkeypatch):
    calls = []
    monkeypatch.setattr(tclk_pilot_accept.oracle_signer, "expected_did", lambda: DID)
    monkeypatch.setattr(tclk_pilot_accept.core, "require_verified_did", lambda _did: None)
    monkeypatch.setattr(tclk_pilot_accept.core, "signer_matches_pinned", lambda: True)
    monkeypatch.setattr(tclk_pilot_accept.oracle_signer, "with_vault_seed", lambda operation: operation())
    monkeypatch.setattr(
        tclk_pilot_accept.core,
        "invoke_signer",
        lambda *args: calls.append(args) or [DID, SIG],
    )
    assert tclk_pilot_accept._sign_exact(DID, "2000000000000", ACCEPT_LINE) == SIG
    assert calls == [("say", "tclk-offers", "2000000000000", ACCEPT_LINE)]


def test_ambiguous_post_terminalizes_and_next_run_never_reposts(monkeypatch):
    s, p, approval = stage(), preview(), approval_record()
    value = accept_state("prepared")
    monkeypatch.setattr(tclk_pilot_accept, "_exact_prepared", lambda *_a, **_k: (s, p, approval, {}))
    monkeypatch.setattr(tclk_pilot_accept, "_load_state", lambda _stage_id: value)
    monkeypatch.setattr(tclk_pilot_accept, "_save_state", lambda _value: None)
    monkeypatch.setattr(tclk_pilot_accept, "_reconcile", lambda current, _text: {"action": "ambiguous", "state": current})
    post_calls = []
    monkeypatch.setattr(
        tclk_pilot_accept,
        "_post_once",
        lambda *_a, **_k: post_calls.append(1) or (_ for _ in ()).throw(RuntimeError("timeout")),
    )
    with pytest.raises(tclk_pilot_accept.AcceptError, match="submission_unknown"):
        tclk_pilot_accept.accept_stage(STAGE_ID, now_ms=NOW)
    assert len(post_calls) == 1
    assert value["state"] == "ambiguous"

    result = tclk_pilot_accept.accept_stage(STAGE_ID, now_ms=NOW + 700_000)
    assert result["action"] == "ambiguous"
    assert len(post_calls) == 1


def test_ambiguous_reconciliation_survives_expiry_and_never_revalidates_for_repost(monkeypatch):
    value = accept_state("ambiguous")
    matched = {"from": DID, "nonce": value["nonce"], "sig": SIG, "text": ACCEPT_LINE, "seq": 77, "ts": "2033-05-18T03:33:22Z"}
    monkeypatch.setattr(tclk_pilot_accept, "_load_state", lambda _stage_id: value)
    monkeypatch.setattr(
        tclk_pilot_accept,
        "_exact_prepared",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not re-enter live write validation")),
    )
    monkeypatch.setattr(tclk_pilot_accept, "_find_exact_message", lambda *_a, **_k: matched)
    monkeypatch.setattr(tclk_pilot_accept, "_ensure_activity", lambda *_a, **_k: None)
    monkeypatch.setattr(tclk_pilot_accept, "_save_state", lambda *_a, **_k: None)
    result = tclk_pilot_accept.accept_stage(STAGE_ID, now_ms=NOW + 700_000)
    assert result["action"] == "reconciled"
    assert value["state"] == "posted"
    assert value["seq"] == 77


def test_already_posted_is_replay_safe_without_live_revalidation(monkeypatch):
    value = accept_state("posted")
    value["posted_at"] = "2033-05-18T03:33:22+00:00"
    value["seq"] = 77
    value["ts"] = "2033-05-18T03:33:22Z"
    monkeypatch.setattr(tclk_pilot_accept, "_load_state", lambda _stage_id: value)
    monkeypatch.setattr(
        tclk_pilot_accept,
        "_exact_prepared",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("posted state must be terminal")),
    )
    result = tclk_pilot_accept.accept_stage(STAGE_ID, now_ms=NOW + 700_000)
    assert result["action"] == "already_posted"


def test_accept_service_and_wrapper_preserve_one_shot_fixed_shape():
    unit = (core.ROOT / "packaging" / "oracle" / "technocore-safe-agent-tclk-accept@.service").read_text("utf-8")
    wrapper = (core.ROOT / "packaging" / "oracle" / "technocore-tclk-approve").read_text("utf-8")
    assert "Type=oneshot" in unit
    assert "User=technocore-signer" in unit
    assert "EnvironmentFile=/etc/technocore-safe-agent/signer.env" in unit
    assert "-m flop_agent.tclk_pilot_accept %i" in unit
    assert "Restart=" not in unit
    assert not (core.ROOT / "packaging" / "oracle" / "technocore-safe-agent-tclk-accept.timer").exists()
    assert "[[ $# -ne 3 ]]" in wrapper
    assert "[[ $CONFIRM == APPROVE ]]" in wrapper
    assert "approval already exists; refusing replacement" in wrapper
    assert "systemctl start \"$UNIT\"" in wrapper
    assert "curl " not in wrapper and "wget " not in wrapper
