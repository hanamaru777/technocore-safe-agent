import json
from pathlib import Path

import pytest

from flop_agent import core, discord_tclk_approval, tclk_pilot_approval, tclk_pilot_signer


NOW = 2_000_000_000_000
STAGE_ID = "1" * 32
STAGE_DIGEST = "2" * 64
OFFER_ID = "0x" + "3" * 64
FRAME_HASH = "4" * 64
SPEC_HASH = "5" * 64
MATERIAL_HASH = "6" * 64
ACCEPT_HASH = "7" * 64
CONTRACT_ID = "0x" + "8" * 64
DEAL_ROOM = "mb-p-tclk-" + "9" * 16


def stage():
    return {
        "stage_id": STAGE_ID,
        "stage_digest": STAGE_DIGEST,
        "offer_id": OFFER_ID,
        "frame_sha256": FRAME_HASH,
        "full_spec_sha256": SPEC_HASH,
        "material_sha256": MATERIAL_HASH,
        "expires_ms": NOW + 600_000,
        "job_id": "public-repo-review",
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
        "accept_sha256": ACCEPT_HASH,
        "contract_id": CONTRACT_ID,
        "deal_room": DEAL_ROOM,
    }


def evidence():
    return {
        "offer_id": OFFER_ID,
        "job_id": "public-repo-review",
        "frame_sha256": FRAME_HASH,
        "expires_ms": NOW + 600_000,
        "accepted": False,
        "external_url_present": False,
        "full_spec": {"sha256": SPEC_HASH, "value": "Review the public repository specification and summarize findings."},
        "material": {"sha256": MATERIAL_HASH, "value": "public fixture"},
    }


def prepared():
    s, p = stage(), preview()
    return {"stage": s, "preview": p, "bindings": tclk_pilot_approval._bindings(s, p), "approval_digest": tclk_pilot_approval.approval_digest(s, p)}


def test_public_approval_preview_never_reads_private_protocol_material(monkeypatch):
    s, p = stage(), preview()
    monkeypatch.setattr(tclk_pilot_approval.tclk_pilot, "load_stage", lambda *_a, **_k: s)
    monkeypatch.setattr(tclk_pilot_signer, "_load_preview", lambda *_a, **_k: p)
    monkeypatch.setattr(tclk_pilot_signer, "_require_preview_binding", lambda *_a, **_k: None)
    monkeypatch.setattr(
        tclk_pilot_signer,
        "_require_protocol_file",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("public preview must not read private material")),
    )

    public = tclk_pilot_approval.public_prepared_approval(STAGE_ID, now_ms=NOW)
    assert public["approval_digest"] == tclk_pilot_approval.approval_digest(s, p)

    with pytest.raises(AssertionError, match="public preview must not read private material"):
        tclk_pilot_approval.prepared_approval(STAGE_ID, now_ms=NOW)


def test_public_digest_exactly_matches_root_approval_digest(monkeypatch):
    s, p = stage(), preview()
    monkeypatch.setattr(tclk_pilot_approval.tclk_pilot, "load_stage", lambda *_a, **_k: s)
    monkeypatch.setattr(tclk_pilot_signer, "_load_preview", lambda *_a, **_k: p)
    monkeypatch.setattr(tclk_pilot_signer, "_require_preview_binding", lambda *_a, **_k: None)
    monkeypatch.setattr(tclk_pilot_signer, "_require_protocol_file", lambda *_a, **_k: Path("/private/protocol"))

    public = tclk_pilot_approval.public_prepared_approval(STAGE_ID, now_ms=NOW)
    root_record = tclk_pilot_approval.build_approval(STAGE_ID, public["approval_digest"], now_ms=NOW)
    assert root_record["approval_digest"] == public["approval_digest"]


def test_prepared_notice_contains_exact_operator_action_and_public_evidence(monkeypatch, tmp_path):
    preview_dir = tmp_path / "previews"
    preview_dir.mkdir()
    (preview_dir / f"{STAGE_ID}.json").write_text("{}\n", encoding="utf-8")
    saved = []

    monkeypatch.setattr(discord_tclk_approval.tclk_pilot, "preview_dir", lambda: preview_dir)
    monkeypatch.setattr(discord_tclk_approval.tclk_pilot_approval, "public_prepared_approval", lambda *_a, **_k: prepared())
    monkeypatch.setattr(discord_tclk_approval, "_evidence_for", lambda _stage: evidence())
    monkeypatch.setattr(discord_tclk_approval, "_load_notice_state", lambda: {"schema_version": 1, "notified": []})
    monkeypatch.setattr(discord_tclk_approval, "_save_notice_state", lambda value: saved.append(json.loads(json.dumps(value))))
    monkeypatch.setattr(discord_tclk_approval, "_now_ms", lambda: NOW)

    notices = discord_tclk_approval._new_prepared_approval_notices()
    assert len(notices) == 1
    text = notices[0]
    digest = prepared()["approval_digest"]
    assert "PREPARE完了" in text
    assert "PaperRail / no-value rehearsal" in text
    assert f"approval digest: {digest}" in text
    assert f"sudo /usr/local/sbin/technocore-tclk-approve {STAGE_ID} {digest} APPROVE" in text
    assert "Review the public repository specification" in text
    assert saved[0]["notified"][0]["stage_id"] == STAGE_ID


def test_notice_dedupe_survives_restart_state(monkeypatch, tmp_path):
    preview_dir = tmp_path / "previews"
    preview_dir.mkdir()
    (preview_dir / f"{STAGE_ID}.json").write_text("{}\n", encoding="utf-8")
    row = {"stage_id": STAGE_ID, "approval_digest": prepared()["approval_digest"], "notified_at": "2033-05-18T03:33:20+00:00"}

    monkeypatch.setattr(discord_tclk_approval.tclk_pilot, "preview_dir", lambda: preview_dir)
    monkeypatch.setattr(discord_tclk_approval.tclk_pilot_approval, "public_prepared_approval", lambda *_a, **_k: prepared())
    monkeypatch.setattr(discord_tclk_approval, "_evidence_for", lambda _stage: evidence())
    monkeypatch.setattr(discord_tclk_approval, "_load_notice_state", lambda: {"schema_version": 1, "notified": [row]})
    monkeypatch.setattr(discord_tclk_approval, "_now_ms", lambda: NOW)

    assert discord_tclk_approval._new_prepared_approval_notices() == []


def test_expired_or_missing_public_binding_never_prompts(monkeypatch, tmp_path):
    preview_dir = tmp_path / "previews"
    preview_dir.mkdir()
    (preview_dir / f"{STAGE_ID}.json").write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(discord_tclk_approval.tclk_pilot, "preview_dir", lambda: preview_dir)
    monkeypatch.setattr(discord_tclk_approval, "_load_notice_state", lambda: {"schema_version": 1, "notified": []})
    monkeypatch.setattr(
        discord_tclk_approval.tclk_pilot_approval,
        "public_prepared_approval",
        lambda *_a, **_k: (_ for _ in ()).throw(tclk_pilot_approval.ApprovalError("approval_window_elapsed")),
    )
    assert discord_tclk_approval._new_prepared_approval_notices() == []


def test_evidence_binding_mismatch_fails_closed(monkeypatch):
    bad = evidence()
    bad["frame_sha256"] = "f" * 64
    monkeypatch.setattr(discord_tclk_approval.tclk_review_evidence, "get", lambda _offer_id: bad)
    with pytest.raises(discord_tclk_approval.NoticeError, match="approval_evidence_binding_mismatch"):
        discord_tclk_approval._evidence_for(stage())


def test_discord_overlay_has_no_accept_or_signer_capability_and_service_is_public_only():
    source = (core.ROOT / "src" / "flop_agent" / "discord_tclk_approval.py").read_text("utf-8")
    unit = (core.ROOT / "packaging" / "oracle" / "discord.service").read_text("utf-8")
    assert "tclk_pilot_accept" not in source
    assert "oracle_signer" not in source
    assert "invoke_signer" not in source
    assert "httpx.post" not in source
    assert "approval_path(" not in source
    assert "EnvironmentFile=/etc/technocore-safe-agent/signer.env" not in unit
    assert "-m flop_agent.discord_tclk_approval" in unit
    assert "IPAddressDeny=169.254.169.254" in unit
