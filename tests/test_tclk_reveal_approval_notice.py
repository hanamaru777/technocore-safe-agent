import json
from pathlib import Path

from flop_agent import discord_tclk_approval
from flop_agent import tclk_pilot_reveal_approval


NOW = 2_000_000_000_000
STAGE_ID = "1" * 32
STAGE_DIGEST = "2" * 64
OFFER_ID = "0x" + "3" * 64
COUNTERPART = "did:key:z6Mk" + "f" * 44
OUR_DID = "did:key:z6Mk" + "g" * 44
CONTRACT_ID = "0x" + "4" * 64
DEAL_ROOM = "mb-p-tclk-" + "4" * 16
ACCEPT_HASH = "5" * 64
LOCK_HASH = "6" * 64
PAPER_HASH = "7" * 64
WORK_HASH = "8" * 64
REVEAL_HASH = "9" * 64
CLAIM_BY = NOW + 600_000
REFUND_AFTER = NOW + 900_000


def reveal_preview():
    return {
        "schema_version": 1,
        "status": "prepared",
        "prepared_at": "2033-05-18T03:33:20+00:00",
        "stage_id": STAGE_ID,
        "stage_digest": STAGE_DIGEST,
        "offer_id": OFFER_ID,
        "counterpart_did": COUNTERPART,
        "our_did": OUR_DID,
        "job_id": "public-repo-review",
        "contract_id": CONTRACT_ID,
        "deal_room": DEAL_ROOM,
        "accept_sha256": ACCEPT_HASH,
        "lock_line_sha256": LOCK_HASH,
        "lock_ref": CONTRACT_ID,
        "paper_note_sha256": PAPER_HASH,
        "work_evidence_sha256": WORK_HASH,
        "expires_ms": NOW + 300_000,
        "claim_by_ms": CLAIM_BY,
        "refund_after_ms": REFUND_AFTER,
        "reveal_sha256": REVEAL_HASH,
    }


def prepared():
    preview = reveal_preview()
    bindings = tclk_pilot_reveal_approval._bindings(preview)
    return {
        "preview": preview,
        "bindings": bindings,
        "approval_digest": tclk_pilot_reveal_approval.approval_digest(preview),
    }


def test_reveal_notice_contains_exact_public_bindings_and_root_command(monkeypatch, tmp_path):
    preview_dir = tmp_path / "reveal-previews"
    preview_dir.mkdir()
    (preview_dir / f"{STAGE_ID}.json").write_text("{}\n", encoding="utf-8")
    saved = []

    monkeypatch.setattr(discord_tclk_approval.tclk_pilot_reveal, "preview_dir", lambda: preview_dir)
    monkeypatch.setattr(
        discord_tclk_approval.tclk_pilot_reveal_approval,
        "public_prepared_approval",
        lambda *_a, **_k: prepared(),
    )
    monkeypatch.setattr(
        discord_tclk_approval,
        "_load_reveal_notice_state",
        lambda: {"schema_version": 1, "notified": []},
    )
    monkeypatch.setattr(
        discord_tclk_approval,
        "_save_reveal_notice_state",
        lambda value: saved.append(json.loads(json.dumps(value))),
    )
    monkeypatch.setattr(discord_tclk_approval, "_now_ms", lambda: NOW)

    notices = discord_tclk_approval._new_prepared_reveal_notices()
    assert len(notices) == 1
    text = notices[0]
    digest = prepared()["approval_digest"]
    assert "REVEAL PREPARE完了" in text
    assert "PaperRail / no-value rehearsal" in text
    assert f"stage id: {STAGE_ID}" in text
    assert f"contract: {CONTRACT_ID}" in text
    assert f"deal room: {DEAL_ROOM}" in text
    assert f"accept sha256: {ACCEPT_HASH}" in text
    assert f"lock sha256: {LOCK_HASH}" in text
    assert f"lock ref: {CONTRACT_ID}" in text
    assert f"paper note sha256: {PAPER_HASH}" in text
    assert f"work evidence sha256: {WORK_HASH}" in text
    assert f"reveal sha256: {REVEAL_HASH}" in text
    assert f"claim by ms: {CLAIM_BY}" in text
    assert f"refund after ms: {REFUND_AFTER}" in text
    assert f"reveal approval digest: {digest}" in text
    assert (
        f"sudo /usr/local/sbin/technocore-tclk-reveal-approve {STAGE_ID} {digest} APPROVE_REVEAL"
        in text
    )
    assert "accept承認はREVEAL承認には使えません" in text
    assert saved[0]["notified"][0]["stage_id"] == STAGE_ID


def test_reveal_notice_dedupe_survives_restart_state(monkeypatch, tmp_path):
    preview_dir = tmp_path / "reveal-previews"
    preview_dir.mkdir()
    (preview_dir / f"{STAGE_ID}.json").write_text("{}\n", encoding="utf-8")
    row = {
        "stage_id": STAGE_ID,
        "approval_digest": prepared()["approval_digest"],
        "notified_at": "2033-05-18T03:33:20+00:00",
    }

    monkeypatch.setattr(discord_tclk_approval.tclk_pilot_reveal, "preview_dir", lambda: preview_dir)
    monkeypatch.setattr(
        discord_tclk_approval.tclk_pilot_reveal_approval,
        "public_prepared_approval",
        lambda *_a, **_k: prepared(),
    )
    monkeypatch.setattr(
        discord_tclk_approval,
        "_load_reveal_notice_state",
        lambda: {"schema_version": 1, "notified": [row]},
    )
    monkeypatch.setattr(discord_tclk_approval, "_now_ms", lambda: NOW)

    assert discord_tclk_approval._new_prepared_reveal_notices() == []


def test_expired_or_missing_reveal_public_binding_never_prompts(monkeypatch, tmp_path):
    preview_dir = tmp_path / "reveal-previews"
    preview_dir.mkdir()
    (preview_dir / f"{STAGE_ID}.json").write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(discord_tclk_approval.tclk_pilot_reveal, "preview_dir", lambda: preview_dir)
    monkeypatch.setattr(
        discord_tclk_approval,
        "_load_reveal_notice_state",
        lambda: {"schema_version": 1, "notified": []},
    )
    monkeypatch.setattr(
        discord_tclk_approval.tclk_pilot_reveal_approval,
        "public_prepared_approval",
        lambda *_a, **_k: (_ for _ in ()).throw(
            tclk_pilot_reveal_approval.RevealApprovalError("reveal_approval_window_elapsed")
        ),
    )

    assert discord_tclk_approval._new_prepared_reveal_notices() == []


def test_reveal_notice_durable_state_error_fails_closed(monkeypatch, tmp_path):
    preview_dir = tmp_path / "reveal-previews"
    preview_dir.mkdir()
    (preview_dir / f"{STAGE_ID}.json").write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(discord_tclk_approval.tclk_pilot_reveal, "preview_dir", lambda: preview_dir)
    monkeypatch.setattr(
        discord_tclk_approval,
        "_load_reveal_notice_state",
        lambda: (_ for _ in ()).throw(discord_tclk_approval.NoticeError("reveal_notice_state_invalid")),
    )

    assert discord_tclk_approval._new_prepared_reveal_notices() == []


def test_discord_reveal_notice_has_no_private_reveal_or_write_capability():
    source = Path("src/flop_agent/discord_tclk_approval.py").read_text("utf-8")
    unit = Path("packaging/oracle/discord.service").read_text("utf-8")
    assert "_require_private_reveal(" not in source
    assert ".prepared_approval(" not in source
    assert "reveal_approval.approval_path(" not in source
    assert "invoke_signer" not in source
    assert "oracle_signer" not in source
    assert "with_vault_seed" not in source
    assert "httpx.post" not in source
    assert "EnvironmentFile=/etc/technocore-safe-agent/signer.env" not in unit
    assert "-m flop_agent.discord_tclk_approval" in unit
