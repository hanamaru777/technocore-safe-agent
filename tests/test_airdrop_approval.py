from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from flop_agent import airdrop_approval, core, discord_control, discord_tclk_approval


T0 = datetime(2026, 9, 19, 0, 0, tzinfo=UTC)
PAYLOAD = "a" * 64


@pytest.fixture
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setattr(airdrop_approval, "_FAILURE_NOTIFIED", False)
    return tmp_path


def stage(*, expires: datetime | None = None) -> dict:
    return airdrop_approval.stage_request(
        action_class="registration",
        payload_sha256=PAYLOAD,
        source_event_id="event-123",
        summary="Register MARU agent on the official FLOP testnet.",
        cost_note="0 FLOP / no real-value spend",
        reversible=False,
        expires_at=expires or FUTURE,
        now=T0,
    )


def test_stage_is_durable_idempotent_and_non_executing(isolated_state: Path) -> None:
    first = stage()
    second = stage()

    assert first == second
    assert first["status"] == "pending"
    assert first["action_class"] == "registration"
    assert len(first["request_id"]) == 32
    assert len(first["approval_digest"]) == 64
    assert airdrop_approval.state_path().exists()
    assert airdrop_approval.list_requests(now=T0) == [first]


def test_exact_digest_approval_and_single_consumption(isolated_state: Path) -> None:
    row = stage()
    approved = airdrop_approval.decide(
        row["request_id"],
        row["approval_digest"],
        decision="approved",
        actor_id="42",
        now=T0 + timedelta(minutes=1),
    )
    assert approved["status"] == "approved"

    consumed = airdrop_approval.consume(
        row["request_id"],
        row["approval_digest"],
        receipt="executor-receipt-1",
        now=T0 + timedelta(minutes=2),
    )
    assert consumed["status"] == "consumed"
    assert consumed["consumption_receipt"] == "executor-receipt-1"

    with pytest.raises(airdrop_approval.ApprovalInboxError, match="not_approved:consumed"):
        airdrop_approval.consume(
            row["request_id"],
            row["approval_digest"],
            receipt="executor-receipt-2",
            now=T0 + timedelta(minutes=3),
        )


def test_digest_mismatch_rejection_and_reuse_fail_closed(isolated_state: Path) -> None:
    row = stage()

    with pytest.raises(airdrop_approval.ApprovalInboxError, match="digest_mismatch"):
        airdrop_approval.decide(
            row["request_id"],
            "b" * 64,
            decision="approved",
            actor_id="42",
            now=T0 + timedelta(minutes=1),
        )

    rejected = airdrop_approval.decide(
        row["request_id"],
        row["approval_digest"],
        decision="rejected",
        actor_id="42",
        now=T0 + timedelta(minutes=1),
    )
    assert rejected["status"] == "rejected"

    with pytest.raises(airdrop_approval.ApprovalInboxError, match="not_pending:rejected"):
        airdrop_approval.decide(
            row["request_id"],
            row["approval_digest"],
            decision="approved",
            actor_id="42",
            now=T0 + timedelta(minutes=2),
        )


def test_expired_request_cannot_be_approved(isolated_state: Path) -> None:
    row = stage(expires=T0 + timedelta(minutes=1))

    with pytest.raises(airdrop_approval.ApprovalInboxError, match="not_pending:expired"):
        airdrop_approval.decide(
            row["request_id"],
            row["approval_digest"],
            decision="approved",
            actor_id="42",
            now=T0 + timedelta(minutes=2),
        )

    assert airdrop_approval.get_request(
        row["request_id"], now=T0 + timedelta(minutes=2)
    )["status"] == "expired"


def test_notice_is_durable_and_not_repeated(isolated_state: Path) -> None:
    row = stage()

    notices = airdrop_approval.poll_notices(now=T0 + timedelta(seconds=1))
    assert len(notices) == 1
    assert row["request_id"] in notices[0]
    assert row["approval_digest"] in notices[0]
    assert "/airdrop-approve" in notices[0]
    assert "署名・送信・Claim・支払いは実行しません" in notices[0]

    assert airdrop_approval.poll_notices(now=T0 + timedelta(seconds=2)) == []


def test_discord_commands_require_authorized_user_exact_digest_and_token(
    isolated_state: Path,
) -> None:
    row = stage()
    control = discord_control.Control({"42"}, "99")

    assert control.command("7", "/airdrop-approvals", "99")["error"] == "unauthorized"
    pending = control.command("42", "/airdrop-approvals", "99")
    assert pending["ok"] is True
    assert row["request_id"] in pending["message"]

    detail = control.command(
        "42", f"/airdrop-approval {row['request_id']}", "99"
    )
    assert detail["ok"] is True
    assert row["approval_digest"] in detail["message"]

    missing_token = control.command(
        "42",
        f"/airdrop-approve {row['request_id']} {row['approval_digest']} yes",
        "99",
    )
    assert missing_token["ok"] is False
    assert missing_token["error"] == "confirmation_required"

    approved = control.command(
        "42",
        f"/airdrop-approve {row['request_id']} {row['approval_digest']} APPROVE",
        "99",
    )
    assert approved["ok"] is True
    assert "外部実行はまだ" in approved["message"]
    assert airdrop_approval.get_request(row["request_id"], now=T0)["status"] == "approved"


def test_discord_reject_is_separate_exact_action(isolated_state: Path) -> None:
    row = stage()
    control = discord_control.Control({"42"}, "99")

    rejected = control.command(
        "42",
        f"/airdrop-reject {row['request_id']} {row['approval_digest']} REJECT",
        "99",
    )
    assert rejected["ok"] is True
    assert airdrop_approval.get_request(row["request_id"], now=T0)["status"] == "rejected"


def test_tclk_notice_chain_includes_airdrop_notices(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discord_tclk_approval, "_ORIGINAL_NOTICES", lambda: ["base"])
    monkeypatch.setattr(
        discord_tclk_approval, "_new_prepared_approval_notices", lambda: ["accept"]
    )
    monkeypatch.setattr(
        discord_tclk_approval, "_new_prepared_reveal_notices", lambda: ["reveal"]
    )
    monkeypatch.setattr(
        discord_tclk_approval.airdrop_approval, "poll_notices", lambda: ["airdrop"]
    )

    from flop_agent import discord_sonnet_alerts

    monkeypatch.setattr(discord_sonnet_alerts, "poll_notices", lambda: ["sonnet"])
    assert discord_tclk_approval._combined_notices() == [
        "base",
        "accept",
        "reveal",
        "sonnet",
        "airdrop",
    ]


def test_approval_module_has_no_network_or_signer_capability() -> None:
    source = (core.ROOT / "src" / "flop_agent" / "airdrop_approval.py").read_text(
        "utf-8"
    )
    assert "httpx" not in source
    assert "oracle_signer" not in source
    assert "DISCORD_BOT_TOKEN" not in source
    assert "client.post" not in source.lower()
