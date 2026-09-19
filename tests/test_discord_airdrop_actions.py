from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from flop_agent import (
    airdrop_action_stager,
    airdrop_approval,
    airdrop_ledger,
    core,
    discord_airdrop_actions,
    discord_control,
)


T0 = datetime(2026, 9, 19, 0, 0, tzinfo=UTC)
PAYLOAD = "c" * 64


@pytest.fixture
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setattr(airdrop_approval, "_FAILURE_NOTIFIED", False)
    return tmp_path


def stage_manual(
    *,
    action_class: str = "x_post",
    expires_at: datetime | None = None,
) -> dict:
    return airdrop_approval.stage_request(
        action_class=action_class,
        payload_sha256=PAYLOAD,
        source_event_id="event-manual",
        summary="Exact local approval UX test.",
        cost_note="0 FLOP / no external execution",
        reversible=False,
        expires_at=expires_at or T0 + timedelta(hours=2),
        now=T0,
    )


def test_button_specs_are_bounded_and_do_not_embed_digest(
    isolated_state: Path,
) -> None:
    row = stage_manual()
    specs = discord_airdrop_actions.button_specs(row)

    assert [item["action"] for item in specs] == ["details", "approve", "reject"]
    for item in specs:
        assert len(item["custom_id"]) <= 100
        assert row["request_id"] in item["custom_id"]
        assert row["approval_digest"] not in item["custom_id"]
        assert PAYLOAD not in item["custom_id"]


def test_component_authorization_and_channel_gate(isolated_state: Path) -> None:
    row = stage_manual()
    custom = discord_airdrop_actions.custom_id("details", row["request_id"])

    with pytest.raises(
        discord_airdrop_actions.DiscordAirdropActionError,
        match="unauthorized",
    ):
        discord_airdrop_actions.handle_interaction(
            allowed_ids={"42"},
            expected_channel_id="99",
            user_id="7",
            channel_id="99",
            component_custom_id=custom,
            now=T0,
        )

    with pytest.raises(
        discord_airdrop_actions.DiscordAirdropActionError,
        match="wrong_channel",
    ):
        discord_airdrop_actions.handle_interaction(
            allowed_ids={"42"},
            expected_channel_id="99",
            user_id="42",
            channel_id="100",
            component_custom_id=custom,
            now=T0,
        )


def test_approve_and_reject_are_exact_local_decisions(isolated_state: Path) -> None:
    approved_row = stage_manual()
    approved = discord_airdrop_actions.handle_interaction(
        allowed_ids={"42"},
        expected_channel_id="99",
        user_id="42",
        channel_id="99",
        component_custom_id=discord_airdrop_actions.custom_id(
            "approve", approved_row["request_id"]
        ),
        now=T0 + timedelta(minutes=1),
    )
    assert approved["record"]["status"] == "approved"
    assert approved["edit_original"] is True
    assert "まだ署名・送信・Claim・支払いは実行していません" in approved["message"]

    rejected_row = stage_manual(
        expires_at=T0 + timedelta(hours=3),
    )
    # Different expiry produces a different exact request id.
    rejected = discord_airdrop_actions.handle_interaction(
        allowed_ids={"42"},
        expected_channel_id="99",
        user_id="42",
        channel_id="99",
        component_custom_id=discord_airdrop_actions.custom_id(
            "reject", rejected_row["request_id"]
        ),
        now=T0 + timedelta(minutes=1),
    )
    assert rejected["record"]["status"] == "rejected"
    assert "外部実行はありません" in rejected["message"]


def test_duplicate_expired_and_consumed_clicks_fail_closed(
    isolated_state: Path,
) -> None:
    row = stage_manual()
    approve_id = discord_airdrop_actions.custom_id("approve", row["request_id"])
    discord_airdrop_actions.handle_interaction(
        allowed_ids={"42"},
        expected_channel_id="99",
        user_id="42",
        channel_id="99",
        component_custom_id=approve_id,
        now=T0 + timedelta(minutes=1),
    )
    with pytest.raises(
        discord_airdrop_actions.DiscordAirdropActionError,
        match="not_pending:approved",
    ):
        discord_airdrop_actions.handle_interaction(
            allowed_ids={"42"},
            expected_channel_id="99",
            user_id="42",
            channel_id="99",
            component_custom_id=approve_id,
            now=T0 + timedelta(minutes=2),
        )

    expired = stage_manual(expires_at=T0 + timedelta(minutes=3))
    with pytest.raises(
        discord_airdrop_actions.DiscordAirdropActionError,
        match="not_pending:expired",
    ):
        discord_airdrop_actions.handle_interaction(
            allowed_ids={"42"},
            expected_channel_id="99",
            user_id="42",
            channel_id="99",
            component_custom_id=discord_airdrop_actions.custom_id(
                "approve", expired["request_id"]
            ),
            now=T0 + timedelta(minutes=4),
        )

    consumed = stage_manual(expires_at=T0 + timedelta(hours=4))
    approved_consumed = airdrop_approval.decide(
        consumed["request_id"],
        consumed["approval_digest"],
        decision="approved",
        actor_id="42",
        now=T0 + timedelta(minutes=1),
    )
    airdrop_approval.consume(
        consumed["request_id"],
        approved_consumed["approval_digest"],
        receipt="local-test-receipt",
        now=T0 + timedelta(minutes=2),
    )
    with pytest.raises(
        discord_airdrop_actions.DiscordAirdropActionError,
        match="not_pending:consumed",
    ):
        discord_airdrop_actions.handle_interaction(
            allowed_ids={"42"},
            expected_channel_id="99",
            user_id="42",
            channel_id="99",
            component_custom_id=discord_airdrop_actions.custom_id(
                "reject", consumed["request_id"]
            ),
            now=T0 + timedelta(minutes=3),
        )


def test_malformed_component_id_is_rejected(isolated_state: Path) -> None:
    with pytest.raises(
        discord_airdrop_actions.DiscordAirdropActionError,
        match="custom_id_invalid",
    ):
        discord_airdrop_actions.handle_interaction(
            allowed_ids={"42"},
            expected_channel_id="99",
            user_id="42",
            channel_id="99",
            component_custom_id="flop-airdrop:approve:not-a-request",
            now=T0,
        )


def test_auto_staged_action_revalidates_candidate_and_ledger(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = stage_manual(action_class="registration")
    candidate = {
        "candidate_id": "d" * 32,
        "request_id": row["request_id"],
        "approval_digest": row["approval_digest"],
        "payload_sha256": row["payload_sha256"],
        "source_event_id": row["source_event_id"],
        "source_ledger_hash": "e" * 64,
        "payload": {
            "action": "registration",
            "url": "https://flop.finance/register",
        },
    }
    monkeypatch.setattr(
        airdrop_action_stager,
        "get_candidate_for_request",
        lambda request_id: dict(candidate),
    )
    monkeypatch.setattr(
        airdrop_ledger,
        "verify_ledger",
        lambda: {
            "valid": True,
            "count": 1,
            "tip_hash": candidate["source_ledger_hash"],
            "records": [
                {
                    "event_id": row["source_event_id"],
                    "hash": candidate["source_ledger_hash"],
                    "source_evidence": [
                        {
                            "tier": 1,
                            "authority": "official",
                            "status": "ok",
                            "observation": "current",
                            "url": "https://flop.finance/",
                        }
                    ],
                }
            ],
        },
    )

    details = discord_airdrop_actions.handle_interaction(
        allowed_ids={"42"},
        expected_channel_id="99",
        user_id="42",
        channel_id="99",
        component_custom_id=discord_airdrop_actions.custom_id(
            "details", row["request_id"]
        ),
        now=T0,
    )
    assert details["edit_original"] is False
    assert "exact payload:" in details["message"]
    assert "source ledger hash:" in details["message"]
    assert "authority=official" in details["message"]

    approved = discord_airdrop_actions.handle_interaction(
        allowed_ids={"42"},
        expected_channel_id="99",
        user_id="42",
        channel_id="99",
        component_custom_id=discord_airdrop_actions.custom_id(
            "approve", row["request_id"]
        ),
        now=T0 + timedelta(minutes=1),
    )
    assert approved["record"]["status"] == "approved"


def test_auto_staged_candidate_binding_mismatch_blocks_click(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = stage_manual(action_class="claim")
    monkeypatch.setattr(
        airdrop_action_stager,
        "get_candidate_for_request",
        lambda request_id: {
            "request_id": row["request_id"],
            "approval_digest": "f" * 64,
            "payload_sha256": row["payload_sha256"],
            "source_event_id": row["source_event_id"],
            "source_ledger_hash": "e" * 64,
        },
    )

    with pytest.raises(
        discord_airdrop_actions.DiscordAirdropActionError,
        match="candidate_binding_mismatch",
    ):
        discord_airdrop_actions.handle_interaction(
            allowed_ids={"42"},
            expected_channel_id="99",
            user_id="42",
            channel_id="99",
            component_custom_id=discord_airdrop_actions.custom_id(
                "approve", row["request_id"]
            ),
            now=T0,
        )


def test_notice_ack_happens_only_after_successful_gateway_send(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = stage_manual()
    monkeypatch.setattr(
        discord_control,
        "_airdrop_action_view",
        lambda discord, record: object(),
    )

    class AllowedMentions:
        @staticmethod
        def none():
            return None

    class FakeDiscord:
        AllowedMentions = AllowedMentions

    class FailingChannel:
        async def send(self, *args, **kwargs):
            raise RuntimeError("discord unavailable")

    asyncio.run(
        discord_control._send_airdrop_action_notices(
            FailingChannel(),
            FakeDiscord,
        )
    )
    still_pending = airdrop_approval.get_request(row["request_id"], now=T0)
    assert still_pending["notified_at"] is None
    assert len(airdrop_approval.poll_notice_batch(now=T0)["records"]) == 1

    class SuccessChannel:
        def __init__(self):
            self.sent = 0

        async def send(self, *args, **kwargs):
            self.sent += 1
            return object()

    channel = SuccessChannel()
    asyncio.run(
        discord_control._send_airdrop_action_notices(
            channel,
            FakeDiscord,
        )
    )
    delivered = airdrop_approval.get_request(row["request_id"], now=T0)
    assert channel.sent == 1
    assert delivered["notified_at"] is not None
    assert airdrop_approval.poll_notice_batch(now=T0)["records"] == []


def test_control_component_delegates_same_user_and_channel_gate(
    isolated_state: Path,
) -> None:
    row = stage_manual()
    control = discord_control.Control({"42"}, "99")

    result = control.airdrop_component(
        "42",
        discord_airdrop_actions.custom_id("details", row["request_id"]),
        "99",
    )
    assert result["ok"] is True

    with pytest.raises(
        discord_airdrop_actions.DiscordAirdropActionError,
        match="unauthorized",
    ):
        control.airdrop_component(
            "7",
            discord_airdrop_actions.custom_id("details", row["request_id"]),
            "99",
        )


def test_gateway_has_one_client_and_component_handler() -> None:
    source = (
        core.ROOT / "src" / "flop_agent" / "discord_control.py"
    ).read_text("utf-8")
    assert source.count("discord.Client(") == 1
    assert "async def on_interaction" in source
    assert "_send_airdrop_action_notices" in source
    assert "flop-airdrop" not in source


def test_interaction_policy_has_no_transport_signer_or_secret_access() -> None:
    source = (
        core.ROOT / "src" / "flop_agent" / "discord_airdrop_actions.py"
    ).read_text("utf-8").lower()
    assert "httpx" not in source
    assert "discord_bot_token" not in source
    assert "oracle_signer" not in source
    assert "technocore_signing_key" not in source
    assert "subprocess" not in source
    assert "socket" not in source
