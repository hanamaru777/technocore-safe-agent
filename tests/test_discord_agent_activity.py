import json
from pathlib import Path

import pytest

from flop_agent import discord_agent_activity as activity


@pytest.fixture
def state_root(monkeypatch, tmp_path):
    monkeypatch.setattr(activity.core, "STATE", tmp_path)
    (tmp_path / "signer").mkdir(parents=True)
    monkeypatch.setattr(activity, "verify_signed_record", lambda room, row: None)
    return tmp_path


def empty_rooms(room, **kwargs):
    assert kwargs["limit"] == 200
    assert kwargs["cache_buster"]
    return {"messages": []}


def test_backfills_posted_mitsuri_send_once(state_root):
    path = state_root / "signer" / "sonnet-2-mitsuri-contact.json"
    path.write_text(
        json.dumps(
            {
                "state": "posted",
                "request_id": "maru-mitsuri-contact-20260915-1",
                "seq": 104521,
                "ts": "2026-09-15T10:03:26.255754Z",
                "target_did": activity.MITSURI_DID,
                "payload": {
                    "request_id": "maru-mitsuri-contact-20260915-1",
                    "target_did": activity.MITSURI_DID,
                    "text": "Hey, Mitsuri's Agent 👋 MARU here.",
                },
            }
        ),
        encoding="utf-8",
    )
    notices = activity.poll_notices(room_read=empty_rooms)
    assert len(notices) == 1
    assert "📤 Agent送信" in notices[0]
    assert "Mitsuri Agent" in notices[0]
    assert "104521" in notices[0]
    assert "再送不要" in notices[0]
    assert activity.poll_notices(room_read=empty_rooms) == []


def test_signed_inbound_targeting_maru_notifies_once(state_root):
    row = {
        "from": activity.MITSURI_DID,
        "seq": 104600,
        "ts": "2026-09-15T10:10:00Z",
        "nonce": "1",
        "sig": "x",
        "text": json.dumps(
            {
                "type": "sonnet.reply.v1",
                "target_did": activity.MARU_DID,
                "text": "There is still a seat. Send me your roster consent when ready.",
            }
        ),
    }

    def read(room, **kwargs):
        return {"messages": [row]} if room == activity.DISCOVERY_ROOM else {"messages": []}

    notices = activity.poll_notices(room_read=read)
    assert len(notices) == 1
    assert "📥 Agent受信" in notices[0]
    assert "Mitsuri Agent" in notices[0]
    assert "自動同意はしていません" in notices[0]
    assert activity.poll_notices(room_read=read) == []


def test_referee_record_involving_maru_is_official_notice(state_root):
    row = {
        "from": activity.REFEREE_DID,
        "seq": 777,
        "ts": "2026-09-15T10:11:00Z",
        "nonce": "2",
        "sig": "x",
        "text": json.dumps(
            {
                "type": "sonnet.setup.v1",
                "contest_id": "sonnet-2",
                "game_id": "mitsuri-second",
                "members": [activity.MARU_DID],
                "text": "setup accepted",
            }
        ),
    }

    def read(room, **kwargs):
        return {"messages": [row]} if room == activity.RESULTS_ROOM else {"messages": []}

    notices = activity.poll_notices(room_read=read)
    assert len(notices) == 1
    assert "🏛️ Sonnet公式更新" in notices[0]
    assert "mitsuri-second" in notices[0]
    assert "要確認" in notices[0]


def test_unrelated_signed_room_activity_is_ignored(state_root):
    row = {
        "from": "did:key:z6MkOther",
        "seq": 12,
        "ts": "2026-09-15T10:12:00Z",
        "nonce": "3",
        "sig": "x",
        "text": json.dumps({"type": "sonnet.reply.v1", "target_did": "did:key:z6MkElse", "text": "hello"}),
    }

    def read(room, **kwargs):
        return {"messages": [row]}

    assert activity.poll_notices(room_read=read) == []


def test_retains_audited_discord_entrypoint_and_wires_activity_layer():
    service = Path("packaging/oracle/discord.service").read_text("utf-8")
    health = Path("src/flop_agent/discord_health_coalescing.py").read_text("utf-8")
    source = Path("src/flop_agent/discord_agent_activity.py").read_text("utf-8")
    assert "ExecStart=/opt/technocore-safe-agent/.venv/bin/python -m flop_agent.discord_tclk_approval" in service
    assert "discord_agent_activity.poll_notices()" in health
    assert "httpx.post" not in source
    assert "/export" not in source
    assert "lobby-capture-service.sqlite3" not in source
    assert "NoNewPrivileges=true" in service
