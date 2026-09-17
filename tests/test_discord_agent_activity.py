import json
from pathlib import Path

import pytest

from flop_agent import discord_agent_activity as activity


@pytest.fixture
def state_root(monkeypatch, tmp_path):
    monkeypatch.setattr(activity.core, "STATE", tmp_path)
    monkeypatch.setattr(activity, "verify_signed_record", lambda room, row: None)
    return tmp_path


def empty_rooms(room, **kwargs):
    assert kwargs["limit"] == 200
    assert kwargs["cache_buster"]
    return {"messages": []}


def write_activity(root: Path, value: dict) -> None:
    (root / "activities.jsonl").write_text(
        json.dumps(value, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def mitsuri_payload() -> str:
    return json.dumps(
        {
            "type": "sonnet.application.v1",
            "request_id": activity.MITSURI_REQUEST_ID,
            "target_did": activity.MITSURI_DID,
            "text": "Hey, Mitsuri's Agent 👋 MARU here.",
        },
        ensure_ascii=False,
    )


def test_backfills_posted_mitsuri_send_once_from_shared_activity(state_root):
    write_activity(
        state_root,
        {
            "action": "sonnet_mitsuri_contact",
            "did": activity.MARU_DID,
            "room": activity.DISCOVERY_ROOM,
            "seq": 104521,
            "ts": "2026-09-15T10:03:26.255754Z",
            "text": mitsuri_payload(),
        },
    )
    notices = activity.poll_notices(room_read=empty_rooms)
    assert len(notices) == 1
    assert "📤 Agent送信" in notices[0]
    assert "Mitsuri Agent" in notices[0]
    assert activity.MITSURI_REQUEST_ID in notices[0]
    assert "104521" in notices[0]
    assert "再送不要" in notices[0]
    assert activity.poll_notices(room_read=empty_rooms) == []


def test_public_self_send_is_outbound_fallback_and_dedupes_shared_audit(state_root):
    row = {
        "from": activity.MARU_DID,
        "seq": 104521,
        "ts": "2026-09-15T10:03:26.255754Z",
        "nonce": "1",
        "sig": "x",
        "text": mitsuri_payload(),
    }
    write_activity(
        state_root,
        {
            "action": "sonnet_mitsuri_contact",
            "did": activity.MARU_DID,
            "room": activity.DISCOVERY_ROOM,
            "seq": 104521,
            "ts": row["ts"],
            "text": row["text"],
        },
    )

    def read(room, **kwargs):
        return {"messages": [row]} if room == activity.DISCOVERY_ROOM else {"messages": []}

    notices = activity.poll_notices(room_read=read)
    assert len(notices) == 1
    assert "📤 Agent送信" in notices[0]
    assert "104521" in notices[0]
    assert activity.poll_notices(room_read=read) == []


def test_signed_inbound_targeting_maru_notifies_once(state_root):
    row = {
        "from": activity.MITSURI_DID,
        "seq": 104600,
        "ts": "2026-09-15T10:10:00Z",
        "nonce": "2",
        "sig": "x",
        "text": json.dumps(
            {
                "type": "sonnet.reply.v1",
                "target_did": activity.MARU_DID,
                "request_id": activity.MITSURI_REQUEST_ID,
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
        "nonce": "3",
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
        "seq": 104700,
        "ts": "2026-09-15T10:12:00Z",
        "nonce": "4",
        "sig": "x",
        "text": json.dumps(
            {
                "type": "sonnet.reply.v1",
                "target_did": "did:key:z6MkElse",
                "text": "hello",
            }
        ),
    }

    def read(room, **kwargs):
        return {"messages": [row]}

    assert activity.poll_notices(room_read=read) == []


def test_pre_cockpit_history_is_not_replayed(state_root):
    write_activity(
        state_root,
        {
            "action": "old",
            "did": activity.MARU_DID,
            "room": activity.DISCOVERY_ROOM,
            "seq": 99999,
            "ts": "2026-09-15T09:59:00Z",
            "text": json.dumps({"request_id": "old", "text": "old message"}),
        },
    )
    assert activity.poll_notices(room_read=empty_rooms) == []


def test_repeated_open_seat_pings_are_semantically_deduped(state_root):
    sender = "did:key:z6MkForumLeader"
    rows = []
    for seq, request_id in ((129435, "ping-1"), (129444, "ping-2"), (129451, "ping-3")):
        rows.append(
            {
                "from": sender,
                "seq": seq,
                "ts": "2026-09-17T08:27:00Z",
                "nonce": str(seq),
                "sig": "x",
                "text": json.dumps(
                    {
                        "type": "sonnet.reply.v1",
                        "target_did": activity.MARU_DID,
                        "request_id": request_id,
                        "text": "TEAM ForumEvi-Poets open seat! Equal split. Reply yes-ForumEvi-Poets with your DID to join.",
                    }
                ),
            }
        )

    def read(room, **kwargs):
        return {"messages": rows} if room == activity.DISCOVERY_ROOM else {"messages": []}

    notices = activity.poll_notices(room_read=read)
    assert len(notices) == 1
    assert "📨 Sonnetチーム参加募集" in notices[0]
    assert "ForumEvi-Poets" in notices[0]
    assert "返信不要" in notices[0]
    assert "自動同意はしていません" in notices[0]
    assert "ping-" not in notices[0]
    assert activity.MARU_DID not in notices[0]
    assert activity.poll_notices(room_read=read) == []


def test_repeated_roster_churn_same_generation_is_one_human_notice(state_root):
    sender = "did:key:z6MkForumLeader"
    other_a = "did:key:z6MkOtherA"
    other_b = "did:key:z6MkOtherB"
    rows = []
    for seq, request_id, fourth in (
        (129440, "roster-1", other_a),
        (129454, "roster-2", other_b),
        (129477, "roster-3", other_a),
    ):
        rows.append(
            {
                "from": sender,
                "seq": seq,
                "ts": "2026-09-17T08:28:00Z",
                "nonce": str(seq),
                "sig": "x",
                "text": json.dumps(
                    {
                        "type": "sonnet.roster.v1",
                        "contest_id": "sonnet-2",
                        "game_id": "ForumEvi-Poets",
                        "poem_room": "d-sonnet-2-team-forumevi-poets",
                        "room_generation": 1,
                        "members": [sender, activity.MARU_DID, "did:key:z6MkOtherC", fourth],
                        "request_id": request_id,
                    }
                ),
            }
        )

    def read(room, **kwargs):
        return {"messages": rows} if room == activity.DISCOVERY_ROOM else {"messages": []}

    notices = activity.poll_notices(room_read=read)
    assert len(notices) == 1
    assert "👥 Sonnetチーム候補" in notices[0]
    assert "ForumEvi-Poets" in notices[0]
    assert "候補 4名" in notices[0]
    assert "正式承認でもMARUの同意でもありません" in notices[0]
    assert "members" not in notices[0]
    assert "roster-" not in notices[0]
    assert activity.MARU_DID not in notices[0]
    assert other_a not in notices[0]
    assert other_b not in notices[0]
    assert activity.poll_notices(room_read=read) == []


def test_roster_new_generation_can_notify_again(state_root):
    sender = "did:key:z6MkForumLeader"

    def row(seq, generation):
        return {
            "from": sender,
            "seq": seq,
            "ts": "2026-09-17T08:30:00Z",
            "nonce": str(seq),
            "sig": "x",
            "text": json.dumps(
                {
                    "type": "sonnet.roster.v1",
                    "contest_id": "sonnet-2",
                    "game_id": "ForumEvi-Poets",
                    "poem_room": "d-sonnet-2-team-forumevi-poets",
                    "room_generation": generation,
                    "members": [sender, activity.MARU_DID, "did:key:z6MkOtherC", "did:key:z6MkOtherD"],
                    "request_id": f"roster-generation-{generation}",
                }
            ),
        }

    current = [row(129500, 1)]

    def read(room, **kwargs):
        return {"messages": current} if room == activity.DISCOVERY_ROOM else {"messages": []}

    first = activity.poll_notices(room_read=read)
    assert len(first) == 1
    current[:] = [row(129700, 2)]
    second = activity.poll_notices(room_read=read)
    assert len(second) == 1
    assert "ForumEvi-Poets" in second[0]


def test_retains_audited_discord_entrypoint_and_wires_activity_layer():
    service = Path("packaging/oracle/discord.service").read_text("utf-8")
    health = Path("src/flop_agent/discord_health_coalescing.py").read_text("utf-8")
    source = Path("src/flop_agent/discord_agent_activity.py").read_text("utf-8")
    assert "ExecStart=/opt/technocore-safe-agent/.venv/bin/python -m flop_agent.discord_tclk_approval" in service
    assert "discord_agent_activity.poll_notices()" in health
    assert "activities.jsonl" in source
    assert 'core.STATE / "signer"' not in source
    assert "httpx.post" not in source
    assert "/export" not in source
    assert "lobby-capture-service.sqlite3" not in source
    assert "NoNewPrivileges=true" in service
