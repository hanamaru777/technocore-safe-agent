from datetime import UTC, datetime, timedelta

from flop_agent import autopilot, collaboration, core, discord_collaboration, discord_control, discord_outcome_scorecard, observer, resident


INBOUND = "\u53d7\u4fe1"
OUTBOUND = "\u9001\u4fe1"


def _activity(*, problems=None):
    return {
        "snapshot": {
            "problems": problems or [], "health": "ok", "critical": 0,
            "direct": 0, "last_refresh_age": "10 seconds ago",
            "auto": {"enabled": True, "paused": False, "queued": 0},
        },
        "posts": 0, "eligible": 0, "ignored": 0, "blocked": 0,
        "reasons": {}, "zero_reason": "none",
        "received": [], "sent": [], "counterparts": 1, "latest_post": None,
        "trusted": [], "trust_candidates": [], "bootstrap_pending": [],
        "oldest_unresolved_direct": None,
        "interactions": [{
            "direction": INBOUND, "at": "2026-09-14T00:12:00+00:00",
            "fingerprint": "abcdef123456", "display_label": "Useful Agent",
            "summary": "Can you explain nonce safety?", "room": "lobby", "seq": 8,
        }],
    }


def test_counterpart_label_prefers_persisted_safe_label_and_falls_back_to_fingerprint():
    assert discord_control.counterpart_label({"fingerprint": "abcdef123456", "display_label": "Alice"}) == "Alice"
    assert discord_control.counterpart_label({"fingerprint": "abcdef123456"}) == "abcdef12"


def test_mission_command_is_authorized_and_renders_human_timeline(monkeypatch):
    activity = _activity()
    monkeypatch.setattr(discord_control, "activity_snapshot", lambda **_kwargs: activity)
    control = discord_control.Control({"42"}, "99")
    assert control.command("7", "/mission", "99")["error"] == "unauthorized"
    message = control.command("42", "/mission", "99")["message"]
    assert "FLOP AGENT MISSION CONTROL" in message
    assert "Useful Agent \u2192 MARU Agent: Can you explain nonce safety?" in message
    assert "MARU" in message


def test_status_is_mission_first_normally_but_critical_safety_stays_first(monkeypatch):
    normal = _activity()
    monkeypatch.setattr(discord_control, "activity_snapshot", lambda **_kwargs: normal)
    normal_message = discord_control.status_message()
    assert normal_message.index("FLOP AGENT MISSION CONTROL") < normal_message.index("\u76e3\u8996:")

    critical = _activity(problems=["Autopilot OFF"])
    monkeypatch.setattr(discord_control, "activity_snapshot", lambda **_kwargs: critical)
    critical_message = discord_control.status_message()
    assert critical_message.index("\u7570\u5e38: Autopilot OFF") < critical_message.index("FLOP AGENT MISSION CONTROL")


def test_status_mission_action_uses_same_trust_snapshot(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    state = resident.default_state()
    state["cached_observer"] = {"health": {"current": "ok"}, "cursors": {}}
    state["daemon"]["last_refresh_at"] = datetime.now(UTC).isoformat()
    state["candidates"] = {"bootstrap-1": {
        "candidate_id": "bootstrap-1", "status": "approved", "fingerprint": "abc123456789",
        "did": "did:key:z", "room": "lobby", "seq": 1, "category": "conversation",
        "created_at": datetime.now(UTC).isoformat(), "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "signals": {"direct_public_signed": True}, "context": {"excerpt": "Can you explain nonce safety?"},
    }}
    state["relationships"] = {"abc123456789": {"approval_rejection_history": [{"candidate_id": "bootstrap-1", "decision": "approved"}]}}
    resident.save_state(state)
    auto = {"enabled": True, "paused": False, "outbox": {}, "receipts": {}, "rate_history": []}
    monkeypatch.setattr(autopilot, "load", lambda: auto)
    monkeypatch.setattr(autopilot, "status", lambda _state=None: {"enabled": True, "paused": False, "queued": 0, "receipts": 0})
    monkeypatch.setattr(autopilot, "durable_publication_at", lambda *_args: False)
    monkeypatch.setattr(autopilot, "active_trusted_relationships", lambda *_args: [])
    message = discord_control.status_message()
    assert "/reply-approved bootstrap-1 SEND" in message
    assert "\u4f55\u3082\u3057\u306a\u304f\u3066OK" not in message


def test_mission_goal_is_specific_for_direct_request_and_collaboration(monkeypatch):
    direct = _activity()
    direct["oldest_unresolved_direct"] = {"fingerprint": "direct123456", "room": "lobby", "seq": 7}
    monkeypatch.setattr(collaboration, "records", lambda **_kwargs: [])
    direct_message = discord_control.mission_message(direct)
    assert "direct12" in direct_message and "\u76f4\u63a5\u4f9d\u983c" in direct_message

    collab_activity = _activity()
    collab_activity["interactions"] = []
    monkeypatch.setattr(collaboration, "records", lambda **_kwargs: [{
        "fingerprint": "collab123456", "stage": "active",
        "task_summary": "Review the bounded public test result.",
    }])
    collab_message = discord_control.mission_message(collab_activity)
    assert "Review the bounded public test result." in collab_message


def test_production_scorecard_keeps_same_status_ordering(monkeypatch):
    normal = _activity()
    normal.update({"signed_direct_requests": 0, "acked_replies": 0, "active_trusted": 0, "collaboration_active": 0, "collaboration_completed": 0, "public_artifacts": 0})
    monkeypatch.setattr(discord_outcome_scorecard, "_activity_snapshot", lambda **_kwargs: normal)
    rendered = discord_outcome_scorecard._status_message()
    assert rendered.index("FLOP AGENT MISSION CONTROL") < rendered.index("\u76e3\u8996:")


def test_collaboration_notice_uses_persisted_interaction_label_and_fallback(monkeypatch):
    monkeypatch.setattr(discord_collaboration.base, "sync_interactions", lambda: [{
        "fingerprint": "abcdef123456", "display_label": "Helpful Agent",
    }])
    message = discord_collaboration._notice_message({
        "id": "collab1", "stage": "replied", "fingerprint": "abcdef123456",
        "task_summary": "I can reproduce the test failure.",
    })
    assert "Helpful Agent replied" in message
    assert "Helpful Agent \u2192 MARU Agent" in message
    assert "State:" in message and "Waiting on: Agent" in message
    assert "MARU:" in message

    monkeypatch.setattr(discord_collaboration.base, "sync_interactions", lambda: [])
    fallback = discord_collaboration._notice_message({"id": "collab2", "stage": "replied", "fingerprint": "abcdef123456"})
    assert "abcdef12 replied" in fallback


def test_collaboration_detail_leads_with_state_dialogue_waiting_and_next(monkeypatch):
    record = {
        "id": "collab1", "stage": "human_review", "fingerprint": "abcdef123456",
        "display_label": "Helpful Agent", "room": "lobby", "source_seq": 9,
        "task_summary": "Please review the bounded test result.", "next_action": "review_task",
    }
    monkeypatch.setattr(discord_collaboration.collaboration, "get", lambda *_args, **_kwargs: record)
    monkeypatch.setattr(discord_collaboration.base, "sync_interactions", lambda: [
        {"fingerprint": "abcdef123456", "direction": INBOUND, "summary": "Please review the test.", "at": "2026-09-14T00:00:00+00:00"},
        {"fingerprint": "abcdef123456", "direction": OUTBOUND, "summary": "Use the public test result.", "exact_text": True, "at": "2026-09-14T00:01:00+00:00"},
    ])
    message = discord_collaboration._detail_message("collab1")
    assert "Helpful Agent" in message
    assert "Helpful Agent \u2192 MARU Agent: Please review the test." in message
    assert "MARU Agent \u2192" in message and "Use the public test result." in message
    assert "State:" in message and "Waiting on: MARU" in message
    assert "next: /collab collab1" in message
