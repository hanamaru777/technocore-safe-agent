from flop_agent import discord_collaboration, discord_control, discord_outcome_scorecard


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


def test_production_scorecard_keeps_same_status_ordering(monkeypatch):
    normal = _activity()
    normal.update({"signed_direct_requests": 0, "acked_replies": 0, "active_trusted": 0, "collaboration_active": 0, "collaboration_completed": 0, "public_artifacts": 0})
    monkeypatch.setattr(discord_outcome_scorecard, "_activity_snapshot", lambda **_kwargs: normal)
    rendered = discord_outcome_scorecard._status_message()
    assert rendered.index("FLOP AGENT MISSION CONTROL") < rendered.index("\u76e3\u8996:")


def test_collaboration_notice_is_self_contained_and_human_first():
    message = discord_collaboration._notice_message({
        "id": "collab1", "stage": "replied", "fingerprint": "abcdef123456",
        "display_label": "Helpful Agent", "task_summary": "I can reproduce the test failure.",
    })
    assert "Helpful Agent replied" in message
    assert "Helpful Agent \u2192 MARU Agent" in message
    assert "State:" in message and "Waiting on: Agent" in message
    assert "MARU:" in message


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
