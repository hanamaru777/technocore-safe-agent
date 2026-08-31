from flop_agent import autopilot, core, discord_control, observer, resident


def setup_state(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    state = resident.default_state()
    state["cached_observer"] = {
        "health": {"current": "ok"},
        "cursors": {},
        "message_gaps": 0,
        "discovery_queue": 0,
        "agents_known": 5000,
        "returning_agents": 42,
        "inbound": 0,
    }
    state["metrics"]["noise_ignored"] = 247
    resident.save_state(state)
    return state


def candidate(candidate_id, *, priority="high", direct=False, excerpt="hello"):
    return {
        "candidate_id": candidate_id,
        "status": "pending",
        "priority": priority,
        "category": "specific_question",
        "fingerprint": "abc123",
        "room": "lobby",
        "seq": 99,
        "signals": {
            "direct_public_signed": direct,
            "useful_agent_probability": 0.72,
            "spam_noise_probability": 0.08,
        },
        "context": {"excerpt": excerpt, "untrusted": True},
    }


def test_candidate_message_removes_urls_and_explains_signal():
    item = candidate("c1", excerpt="earn refs at https://example.invalid/?ref=abc now")
    message = discord_control.candidate_message(item)
    assert "https://" not in message
    assert "[URL省略]" in message
    assert "具体的な質問" in message
    assert "有用度 72%" in message
    assert "ノイズ 8%" in message
    assert "/candidate c1" in message


def test_notifications_ignore_generic_high_but_keep_critical_and_direct(monkeypatch, tmp_path):
    state = setup_state(monkeypatch, tmp_path)
    state["candidates"] = {
        "generic": candidate("generic", priority="high"),
        "critical": candidate("critical", priority="critical"),
        "direct": candidate("direct", priority="medium", direct=True),
    }
    resident.save_state(state)
    control = discord_control.Control({"42"}, "99")
    ids = {item["candidate_id"] for item in control.notifications()}
    assert ids == {"critical", "direct"}
    assert control.notifications() == []


def test_digest_is_human_readable_and_action_oriented(monkeypatch, tmp_path):
    setup_state(monkeypatch, tmp_path)
    monkeypatch.setattr(autopilot, "status", lambda: {"enabled": True, "paused": False, "queued": 0, "receipts": 1})
    message = discord_control.Control({"42"}, "99").digest()
    assert "🟢 FLOP Agent 1時間レポート" in message
    assert "Agent 5000" in message
    assert "Autopilot ON" in message
    assert "投稿記録 1" in message
    assert "今すぐ対応不要" in message
    assert "gap" not in message
    assert "discovery" not in message
