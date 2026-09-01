from datetime import UTC, datetime, timedelta

from flop_agent import autopilot, core, discord_control, observer, resident


def setup_state(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    observed = observer.default_state()
    observed["metrics"]["unique_dids_discovered"] = 100
    observed["metrics"]["returning_did_encounters"] = 20
    observed["metrics"]["message_gaps"] = 0
    observer.save_state(observed)
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
    state["daemon"]["last_refresh_at"] = datetime.now(UTC).isoformat()
    state["metrics"]["noise_ignored"] = 247
    resident.save_state(state)
    return state


def mock_autopilot(monkeypatch, *, enabled=True, paused=False, queued=0, receipts=1, rate_history=None):
    auto_state = {
        "schema_version": 1,
        "enabled": enabled,
        "paused": paused,
        "outbox": {},
        "receipts": {},
        "rate_history": rate_history or [],
        "migrated_at": "done",
    }
    monkeypatch.setattr(autopilot, "load", lambda: auto_state)
    monkeypatch.setattr(autopilot, "status", lambda state=None: {"enabled": enabled, "paused": paused, "queued": queued, "receipts": receipts, "migration_complete": True})
    return auto_state


def candidate(candidate_id, *, priority="high", direct=False, excerpt="hello"):
    return {
        "candidate_id": candidate_id,
        "status": "pending",
        "priority": priority,
        "category": "specific_question",
        "fingerprint": "abc123",
        "did": "did:key:z6MkOther",
        "room": "lobby",
        "seq": 99,
        "created_at": "2026-08-31T12:00:00+00:00",
        "signals": {
            "direct_public_signed": direct,
            "conversation_topic": "repo_safety" if direct else None,
            "useful_agent_probability": 0.72,
            "spam_noise_probability": 0.08,
        },
        "context": {"excerpt": excerpt, "untrusted": True},
    }


def test_candidate_message_is_actionable_and_sanitizes_untrusted_content(monkeypatch, tmp_path):
    setup_state(monkeypatch, tmp_path)
    item = candidate("c1", direct=True, excerpt="@everyone earn refs at https://example.invalid/?ref=abc now")
    message = discord_control.candidate_message(item)
    assert "https://" not in message
    assert "[URL省略]" in message
    assert "@everyone" not in message
    assert "あなたのDID宛" in message
    assert "有用度 高" in message
    assert "ノイズ 低" in message
    assert "次にやること: /candidate c1" in message
    assert "72%" not in message


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


def test_status_is_human_first_and_hides_internal_counters(monkeypatch, tmp_path):
    setup_state(monkeypatch, tmp_path); mock_autopilot(monkeypatch)
    message = discord_control.status_message()
    assert "🟢 FLOP Agent 正常" in message
    assert "Autopilot: ON / queue 0" in message
    assert "最終監視:" in message
    assert "結論: 対応不要" in message
    assert "agents=5000" not in message
    assert "pending=" not in message
    assert "gaps=" not in message


def test_history_records_when_who_and_what(monkeypatch, tmp_path):
    state = setup_state(monkeypatch, tmp_path); mock_autopilot(monkeypatch)
    state["candidates"] = {"direct": candidate("direct", priority="medium", direct=True, excerpt="ignored-context")}
    resident.save_state(state)
    observed = observer.load_state()
    observed["agents"]["abc123"] = {
        "did": "did:key:z6MkOther",
        "fingerprint": "abc123",
        "facts": {
            "recent_messages": [{"room": "lobby", "seq": 99, "ts": "2026-08-31T12:00:00Z", "text": "Can you review repo safety? https://bad.invalid", "signed": True}],
        },
        "inferences": {},
    }
    observer.save_state(observed)
    message = discord_control.history_message()
    assert "最近のやりとり" in message
    assert "受信 | abc123" in message
    assert "lobby #99" in message
    assert "Can you review repo safety?" in message
    assert "https://bad.invalid" not in message
    assert "[URL省略]" in message


def test_digest_uses_six_hour_deltas_not_cumulative_noise(monkeypatch, tmp_path):
    setup_state(monkeypatch, tmp_path); mock_autopilot(monkeypatch)
    control = discord_control.Control({"42"}, "99")
    control.ensure_baseline()
    observed = observer.load_state()
    observed["metrics"]["unique_dids_discovered"] = 112
    observed["metrics"]["returning_did_encounters"] = 23
    observer.save_state(observed)
    message = control.digest()
    assert "FLOP Agent 6時間レポート" in message
    assert "新規Agent +12" in message
    assert "再会 +3" in message
    assert "ノイズ除外" not in message
    assert "Agent 5000" not in message
    assert "今すぐ対応不要" not in message
    assert "対応不要。そのまま稼働中" in message


def test_gap_burst_and_autopilot_problem_are_immediate_once(monkeypatch, tmp_path):
    setup_state(monkeypatch, tmp_path); mock_autopilot(monkeypatch)
    control = discord_control.Control({"42"}, "99")
    control.ensure_baseline()
    observed = observer.load_state(); observed["metrics"]["message_gaps"] = 3; observer.save_state(observed)
    notices = control.system_notices()
    assert any("通信欠落" in notice and "未通知gap: +3" in notice for notice in notices)
    assert not any("通信欠落" in notice for notice in control.system_notices())

    mock_autopilot(monkeypatch, paused=True)
    notices = control.system_notices()
    assert any("🔴 FLOP Agent 異常" in notice and "Autopilot 一時停止" in notice for notice in notices)
    assert not any("🔴 FLOP Agent 異常" in notice for notice in control.system_notices())

    mock_autopilot(monkeypatch, enabled=False, paused=True)
    notices = control.system_notices()
    assert any("🔴 FLOP Agent 異常" in notice and "Autopilot OFF" in notice for notice in notices)


def test_transient_observer_degraded_is_silent_and_status_is_immediate(monkeypatch, tmp_path):
    state = setup_state(monkeypatch, tmp_path); mock_autopilot(monkeypatch)
    control = discord_control.Control({"42"}, "99")
    state["cached_observer"]["health"] = {"current": "degraded"}; resident.save_state(state)
    assert not control.system_notices()
    assert "監視状態 degraded" in discord_control.status_message()
    state["cached_observer"]["health"] = {"current": "ok"}; resident.save_state(state)
    assert not control.system_notices()


def test_persistent_observer_degraded_alerts_once_then_recovers_once(monkeypatch, tmp_path):
    state = setup_state(monkeypatch, tmp_path); mock_autopilot(monkeypatch)
    control = discord_control.Control({"42"}, "99")
    state["cached_observer"]["health"] = {"current": "degraded"}; resident.save_state(state)
    assert not control.system_notices()
    ui = discord_control.load_ui_state()
    ui["observer_degraded_since"] = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    discord_control.save_ui_state(ui)
    notices = control.system_notices()
    assert len([notice for notice in notices if "監視状態 degraded が5分以上" in notice]) == 1
    assert not control.system_notices()
    state["cached_observer"]["health"] = {"current": "ok"}; resident.save_state(state)
    notices = control.system_notices()
    assert len([notice for notice in notices if "監視復旧" in notice]) == 1
    assert not control.system_notices()


def test_stale_resident_health_remains_immediate(monkeypatch, tmp_path):
    state = setup_state(monkeypatch, tmp_path); mock_autopilot(monkeypatch)
    control = discord_control.Control({"42"}, "99")
    state["daemon"]["last_refresh_at"] = (datetime.now(UTC) - timedelta(minutes=4)).isoformat(); resident.save_state(state)
    notices = control.system_notices()
    assert any("最終監視" in notice and "🔴 FLOP Agent 異常" in notice for notice in notices)

    state["daemon"]["last_refresh_at"] = (datetime.now(UTC) - timedelta(minutes=5)).isoformat(); resident.save_state(state)
    assert not any("🔴 FLOP Agent 異常" in notice for notice in control.system_notices())

    state["daemon"]["last_refresh_at"] = datetime.now(UTC).isoformat(); resident.save_state(state)
    notices = control.system_notices()
    assert len([notice for notice in notices if "🟢 FLOP Agent 復旧" in notice]) == 1
    assert not control.system_notices()


def test_legacy_health_display_migrates_to_stable_incident_key(monkeypatch, tmp_path):
    state = setup_state(monkeypatch, tmp_path); mock_autopilot(monkeypatch)
    state["daemon"]["last_refresh_at"] = (datetime.now(UTC) - timedelta(minutes=4)).isoformat(); resident.save_state(state)
    legacy = discord_control.default_ui_state()
    legacy.pop("health_incident_keys")
    legacy["last_health_problem"] = "最終監視 4分前"
    discord_control.save_ui_state(legacy)
    control = discord_control.Control({"42"}, "99")
    assert not any("🔴 FLOP Agent 異常" in notice for notice in control.system_notices())
    assert discord_control.load_ui_state()["health_incident_keys"] == ["resident_stale"]


def test_health_incident_transitions_do_not_emit_partial_recovery(monkeypatch, tmp_path):
    setup_state(monkeypatch, tmp_path)
    control = discord_control.Control({"42"}, "99")
    mock_autopilot(monkeypatch, paused=True)
    assert any("Autopilot 一時停止" in notice for notice in control.system_notices())

    mock_autopilot(monkeypatch, enabled=False, paused=True)
    notices = control.system_notices()
    assert any("Autopilot OFF" in notice and "🔴 FLOP Agent 異常" in notice for notice in notices)
    assert not any("🟢 FLOP Agent 復旧" in notice or "対応不要。そのまま稼働中" in notice for notice in notices)

    mock_autopilot(monkeypatch, paused=True)
    notices = control.system_notices()
    assert any("Autopilot 一時停止" in notice and "🔴 FLOP Agent 異常" in notice for notice in notices)
    assert not any("🟢 FLOP Agent 復旧" in notice or "対応不要。そのまま稼働中" in notice for notice in notices)


def test_only_final_health_incident_resolution_notifies_recovery(monkeypatch, tmp_path):
    state = setup_state(monkeypatch, tmp_path)
    control = discord_control.Control({"42"}, "99")
    state["daemon"]["last_refresh_at"] = (datetime.now(UTC) - timedelta(minutes=4)).isoformat(); resident.save_state(state)
    mock_autopilot(monkeypatch, paused=True)
    assert any("🔴 FLOP Agent 異常" in notice for notice in control.system_notices())

    state["daemon"]["last_refresh_at"] = datetime.now(UTC).isoformat(); resident.save_state(state)
    assert not any("🟢 FLOP Agent 復旧" in notice or "対応不要。そのまま稼働中" in notice for notice in control.system_notices())

    mock_autopilot(monkeypatch)
    notices = control.system_notices()
    assert len([notice for notice in notices if "🟢 FLOP Agent 復旧" in notice]) == 1
    assert not control.system_notices()


def test_help_keeps_daily_surface_small(monkeypatch, tmp_path):
    setup_state(monkeypatch, tmp_path); mock_autopilot(monkeypatch)
    control = discord_control.Control({"42"}, "99")
    message = control.command("42", "/help", "99")["message"]
    assert "/status" in message and "/history" in message and "/candidate" in message
    assert "/intel" not in message and "/agents" not in message
    debug = control.command("42", "/help-debug", "99")["message"]
    assert "/intel" in debug and "/agents" in debug
