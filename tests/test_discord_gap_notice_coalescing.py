from datetime import UTC, datetime

from flop_agent import autopilot, core, discord_control, observer, resident


def setup_runtime(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    observed = observer.default_state()
    observed["metrics"].update(
        {
            "message_gaps": 0,
            "unrecoverable_core_gap_events": 0,
            "unrecoverable_core_gap_messages": 0,
            "unrecoverable_optional_gap_events": 0,
            "unrecoverable_optional_gap_messages": 0,
        }
    )
    observer.save_state(observed)

    local = resident.default_state()
    local["cached_observer"] = {
        "health": {"current": "ok"},
        "cursors": {},
        "message_gaps": 0,
        "discovery_queue": 0,
        "agents_known": 0,
        "returning_agents": 0,
        "inbound": 0,
    }
    local["daemon"]["last_refresh_at"] = datetime.now(UTC).isoformat()
    resident.save_state(local)

    auto_state = {
        "schema_version": 1,
        "enabled": True,
        "paused": False,
        "outbox": {},
        "receipts": {},
        "rate_history": [],
        "migrated_at": "done",
    }
    monkeypatch.setattr(autopilot, "load", lambda: auto_state)
    monkeypatch.setattr(
        autopilot,
        "status",
        lambda state=None: {
            "enabled": True,
            "paused": False,
            "queued": 0,
            "receipts": 0,
            "migration_complete": True,
        },
    )
    return discord_control.Control({"42"}, "99")


def set_gap_counts(
    total: int,
    *,
    core: int = 0,
    optional: int = 0,
    core_messages: int = 0,
    optional_messages: int = 0,
):
    observed = observer.load_state()
    observed["metrics"]["message_gaps"] = total
    observed["metrics"]["unrecoverable_core_gap_events"] = core
    observed["metrics"]["unrecoverable_core_gap_messages"] = core_messages
    observed["metrics"]["unrecoverable_optional_gap_events"] = optional
    observed["metrics"]["unrecoverable_optional_gap_messages"] = optional_messages
    observer.save_state(observed)


def test_optional_only_gaps_are_digest_only_not_hourly_alerts(monkeypatch, tmp_path):
    control = setup_runtime(monkeypatch, tmp_path)
    control.ensure_baseline()

    set_gap_counts(3, optional=3, optional_messages=27)
    notices = control.system_notices()

    assert not any("通信欠落" in notice for notice in notices)
    assert not any("core通信" in notice for notice in notices)
    ui = discord_control.load_ui_state()
    assert ui["pending_optional_gap_delta"] == 3

    digest = control.digest()
    assert "core未回復 +0" in digest
    assert "optional lane未回復 +3" in digest
    assert "対応不要。そのまま稼働中" in digest
    assert discord_control.load_ui_state()["pending_optional_gap_delta"] == 0


def test_new_core_unrecoverable_gap_alerts_immediately_once(monkeypatch, tmp_path):
    control = setup_runtime(monkeypatch, tmp_path)
    control.ensure_baseline()

    set_gap_counts(1, core=1, core_messages=9)
    notices = control.system_notices()

    core_notices = [notice for notice in notices if "core通信" in notice]
    assert len(core_notices) == 1
    assert "新しいcore gap: +1件" in core_notices[0]
    assert "core累計: 1件 / 9 messages" in core_notices[0]
    assert "🔴" in core_notices[0]

    assert not any("core通信" in notice for notice in control.system_notices())


def test_unclassified_gap_falls_back_to_legacy_coalescing(monkeypatch, tmp_path):
    control = setup_runtime(monkeypatch, tmp_path)
    control.ensure_baseline()
    monkeypatch.setattr(discord_control, "_gap_breakdown", lambda: None)

    set_gap_counts(1)
    assert not any("lane判定不能" in notice for notice in control.system_notices())
    set_gap_counts(2)
    assert not any("lane判定不能" in notice for notice in control.system_notices())

    set_gap_counts(3)
    notices = control.system_notices()
    assert len([notice for notice in notices if "lane判定不能" in notice]) == 1
    assert "未通知gap: +3" in "\n".join(notices)

    set_gap_counts(4)
    assert not any("lane判定不能" in notice for notice in control.system_notices())


def test_empty_history_explains_that_passive_observation_is_excluded(monkeypatch, tmp_path):
    setup_runtime(monkeypatch, tmp_path)
    message = discord_control.history_message()
    assert "まだ直接のやりとり記録はありません" in message
    assert "監視しただけの他Agent会話は含めず" in message
