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


def test_readable_lane_counters_override_aggregate_only_gap_noise(monkeypatch, tmp_path):
    control = setup_runtime(monkeypatch, tmp_path)
    control.ensure_baseline()

    # Aggregate-only movement is not authoritative for unrecoverable severity.
    # When readable lane counters explain only one optional event, the remaining
    # aggregate delta must not be re-labeled as an unknown unrecoverable lane.
    set_gap_counts(4, optional=1, optional_messages=7)
    notices = control.system_notices()

    assert not any("lane判定不能" in notice for notice in notices)
    assert not any("core通信" in notice for notice in notices)
    ui = discord_control.load_ui_state()
    assert ui["pending_optional_gap_delta"] == 1
    assert ui["pending_gap_delta"] == 0


def test_aggregate_only_gap_noise_is_silent_when_lane_counters_do_not_move(monkeypatch, tmp_path):
    control = setup_runtime(monkeypatch, tmp_path)
    control.ensure_baseline()

    set_gap_counts(80, core=0, optional=0)
    notices = control.system_notices()

    assert not any("通信欠落" in notice for notice in notices)
    assert not any("core通信" in notice for notice in notices)
    ui = discord_control.load_ui_state()
    assert ui["pending_gap_delta"] == 0
    assert ui["pending_optional_gap_delta"] == 0


def test_lane_baseline_migration_drops_only_legacy_pending_presentation(monkeypatch, tmp_path):
    control = setup_runtime(monkeypatch, tmp_path)
    ui = discord_control.default_ui_state()
    ui["last_gap_count"] = 7
    ui["pending_gap_delta"] = 6
    ui["last_core_gap_count"] = None
    ui["last_optional_gap_count"] = None
    discord_control.save_ui_state(ui)

    set_gap_counts(7, core=2, optional=5, core_messages=20, optional_messages=50)
    control.ensure_baseline()

    migrated = discord_control.load_ui_state()
    assert migrated["last_core_gap_count"] == 2
    assert migrated["last_optional_gap_count"] == 5
    assert migrated["pending_gap_delta"] == 0
    assert migrated["pending_optional_gap_delta"] == 0
    assert control.system_notices() == []


def test_empty_history_explains_that_passive_observation_is_excluded(monkeypatch, tmp_path):
    setup_runtime(monkeypatch, tmp_path)
    message = discord_control.history_message()
    assert "まだ直接のやりとり記録はありません" in message
    assert "監視しただけの他Agent会話は含めず" in message


def test_ensure_baseline_clears_stale_aggregate_pending_when_lane_state_is_readable(monkeypatch, tmp_path):
    control = setup_runtime(monkeypatch, tmp_path)
    ui = discord_control.default_ui_state()
    ui["last_gap_count"] = 80
    ui["last_core_gap_count"] = 0
    ui["last_optional_gap_count"] = 0
    ui["pending_gap_delta"] = 12
    ui["pending_optional_gap_delta"] = 2
    discord_control.save_ui_state(ui)

    set_gap_counts(80, core=0, optional=0)
    control.ensure_baseline()

    migrated = discord_control.load_ui_state()
    assert migrated["pending_gap_delta"] == 0
    assert migrated["pending_optional_gap_delta"] == 2
    assert control.system_notices() == []
