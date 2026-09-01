from datetime import UTC, datetime

from flop_agent import autopilot, core, discord_control, observer, resident


def setup_runtime(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    observed = observer.default_state()
    observed["metrics"]["message_gaps"] = 0
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


def set_gap_count(value):
    observed = observer.load_state()
    observed["metrics"]["message_gaps"] = value
    observer.save_state(observed)


def test_single_gap_events_are_coalesced_before_discord_alert(monkeypatch, tmp_path):
    control = setup_runtime(monkeypatch, tmp_path)
    control.ensure_baseline()

    set_gap_count(1)
    assert not any("通信欠落" in notice for notice in control.system_notices())
    set_gap_count(2)
    assert not any("通信欠落" in notice for notice in control.system_notices())

    set_gap_count(3)
    notices = control.system_notices()
    assert len([notice for notice in notices if "通信欠落" in notice]) == 1
    assert "未通知gap: +3" in "\n".join(notices)

    set_gap_count(4)
    assert not any("通信欠落" in notice for notice in control.system_notices())


def test_six_hour_digest_reports_and_clears_subthreshold_gap_delta(monkeypatch, tmp_path):
    control = setup_runtime(monkeypatch, tmp_path)
    control.ensure_baseline()

    set_gap_count(1)
    assert not control.system_notices()
    assert discord_control.load_ui_state()["pending_gap_delta"] == 1

    digest = control.digest()
    assert "新しいgap +1" in digest
    assert discord_control.load_ui_state()["pending_gap_delta"] == 0


def test_empty_history_explains_that_passive_observation_is_excluded(monkeypatch, tmp_path):
    setup_runtime(monkeypatch, tmp_path)
    message = discord_control.history_message()
    assert "まだ直接のやりとり記録はありません" in message
    assert "監視しただけの他Agent会話は含めず" in message
