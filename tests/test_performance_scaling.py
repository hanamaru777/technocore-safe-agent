from __future__ import annotations

from datetime import UTC, datetime

from flop_agent import autopilot, core, discord_control, observer, resident


def setup_paths(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)


def test_build_outbox_audits_unchanged_pending_decision_once(monkeypatch, tmp_path):
    setup_paths(monkeypatch, tmp_path)
    auto = autopilot.default_state()
    auto.update({"enabled": True, "paused": False, "migrated_at": datetime.now(UTC).isoformat()})
    autopilot.save(auto)
    candidate = {
        "candidate_id": "noise-1",
        "status": "pending",
        "room": "lobby",
        "category": "specific_question",
        "signals": {"spam_noise_probability": 1.0, "generic_template_probability": 1.0, "facts": {}},
        "context": {"excerpt": "hello"},
    }
    monkeypatch.setattr(resident, "load_state", lambda: {"candidates": {"noise-1": candidate}, "relationships": {}})

    autopilot.build_outbox()
    size_after_first = autopilot.audit_path().stat().st_size
    autopilot.build_outbox()
    size_after_second = autopilot.audit_path().stat().st_size

    assert size_after_first > 0
    assert size_after_second == size_after_first
    state = autopilot.load()
    assert len(state["recent_decisions"]) == 1
    assert state["recent_decisions"][0]["source_candidate"] == "noise-1"


def test_audit_rotates_to_bounded_segments(monkeypatch, tmp_path):
    setup_paths(monkeypatch, tmp_path)
    monkeypatch.setattr(autopilot, "AUDIT_MAX_BYTES", 256)
    monkeypatch.setattr(autopilot, "AUDIT_ROTATIONS", 2)
    for number in range(30):
        autopilot.audit({"at": datetime.now(UTC).isoformat(), "source_candidate": f"c{number}", "action": "ignored", "why": "generic_or_noise"})

    paths = [path for path in autopilot.audit_paths() if path.exists()]
    assert 1 <= len(paths) <= 3
    assert all(path.is_file() and not path.is_symlink() for path in paths)
    assert all(path.stat().st_size <= autopilot.AUDIT_MAX_BYTES for path in paths)


def test_resident_pause_marker_survives_stale_state_write_and_fast_refresh(monkeypatch, tmp_path):
    setup_paths(monkeypatch, tmp_path)
    state = resident.default_state()
    state["cached_observer"]["health"] = {"current": "ok"}
    state["daemon"]["last_refresh_at"] = datetime.now(UTC).isoformat()
    resident.save_state(state)

    resident.pause(True)
    stale = resident.default_state()
    stale["control"]["paused"] = False
    stale["cached_observer"]["health"] = {"current": "ok"}
    stale["daemon"]["last_refresh_at"] = datetime.now(UTC).isoformat()
    resident.save_state(stale)
    assert resident.load_state()["control"]["paused"] is True

    monkeypatch.setattr(resident, "load_state", lambda: (_ for _ in ()).throw(AssertionError("paused refresh must stay on heartbeat fast path")))
    result = resident.refresh()
    assert result["paused"] is True


def test_status_uses_small_heartbeat_and_recent_decision_cache(monkeypatch, tmp_path):
    setup_paths(monkeypatch, tmp_path)
    state = resident.default_state()
    state["cached_observer"]["health"] = {"current": "ok"}
    state["daemon"]["last_refresh_at"] = datetime.now(UTC).isoformat()
    resident.save_state(state)
    auto = autopilot.default_state()
    auto.update({"enabled": True, "paused": False, "migrated_at": datetime.now(UTC).isoformat()})
    autopilot.save(auto)

    monkeypatch.setattr(resident, "load_state", lambda: (_ for _ in ()).throw(AssertionError("/status must not parse Resident state")))
    monkeypatch.setattr(observer, "load_state", lambda: (_ for _ in ()).throw(AssertionError("/status must not parse Observer state")))
    message = discord_control.status_message()
    assert "🟢 FLOP Agent 正常" in message
    assert "queue: 0 / eligible 0 / ignored 0 / blocked 0" in message


def test_observer_success_timestamp_does_not_dirty_idle_state(monkeypatch, tmp_path):
    setup_paths(monkeypatch, tmp_path)
    state = observer.default_state()
    assert observer.set_success(state, "lobby") is True
    first = dict(state["health"]["rooms"]["lobby"])
    assert observer.set_success(state, "lobby") is False
    assert state["health"]["rooms"]["lobby"] == first
    assert observer.process_payload(state, observer.DEFAULT_CONFIG, "lobby", {"messages": []}, None, None, bootstrap=False) is False


def test_observer_agent_cap_evicts_one_without_exceeding_bound(monkeypatch, tmp_path):
    setup_paths(monkeypatch, tmp_path)
    config = {**observer.DEFAULT_CONFIG, "max_agents": 100}
    state = observer.default_state()
    for number in range(100):
        fp = f"fp{number:04d}"
        state["agents"][fp] = {
            "did": f"did:key:z6Mk{number:04d}",
            "fingerprint": fp,
            "facts": {"first_seen": "2026-01-01T00:00:00+00:00", "last_seen": "2026-01-01T00:00:00+00:00", "last_encounter_at": "2026-01-01T00:00:00+00:00", "seen_count": 1, "rooms": [], "message_refs": [], "recent_messages": [], "signed_count": 1, "unsigned_count": 0, "interaction_with_us": False},
            "inferences": {"contribution_url_candidates": [], "role_candidates": [], "repeat_seen": False},
        }
    monkeypatch.setattr(core, "did_note_location", lambda did: ("x", "y", "new-fingerprint"))
    observer.process_message(state, config, "lobby", {"seq": 1, "text": "hello", "from": "did:key:z6MkNew", "ts": "2026-09-04T00:00:00+00:00"}, None, None)
    assert len(state["agents"]) == 100
    assert "new-fingerprint" in state["agents"]


def test_shared_observer_unchanged_refresh_skips_resident_state_reload(monkeypatch, tmp_path):
    setup_paths(monkeypatch, tmp_path)
    observed = observer.default_state()
    observed["health"]["current"] = "ok"
    first = resident.refresh(observed_state=observed)
    assert first["last_refresh_at"]
    state_mtime = resident.state_path().stat().st_mtime_ns

    monkeypatch.setattr(resident, "load_state", lambda: (_ for _ in ()).throw(AssertionError("unchanged shared Observer state must stay on heartbeat fast path")))
    second = resident.refresh(observed_state=observed)
    assert second["last_refresh_at"]
    assert resident.state_path().stat().st_mtime_ns == state_mtime


def test_autopilot_skips_unchanged_resident_file_after_first_scan(monkeypatch, tmp_path):
    setup_paths(monkeypatch, tmp_path)
    resident_state = resident.default_state()
    resident_state["cached_observer"]["health"] = {"current": "ok"}
    resident_state["daemon"]["last_refresh_at"] = datetime.now(UTC).isoformat()
    resident.save_state(resident_state)
    auto = autopilot.default_state()
    auto.update({"enabled": True, "paused": False, "migrated_at": datetime.now(UTC).isoformat()})
    autopilot.save(auto)

    autopilot.build_outbox()
    revision = autopilot.load()["resident_revision"]
    assert revision
    monkeypatch.setattr(resident, "load_state", lambda: (_ for _ in ()).throw(AssertionError("unchanged Resident state must not be reparsed")))
    autopilot.build_outbox()
    assert autopilot.load()["resident_revision"] == revision
