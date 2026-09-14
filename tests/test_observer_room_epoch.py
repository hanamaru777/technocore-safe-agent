"""Room recreation never carries an old sequence cursor into a new epoch."""
import asyncio

from flop_agent import observer, observer_resilience, observer_startup_resilience


def message(seq):
    return {"seq": seq, "from": "did:key:z6MkAgent", "text": "hello", "ts": "2026-09-14T00:00:00Z"}


def state_with_cursor(generations=None):
    state = observer.default_state()
    state["cursors"].update({"lobby": 500, "events": 80})
    state["bootstrap_tails"]["lobby"] = {"from_seq": 490, "to_seq": 500}
    if generations is not None:
        state["room_generations"]["lobby"] = generations
    return state


def test_legacy_adopts_generation_without_reset_and_same_generation_continues():
    state = state_with_cursor()
    assert observer.process_payload(state, observer.DEFAULT_CONFIG, "lobby", {"generation": 0, "messages": [message(501)]}, None, None, bootstrap=False)
    assert state["room_generations"]["lobby"] == 0
    assert state["cursors"]["lobby"] == 501
    assert state["metrics"]["message_gaps"] == 0
    observer.process_payload(state, observer.DEFAULT_CONFIG, "lobby", {"generation": 0, "messages": [message(502)]}, None, None, bootstrap=False)
    assert state["cursors"]["lobby"] == 502


def test_epoch_change_discards_stale_since_then_bootstraps_only_that_room():
    state = state_with_cursor(0)
    assert observer.process_payload(state, observer.DEFAULT_CONFIG, "lobby", {"generation": 1, "messages": [message(1), message(2)]}, None, None, bootstrap=False)
    assert "lobby" not in state["cursors"] and "lobby" not in state["bootstrap_tails"]
    assert state["cursors"]["events"] == 80
    assert state["metrics"]["message_gaps"] == 0
    observer.process_payload(state, observer.DEFAULT_CONFIG, "lobby", {"generation": 1, "messages": [message(10), message(11)]}, None, None, bootstrap=True)
    assert state["cursors"]["lobby"] == 11
    assert state["bootstrap_tails"]["lobby"]["from_seq"] == 10
    assert state["metrics"]["message_gaps"] == 0


def test_absent_malformed_and_bool_generation_do_not_reset():
    for payload in ({"messages": []}, {"generation": -1, "messages": []}, {"generation": "1", "messages": []}, {"generation": True, "messages": []}):
        state = state_with_cursor(0)
        observer.process_payload(state, observer.DEFAULT_CONFIG, "lobby", payload, None, None, bootstrap=False)
        assert state["cursors"]["lobby"] == 500
        assert state["room_generations"]["lobby"] == 0


def test_legacy_state_loads_without_generation_mapping(monkeypatch, tmp_path):
    from flop_agent import core
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    state = state_with_cursor()
    del state["room_generations"]
    observer.atomic_json_write(observer.state_path(), state)
    loaded = observer.load_state()
    assert loaded["room_generations"] == {}
    assert loaded["cursors"]["lobby"] == 500


def test_directory_actual_tail_rewinds_only_active_room(monkeypatch):
    state = state_with_cursor()
    class Budget:
        async def acquire(self): pass
    async def rooms(*_):
        return [{"room": "lobby", "last_seq": 12, "topic": ""}, {"room": "events", "last_seq": 80, "topic": ""}], None, None
    monkeypatch.setattr(observer, "read_rooms", rooms)
    asyncio.run(observer.backfill_into_state(object(), Budget(), state, observer.DEFAULT_CONFIG))
    assert "lobby" not in state["cursors"] and "lobby" not in state["bootstrap_tails"]
    assert state["cursors"]["events"] == 80
    assert state["metrics"]["message_gaps"] == 0


def test_directory_equal_or_newer_tail_does_not_rewind(monkeypatch):
    state = state_with_cursor()
    class Budget:
        async def acquire(self): pass
    async def rooms(*_):
        return [{"room": "lobby", "last_seq": 500, "topic": ""}], None, None
    monkeypatch.setattr(observer, "read_rooms", rooms)
    asyncio.run(observer.backfill_into_state(object(), Budget(), state, observer.DEFAULT_CONFIG))
    assert state["cursors"]["lobby"] == 500
    assert state["bootstrap_tails"]["lobby"]["to_seq"] == 500


def test_live_overlay_skips_stale_payload_before_gap_recovery(monkeypatch):
    state = state_with_cursor(0)
    stop = asyncio.Event()
    calls = []
    class Budget:
        async def acquire(self): pass
    async def live(_client, _room, since, _wait):
        calls.append(since)
        if len(calls) == 1: return {"generation": 1, "messages": [message(700)]}, None, None
        stop.set()
        return {"generation": 1, "messages": [message(1)]}, None, None
    async def forbidden(*_args, **_kwargs):
        raise AssertionError("stale-since payload reached recovery")
    monkeypatch.setattr(observer_resilience, "read_room_live", live)
    monkeypatch.setattr(observer_resilience, "read_room_export", forbidden)
    monkeypatch.setattr(observer_resilience, "_effective_room_interval", lambda *_: 0)
    asyncio.run(observer_resilience.room_worker(object(), Budget(), state, observer.DEFAULT_CONFIG, "lobby", None, None, stop))
    assert calls == [500, 0]
    assert state["metrics"]["message_gaps"] == 0


def test_events_startup_probe_detects_new_epoch_before_recovery(monkeypatch):
    state = state_with_cursor(0)
    state["room_generations"]["events"] = 0
    class Budget:
        async def acquire(self): pass
    async def live(*_): return {"generation": 1, "messages": [message(700)]}, None, None
    monkeypatch.setattr(observer_resilience, "read_room_live", live)
    result = asyncio.run(observer_startup_resilience._try_events_live_probe(object(), Budget(), state, observer.DEFAULT_CONFIG, "events", None, None, None))
    assert result == ("success", None)
    assert "events" not in state["cursors"]
    assert state["metrics"]["message_gaps"] == 0
