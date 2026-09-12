from __future__ import annotations

import asyncio
import json
import threading

from flop_agent import core, observer, observer_state_writer_isolation


def _setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    state = observer.default_state()
    state["metrics"]["unrecoverable_core_gap_events"] = 117
    state["metrics"]["unrecoverable_core_gap_messages"] = 5083155
    writer = observer.StateWriter(state, 5, observer.DEFAULT_CONFIG)
    return state, writer


def test_serialize_snapshot_skips_full_compaction_when_within_bounds(monkeypatch, tmp_path):
    state, writer = _setup(monkeypatch, tmp_path)
    state["agents"]["a"] = {
        "did": "did:key:test",
        "fingerprint": "a",
        "facts": {},
        "inferences": {},
    }
    monkeypatch.setattr(
        observer,
        "compact_state",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no routine full sweep")),
    )
    observer_state_writer_isolation.mark_dirty(writer)

    generation, state_text, heartbeat_text, safety_text = observer_state_writer_isolation._serialize_snapshot(writer)

    assert generation == 1
    assert json.loads(state_text)["schema_version"] == observer.SCHEMA_VERSION
    assert json.loads(heartbeat_text)["agent_count"] == 1
    assert json.loads(safety_text) == {
        "schema_version": 1,
        "updated_at": state["updated_at"],
        "health": "ok",
        "unrecoverable_core_gap_events": 117,
        "unrecoverable_core_gap_messages": 5083155,
    }


def test_over_bound_snapshot_still_compacts(monkeypatch, tmp_path):
    state, writer = _setup(monkeypatch, tmp_path)
    writer.config = {**observer.DEFAULT_CONFIG, "max_agents": 100}
    for number in range(101):
        state["agents"][str(number)] = {
            "did": f"did:key:{number}",
            "fingerprint": str(number),
            "facts": {
                "first_seen": "2026-01-01T00:00:00+00:00",
                "last_seen": "2026-01-01T00:00:00+00:00",
                "seen_count": 1,
            },
            "inferences": {},
        }
    called = 0
    base = observer.compact_state

    def compact(*args, **kwargs):
        nonlocal called
        called += 1
        return base(*args, **kwargs)

    monkeypatch.setattr(observer, "compact_state", compact)
    observer_state_writer_isolation.mark_dirty(writer)

    observer_state_writer_isolation._serialize_snapshot(writer)

    assert called == 1
    assert len(state["agents"]) == 100


def test_flush_io_runs_off_event_loop_and_preserves_new_dirty_generation(monkeypatch, tmp_path):
    _state, writer = _setup(monkeypatch, tmp_path)
    started = threading.Event()
    release = threading.Event()

    def persist(_state_text, _heartbeat_text, _safety_text):
        started.set()
        assert release.wait(2)

    monkeypatch.setattr(observer_state_writer_isolation, "_persist_serialized", persist)
    observer_state_writer_isolation.mark_dirty(writer)

    async def run():
        task = asyncio.create_task(observer_state_writer_isolation.flush_async(writer))
        deadline = asyncio.get_running_loop().time() + 1
        while not started.is_set() and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.005)
        assert started.is_set()

        before = asyncio.get_running_loop().time()
        await asyncio.sleep(0.05)
        assert asyncio.get_running_loop().time() - before < 0.5

        observer_state_writer_isolation.mark_dirty(writer)
        release.set()
        await asyncio.wait_for(task, timeout=1)

    asyncio.run(run())
    assert writer.dirty is True
    assert writer.write_count == 1


def test_successful_flush_clears_dirty_and_writes_valid_files(monkeypatch, tmp_path):
    _state, writer = _setup(monkeypatch, tmp_path)
    observer_state_writer_isolation.mark_dirty(writer)

    asyncio.run(observer_state_writer_isolation.flush_async(writer))

    assert writer.dirty is False
    assert writer.write_count == 1
    saved = json.loads(observer.state_path().read_text("utf-8"))
    heartbeat = json.loads(observer.heartbeat_path().read_text("utf-8"))
    safety_path = observer_state_writer_isolation.safety_path()
    safety = json.loads(safety_path.read_text("utf-8"))
    assert saved["schema_version"] == observer.SCHEMA_VERSION
    assert heartbeat["schema_version"] == 1
    assert safety == {
        "schema_version": 1,
        "updated_at": saved["updated_at"],
        "health": "ok",
        "unrecoverable_core_gap_events": 117,
        "unrecoverable_core_gap_messages": 5083155,
    }
    assert safety_path.stat().st_mode & 0o777 == 0o640


def test_safety_snapshot_write_failure_does_not_break_core_persistence(monkeypatch, tmp_path):
    _state, writer = _setup(monkeypatch, tmp_path)
    original = observer_state_writer_isolation._atomic_text_write

    def write(path, encoded, *, mode=None):
        if path == observer_state_writer_isolation.safety_path():
            raise PermissionError("secondary snapshot unavailable")
        return original(path, encoded, mode=mode)

    monkeypatch.setattr(observer_state_writer_isolation, "_atomic_text_write", write)
    observer_state_writer_isolation.mark_dirty(writer)

    asyncio.run(observer_state_writer_isolation.flush_async(writer))

    assert writer.dirty is False
    assert observer.state_path().exists()
    assert observer.heartbeat_path().exists()
    assert not observer_state_writer_isolation.safety_path().exists()


def test_run_sets_stop_on_persistence_failure(monkeypatch, tmp_path):
    _state, writer = _setup(monkeypatch, tmp_path)
    writer.interval_seconds = 0.01
    observer_state_writer_isolation.mark_dirty(writer)
    monkeypatch.setattr(
        observer_state_writer_isolation,
        "_persist_serialized",
        lambda *_: (_ for _ in ()).throw(OSError("disk failure")),
    )

    async def run():
        stop = asyncio.Event()
        try:
            await observer_state_writer_isolation.run(writer, stop)
        except OSError as error:
            assert "disk failure" in str(error)
        else:
            raise AssertionError("persistence failure must surface")
        assert stop.is_set()

    asyncio.run(run())
