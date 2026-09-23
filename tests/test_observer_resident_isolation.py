from __future__ import annotations

import asyncio
import inspect

import pytest

from flop_agent import (
    autopilot,
    observer,
    observer_resident_isolation,
    resident,
    resident_candidate_supersession,
)


class _OneCycleStop:
    def __init__(self):
        self.stopped = False

    def is_set(self):
        return self.stopped

    def wait(self, _seconds):
        self.stopped = True
        return True


def test_maintenance_cycle_uses_only_persisted_local_state(monkeypatch):
    calls: list[object] = []
    observed = {"persisted": True}
    monkeypatch.setattr(observer, "load_state", lambda: observed)
    monkeypatch.setattr(
        resident_candidate_supersession,
        "refresh",
        lambda value: calls.append(("refresh", value)) or {},
    )
    monkeypatch.setattr(autopilot, "build_outbox", lambda: calls.append("outbox") or {})

    observer_resident_isolation.maintenance_cycle()

    assert calls == [("refresh", observed), "outbox"]


def test_maintenance_process_runs_cycle_and_uses_positive_nice(monkeypatch):
    calls: list[str] = []
    stop = _OneCycleStop()
    monkeypatch.setattr(observer_resident_isolation.os, "nice", lambda value: calls.append(f"nice:{value}"), raising=False)
    monkeypatch.setattr(observer_resident_isolation, "maintenance_cycle", lambda: calls.append("cycle"))
    monkeypatch.setattr(observer_resident_isolation, "_maintenance_pressure_high", lambda: False)
    monkeypatch.setattr(resident, "load_config", lambda: {"refresh_interval_seconds": 30})

    observer_resident_isolation._maintenance_process(stop)

    assert calls == ["nice:10", "cycle"]


def test_maintenance_pressure_guard_thresholds(monkeypatch):
    monkeypatch.setattr(
        observer_resident_isolation,
        "_mem_available_bytes",
        lambda: 512 * 1024 * 1024,
    )

    values = {"memory": 0.0, "io": 0.0}
    monkeypatch.setattr(
        observer_resident_isolation,
        "_psi_full_avg10",
        lambda kind: values[kind],
    )

    assert observer_resident_isolation._maintenance_pressure_high() is False

    monkeypatch.setattr(
        observer_resident_isolation,
        "_mem_available_bytes",
        lambda: 128 * 1024 * 1024,
    )
    assert observer_resident_isolation._maintenance_pressure_high() is True

    monkeypatch.setattr(
        observer_resident_isolation,
        "_mem_available_bytes",
        lambda: 512 * 1024 * 1024,
    )
    values["memory"] = 6.0
    assert observer_resident_isolation._maintenance_pressure_high() is True

    values["memory"] = 0.0
    values["io"] = 11.0
    assert observer_resident_isolation._maintenance_pressure_high() is True


def test_maintenance_pressure_guard_fails_closed_when_meminfo_unavailable(monkeypatch):
    monkeypatch.setattr(
        observer_resident_isolation,
        "_mem_available_bytes",
        lambda: None,
    )
    assert observer_resident_isolation._maintenance_pressure_high() is True


def test_maintenance_process_skips_cycle_under_pressure(monkeypatch):
    calls: list[str] = []
    waits: list[float] = []

    class StopAfterPressureWait:
        def __init__(self):
            self.stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, seconds):
            waits.append(seconds)
            self.stopped = True
            return True

    stop = StopAfterPressureWait()
    monkeypatch.setattr(observer_resident_isolation.os, "nice", lambda value: calls.append(f"nice:{value}"), raising=False)
    monkeypatch.setattr(observer_resident_isolation, "maintenance_cycle", lambda: calls.append("cycle"))
    monkeypatch.setattr(observer_resident_isolation, "_maintenance_pressure_high", lambda: True)
    monkeypatch.setattr(resident, "load_config", lambda: {"refresh_interval_seconds": 30})

    observer_resident_isolation._maintenance_process(stop)

    assert calls == ["nice:10"]
    assert waits == [observer_resident_isolation._PRESSURE_RECHECK_SECONDS]


class _FakeProcess:
    def __init__(self, *, target, args, name, daemon):
        self.target = target
        self.args = args
        self.name = name
        self.daemon = daemon
        self.exitcode = None
        self.started = False
        self.joined = False
        self.terminated = False

    def start(self):
        self.started = True

    def join(self, _timeout):
        self.joined = True

    def is_alive(self):
        return False

    def terminate(self):
        self.terminated = True


class _FakeProcessStop:
    def __init__(self):
        self.value = False

    def set(self):
        self.value = True


class _FakeContext:
    def __init__(self):
        self.stops: list[_FakeProcessStop] = []
        self.processes: list[_FakeProcess] = []

    def Event(self):
        stop = _FakeProcessStop()
        self.stops.append(stop)
        return stop

    def Process(self, **kwargs):
        process = _FakeProcess(**kwargs)
        self.processes.append(process)
        return process


def test_worker_supervises_only_maintenance_process(monkeypatch):
    monkeypatch.setattr(observer_resident_isolation, "_maintenance_pressure_high", lambda: False)
    monkeypatch.setattr(observer_resident_isolation, "_PRESSURE_CLEAR_STABLE_SECONDS", 0)
    context = _FakeContext()
    monkeypatch.setattr(
        observer_resident_isolation.multiprocessing,
        "get_context",
        lambda method: context if method == "spawn" else pytest.fail("unexpected method"),
    )

    async def run():
        stop = asyncio.Event()
        task = asyncio.create_task(observer_resident_isolation.resident_worker({}, stop, {}))
        await asyncio.sleep(0.05)
        assert len(context.processes) == 1
        process = context.processes[0]
        assert process.started
        assert process.name == "flop-resident-maintenance"
        stop.set()
        await asyncio.wait_for(task, timeout=1)

    asyncio.run(run())
    assert len(context.stops) == 1
    assert context.stops[0].value
    assert context.processes[0].joined
    assert not context.processes[0].terminated


def test_unexpected_maintenance_exit_fails_closed(monkeypatch):
    monkeypatch.setattr(observer_resident_isolation, "_maintenance_pressure_high", lambda: False)
    monkeypatch.setattr(observer_resident_isolation, "_PRESSURE_CLEAR_STABLE_SECONDS", 0)
    context = _FakeContext()
    original_process = context.Process

    def create_process(**kwargs):
        process = original_process(**kwargs)
        process.exitcode = 7
        return process

    context.Process = create_process
    monkeypatch.setattr(observer_resident_isolation.multiprocessing, "get_context", lambda _: context)

    async def run():
        with pytest.raises(RuntimeError, match="resident maintenance process exited unexpectedly: 7"):
            await asyncio.wait_for(
                observer_resident_isolation.resident_worker({}, asyncio.Event()),
                timeout=1,
            )

    asyncio.run(run())


def test_parent_pressure_lifecycle_preempts_and_restarts_fresh_child(monkeypatch):
    context = _FakeContext()
    monkeypatch.setattr(observer_resident_isolation.multiprocessing, "get_context", lambda _: context)

    async def pressure_heartbeat():
        return True

    monkeypatch.setattr(observer_resident_isolation, "_write_pressure_heartbeat", pressure_heartbeat)
    monkeypatch.setattr(observer_resident_isolation, "_PRESSURE_CLEAR_STABLE_SECONDS", 0)
    # Advance one supervisor turn at a time, without wall-clock pressure timing.
    monkeypatch.setattr(observer_resident_isolation, "_PRESSURE_RECHECK_SECONDS", 0)
    monkeypatch.setattr(observer_resident_isolation, "CHECK_INTERVAL_SECONDS", 0)

    async def run():
        stop = asyncio.Event()
        checks = []

        def pressure():
            turn = len(checks)
            checks.append(turn)
            if turn in (0, 1, 2):
                assert not context.processes  # entry and sustained pressure
                return turn < 2
            if turn == 3:
                assert len(context.processes) == 1
                assert not context.stops[0].value
                return True  # pressure rises during a running cycle
            if turn in (4, 5, 6):
                assert len(context.processes) == 1
                assert context.stops[0].value and context.processes[0].joined
                return turn < 6
            assert len(context.processes) == 2
            assert context.stops[1] is not context.stops[0]
            assert context.processes[1].started
            stop.set()
            return False

        monkeypatch.setattr(observer_resident_isolation, "_maintenance_pressure_high", pressure)
        await observer_resident_isolation.resident_worker({}, stop)
        assert len(checks) == 8

    asyncio.run(run())
    assert context.stops[1].value and context.processes[1].joined


def test_pressure_preemption_uses_bounded_terminate_and_never_overlaps(monkeypatch):
    context = _FakeContext()
    monkeypatch.setattr(observer_resident_isolation.multiprocessing, "get_context", lambda _: context)

    async def pressure_heartbeat():
        return True

    monkeypatch.setattr(observer_resident_isolation, "_write_pressure_heartbeat", pressure_heartbeat)
    monkeypatch.setattr(observer_resident_isolation, "_PRESSURE_CLEAR_STABLE_SECONDS", 0)
    monkeypatch.setattr(observer_resident_isolation, "_PRESSURE_RECHECK_SECONDS", 0)
    monkeypatch.setattr(observer_resident_isolation, "CHECK_INTERVAL_SECONDS", 0)

    async def run():
        stop = asyncio.Event()
        checks = []

        def pressure():
            turn = len(checks)
            checks.append(turn)
            if turn == 0:
                return False
            process = context.processes[0]
            if turn == 1:
                process.is_alive = lambda: True
                return True
            assert len(context.processes) == 1 and process.terminated
            if turn == 2:
                return False  # even cleared pressure cannot overlap a stuck child
            process.is_alive = lambda: False
            stop.set()
            return False

        monkeypatch.setattr(observer_resident_isolation, "_maintenance_pressure_high", pressure)
        await observer_resident_isolation.resident_worker({}, stop)

    asyncio.run(run())
    assert len(context.processes) == 1


def test_brief_pressure_clear_does_not_admit_maintenance(monkeypatch):
    context = _FakeContext()
    monkeypatch.setattr(observer_resident_isolation.multiprocessing, "get_context", lambda _: context)
    monkeypatch.setattr(observer_resident_isolation, "_PRESSURE_RECHECK_SECONDS", 0)
    monkeypatch.setattr(observer_resident_isolation, "_PRESSURE_CLEAR_STABLE_SECONDS", 3600)
    monkeypatch.setattr(observer_resident_isolation, "CHECK_INTERVAL_SECONDS", 0)

    async def pressure_heartbeat():
        return True

    monkeypatch.setattr(observer_resident_isolation, "_write_pressure_heartbeat", pressure_heartbeat)

    async def run():
        stop = asyncio.Event()
        values = iter([True, False, True, False])

        def pressure():
            try:
                value = next(values)
            except StopIteration:
                stop.set()
                return True
            if value is True and context.processes:
                pytest.fail("brief clear must not admit maintenance before pressure returns")
            return value

        monkeypatch.setattr(observer_resident_isolation, "_maintenance_pressure_high", pressure)
        await observer_resident_isolation.resident_worker({}, stop)

    asyncio.run(run())
    assert context.processes == []


def test_pressure_heartbeat_delegates_to_lightweight_resident_writer(monkeypatch):
    calls = []
    monkeypatch.setattr(resident, "write_pressure_heartbeat", lambda: calls.append("heartbeat") or True)
    assert asyncio.run(observer_resident_isolation._write_pressure_heartbeat()) is True
    assert calls == ["heartbeat"]


def test_parent_publishes_supervisor_heartbeat_while_pressure_blocks_maintenance(monkeypatch):
    context = _FakeContext()
    monkeypatch.setattr(observer_resident_isolation.multiprocessing, "get_context", lambda _: context)
    monkeypatch.setattr(observer_resident_isolation, "_maintenance_pressure_high", lambda: True)
    monkeypatch.setattr(observer_resident_isolation, "_PRESSURE_RECHECK_SECONDS", 0)
    monkeypatch.setattr(observer_resident_isolation, "_PRESSURE_HEARTBEAT_SECONDS", 0)
    monkeypatch.setattr(observer_resident_isolation, "CHECK_INTERVAL_SECONDS", 0)

    async def run():
        stop = asyncio.Event()
        calls = []

        async def pressure_heartbeat():
            calls.append("heartbeat")
            if len(calls) == 2:
                stop.set()
            return True

        monkeypatch.setattr(observer_resident_isolation, "_write_pressure_heartbeat", pressure_heartbeat)
        await observer_resident_isolation.resident_worker({}, stop)
        assert calls == ["heartbeat", "heartbeat"]

    asyncio.run(run())
    assert context.processes == []


def test_overlay_has_no_capture_child_or_untrusted_execution_surface():
    source = inspect.getsource(observer_resident_isolation)
    assert "subprocess" not in source
    assert "httpx" not in source
    assert "post_signed(" not in source
    assert "SIGN_SEED" not in source
    assert "multiprocessing.get_context(\"spawn\")" in source
    assert "threading.Thread" not in source
    assert "flop-lobby-capture" not in source
