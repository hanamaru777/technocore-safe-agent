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
    monkeypatch.setattr(observer_resident_isolation.os, "nice", lambda value: calls.append(f"nice:{value}"))
    monkeypatch.setattr(observer_resident_isolation, "maintenance_cycle", lambda: calls.append("cycle"))
    monkeypatch.setattr(resident, "load_config", lambda: {"refresh_interval_seconds": 30})

    observer_resident_isolation._maintenance_process(stop)

    assert calls == ["nice:10", "cycle"]


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


def test_overlay_has_no_capture_child_or_untrusted_execution_surface():
    source = inspect.getsource(observer_resident_isolation)
    assert "subprocess" not in source
    assert "httpx" not in source
    assert "post_signed(" not in source
    assert "SIGN_SEED" not in source
    assert "multiprocessing.get_context(\"spawn\")" in source
    assert "threading.Thread" not in source
    assert "flop-lobby-capture" not in source
