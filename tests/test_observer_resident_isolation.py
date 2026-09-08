from __future__ import annotations

import asyncio
import inspect

import pytest

from flop_agent import (
    autopilot,
    observer,
    observer_resident_isolation,
    resident,
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
    calls: list[str] = []
    monkeypatch.setattr(resident, "refresh", lambda: calls.append("refresh") or {})
    monkeypatch.setattr(autopilot, "build_outbox", lambda: calls.append("outbox") or {})

    observer_resident_isolation.maintenance_cycle()

    assert calls == ["refresh", "outbox"]


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


def test_worker_supervises_maintenance_and_capture_processes(monkeypatch):
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
        assert len(context.processes) == 2
        assert all(process.started for process in context.processes)
        names = {process.name for process in context.processes}
        assert names == {"flop-resident-maintenance", "flop-lobby-capture"}
        stop.set()
        await asyncio.wait_for(task, timeout=1)

    asyncio.run(run())
    assert all(stop.value for stop in context.stops)
    assert all(process.joined for process in context.processes)
    assert not any(process.terminated for process in context.processes)


def test_unexpected_capture_exit_fails_closed(monkeypatch):
    context = _FakeContext()
    original_process = context.Process

    def create_process(**kwargs):
        process = original_process(**kwargs)
        if kwargs.get("name") == "flop-lobby-capture":
            process.exitcode = 7
        return process

    context.Process = create_process
    monkeypatch.setattr(observer_resident_isolation.multiprocessing, "get_context", lambda _: context)

    async def run():
        with pytest.raises(RuntimeError, match="lobby capture process exited unexpectedly: 7"):
            await asyncio.wait_for(
                observer_resident_isolation.resident_worker({}, asyncio.Event()),
                timeout=1,
            )

    asyncio.run(run())


def test_overlay_has_no_untrusted_execution_or_network_surface():
    source = inspect.getsource(observer_resident_isolation)
    assert "subprocess" not in source
    assert "httpx" not in source
    assert "post_signed(" not in source
    assert "SIGN_SEED" not in source
    assert "multiprocessing.get_context(\"spawn\")" in source
    assert "threading.Thread" not in source
    assert "flop-lobby-capture" in source
