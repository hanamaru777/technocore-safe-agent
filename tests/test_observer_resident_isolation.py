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
        self.stop = _FakeProcessStop()
        self.process = None

    def Event(self):
        return self.stop

    def Process(self, **kwargs):
        self.process = _FakeProcess(**kwargs)
        return self.process


def test_worker_supervises_separate_process_without_blocking_loop(monkeypatch):
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
        assert context.process is not None and context.process.started
        stop.set()
        await asyncio.wait_for(task, timeout=1)

    asyncio.run(run())
    assert context.stop.value is True
    assert context.process is not None and context.process.joined
    assert context.process.terminated is False


def test_unexpected_process_exit_fails_closed(monkeypatch):
    context = _FakeContext()

    def create_process(**kwargs):
        process = _FakeProcess(**kwargs)
        process.exitcode = 7
        context.process = process
        return process

    context.Process = create_process
    monkeypatch.setattr(observer_resident_isolation.multiprocessing, "get_context", lambda _: context)

    async def run():
        with pytest.raises(RuntimeError, match="exited unexpectedly: 7"):
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
