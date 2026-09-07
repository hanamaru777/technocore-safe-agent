from __future__ import annotations

import ast
import asyncio
import inspect
import threading
import time

import pytest

from flop_agent import (
    autopilot,
    observer,
    observer_resident_isolation,
    resident,
)


def test_maintenance_cycle_reloads_persisted_observer_state(monkeypatch):
    calls: list[str] = []

    def refresh(*args, **kwargs):
        assert args == ()
        assert kwargs == {}
        calls.append("refresh")
        return {}

    monkeypatch.setattr(resident, "refresh", refresh)
    monkeypatch.setattr(autopilot, "build_outbox", lambda: calls.append("outbox") or {})

    observer_resident_isolation.maintenance_cycle()

    assert calls == ["refresh", "outbox"]


def test_isolated_worker_does_not_block_observer_event_loop(monkeypatch):
    started = threading.Event()
    release = threading.Event()
    completed = threading.Event()

    def refresh():
        started.set()
        assert release.wait(2)
        completed.set()
        return {}

    monkeypatch.setattr(resident, "refresh", refresh)
    monkeypatch.setattr(autopilot, "build_outbox", lambda: {})
    monkeypatch.setattr(resident, "load_config", lambda: {"refresh_interval_seconds": 30})

    async def run():
        stop = asyncio.Event()
        task = asyncio.create_task(
            observer_resident_isolation.resident_worker({}, stop, observer.default_state())
        )
        deadline = time.monotonic() + 1
        while not started.is_set() and time.monotonic() < deadline:
            await asyncio.sleep(0.005)
        assert started.is_set()

        # The maintenance thread is deliberately blocked above.  If maintenance
        # still ran on the Observer loop, this sleep could not complete.
        before = time.monotonic()
        await asyncio.sleep(0.05)
        assert time.monotonic() - before < 0.5
        assert not completed.is_set()

        release.set()
        deadline = time.monotonic() + 1
        while not completed.is_set() and time.monotonic() < deadline:
            await asyncio.sleep(0.005)
        assert completed.is_set()
        stop.set()
        await asyncio.wait_for(task, timeout=1)

    asyncio.run(run())


def test_runtime_error_remains_fail_closed_and_worker_stays_alive(monkeypatch):
    attempts = 0
    second_attempt = threading.Event()

    def refresh():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("expected local refusal")
        second_attempt.set()
        return {}

    monkeypatch.setattr(resident, "refresh", refresh)
    monkeypatch.setattr(autopilot, "build_outbox", lambda: {})
    monkeypatch.setattr(resident, "load_config", lambda: {"refresh_interval_seconds": 1})

    async def run():
        stop = asyncio.Event()
        task = asyncio.create_task(observer_resident_isolation.resident_worker({}, stop))
        deadline = time.monotonic() + 2
        while not second_attempt.is_set() and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        assert second_attempt.is_set()
        stop.set()
        await asyncio.wait_for(task, timeout=1)

    asyncio.run(run())


def test_unexpected_maintenance_failure_surfaces_to_daemon(monkeypatch):
    monkeypatch.setattr(
        resident,
        "refresh",
        lambda: (_ for _ in ()).throw(ValueError("unexpected")),
    )
    monkeypatch.setattr(autopilot, "build_outbox", lambda: {})
    monkeypatch.setattr(resident, "load_config", lambda: {"refresh_interval_seconds": 30})

    async def run():
        with pytest.raises(ValueError, match="unexpected"):
            await asyncio.wait_for(
                observer_resident_isolation.resident_worker({}, asyncio.Event()),
                timeout=1,
            )

    asyncio.run(run())


def test_overlay_is_local_only_and_has_no_command_execution_surface():
    source = inspect.getsource(observer_resident_isolation)
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert imported_roots.isdisjoint({"subprocess", "os", "httpx"})
    assert "post_signed(" not in source
    assert "SIGN_SEED" not in source
