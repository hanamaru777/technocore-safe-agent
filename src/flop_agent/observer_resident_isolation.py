"""Keep CPU-heavy Resident maintenance outside the hot Observer process.

Issue #57 long-run Production evidence showed that a Python thread reduced but did
not eliminate lobby continuity loss. CPython threads still contend on the GIL, so
CPU-heavy Resident scoring runs in a separate spawned process.

Lobby capture used to be another Resident child process. PR #88 production
acceptance proved that this still creates a continuity hole whenever Resident is
restarted, so capture now has its own systemd lifecycle and is intentionally absent
from this supervisor.

This overlay performs no shell execution, signing, Technocore write, URL following,
or secret access.
"""
from __future__ import annotations

import asyncio
import multiprocessing
import os
from pathlib import Path

from . import observer

CHECK_INTERVAL_SECONDS = 0.25
_JOIN_TIMEOUT_SECONDS = 2.0
_PROCESS_NAME = "flop-resident-maintenance"
_MIN_MEM_AVAILABLE_BYTES = 256 * 1024 * 1024
_MAX_MEMORY_FULL_AVG10 = 5.0
_MAX_IO_FULL_AVG10 = 10.0
_PRESSURE_RECHECK_SECONDS = 15.0
_PRESSURE_HEARTBEAT_SECONDS = 60.0
_PRESSURE_CLEAR_STABLE_SECONDS = 60.0
_INSTALLED = False


def _mem_available_bytes() -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text("utf-8").splitlines():
            if line.startswith("MemAvailable:"):
                parts = line.split()
                return int(parts[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def _psi_full_avg10(kind: str) -> float | None:
    try:
        lines = Path(f"/proc/pressure/{kind}").read_text("utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        if not line.startswith("full "):
            continue
        for field in line.split()[1:]:
            if field.startswith("avg10="):
                try:
                    return float(field.split("=", 1)[1])
                except ValueError:
                    return None
    return None


def _maintenance_pressure_high() -> bool:
    """Fail closed for optional maintenance when Linux pressure is unsafe."""
    available = _mem_available_bytes()
    if available is None or available < _MIN_MEM_AVAILABLE_BYTES:
        return True

    memory_full = _psi_full_avg10("memory")
    if memory_full is not None and memory_full > _MAX_MEMORY_FULL_AVG10:
        return True

    io_full = _psi_full_avg10("io")
    if io_full is not None and io_full > _MAX_IO_FULL_AVG10:
        return True

    return False


def maintenance_cycle() -> None:
    """Run one existing local-only Resident/Autopilot maintenance cycle."""
    from . import autopilot, resident_candidate_supersession

    observed = observer.load_state()
    resident_candidate_supersession.refresh(observed)
    autopilot.build_outbox()


def _maintenance_process(stop) -> None:
    """Child-process loop; expected local refusals remain fail-closed."""
    from . import resident

    try:
        os.nice(10)
    except OSError:
        pass

    while not stop.is_set():
        pressured = _maintenance_pressure_high()
        if not pressured:
            try:
                maintenance_cycle()
            except RuntimeError:
                pass
        if stop.is_set():
            break
        interval = float(resident.load_config()["refresh_interval_seconds"])
        if pressured:
            interval = min(interval, _PRESSURE_RECHECK_SECONDS)
        stop.wait(max(1.0, interval))


async def _stop_process(process, process_stop) -> None:
    process_stop.set()
    await asyncio.to_thread(process.join, _JOIN_TIMEOUT_SECONDS)
    if process.is_alive():
        process.terminate()
        await asyncio.to_thread(process.join, _JOIN_TIMEOUT_SECONDS)


async def _write_pressure_heartbeat() -> bool:
    """Refresh only the tiny supervisor heartbeat while maintenance is pressure-paused."""
    from . import resident

    try:
        return bool(await asyncio.to_thread(resident.write_pressure_heartbeat))
    except (OSError, RuntimeError):
        return False


async def resident_worker(
    config: dict,
    stop: asyncio.Event,
    state: dict | None = None,
) -> None:
    """Supervise only isolated Resident/Autopilot maintenance."""
    del config, state

    context = multiprocessing.get_context("spawn")
    maintenance = None
    maintenance_stop = None
    preempted = False
    loop = asyncio.get_running_loop()
    next_pressure_check = 0.0
    next_pressure_heartbeat = 0.0
    pressure_clear_since = None
    try:
        while not stop.is_set():
            if maintenance is not None and not preempted and maintenance.exitcode is not None:
                raise RuntimeError(
                    f"resident maintenance process exited unexpectedly: {maintenance.exitcode}"
                )
            if loop.time() >= next_pressure_check:
                pressured = _maintenance_pressure_high()
                if maintenance is not None and (pressured or preempted):
                    preempted = True
                    await _stop_process(maintenance, maintenance_stop)
                    # A child stuck in kernel I/O may outlive bounded termination.
                    # Retain ownership and never spawn an overlapping replacement.
                    if not maintenance.is_alive():
                        maintenance = None
                        maintenance_stop = None
                        preempted = False
                if pressured:
                    pressure_clear_since = None
                    if loop.time() >= next_pressure_heartbeat:
                        await _write_pressure_heartbeat()
                        next_pressure_heartbeat = loop.time() + _PRESSURE_HEARTBEAT_SECONDS
                else:
                    next_pressure_heartbeat = 0.0
                    if pressure_clear_since is None:
                        pressure_clear_since = loop.time()
                if (
                    maintenance is None
                    and not pressured
                    and pressure_clear_since is not None
                    and loop.time() - pressure_clear_since >= _PRESSURE_CLEAR_STABLE_SECONDS
                    and not stop.is_set()
                ):
                    maintenance_stop = context.Event()
                    maintenance = context.Process(
                        target=_maintenance_process,
                        args=(maintenance_stop,),
                        name=_PROCESS_NAME,
                        daemon=True,
                    )
                    maintenance.start()
                next_pressure_check = loop.time() + _PRESSURE_RECHECK_SECONDS
            try:
                await asyncio.wait_for(stop.wait(), timeout=CHECK_INTERVAL_SECONDS)
            except TimeoutError:
                pass
    finally:
        if maintenance is not None:
            await _stop_process(maintenance, maintenance_stop)


def install() -> None:
    """Install the process-isolated auxiliary worker exactly once."""
    global _INSTALLED
    if _INSTALLED:
        return
    observer.resident_worker = resident_worker
    _INSTALLED = True
