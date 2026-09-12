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

from . import observer

CHECK_INTERVAL_SECONDS = 0.25
_JOIN_TIMEOUT_SECONDS = 2.0
_PROCESS_NAME = "flop-resident-maintenance"
_INSTALLED = False


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
        try:
            maintenance_cycle()
        except RuntimeError:
            pass
        if stop.is_set():
            break
        interval = float(resident.load_config()["refresh_interval_seconds"])
        stop.wait(max(1.0, interval))


async def _stop_process(process, process_stop) -> None:
    process_stop.set()
    await asyncio.to_thread(process.join, _JOIN_TIMEOUT_SECONDS)
    if process.is_alive():
        process.terminate()
        await asyncio.to_thread(process.join, _JOIN_TIMEOUT_SECONDS)


async def resident_worker(
    config: dict,
    stop: asyncio.Event,
    state: dict | None = None,
) -> None:
    """Supervise only isolated Resident/Autopilot maintenance."""
    del config, state

    context = multiprocessing.get_context("spawn")
    maintenance_stop = context.Event()
    maintenance = context.Process(
        target=_maintenance_process,
        args=(maintenance_stop,),
        name=_PROCESS_NAME,
        daemon=True,
    )

    maintenance.start()
    try:
        while not stop.is_set():
            if maintenance.exitcode is not None:
                raise RuntimeError(
                    f"resident maintenance process exited unexpectedly: {maintenance.exitcode}"
                )
            try:
                await asyncio.wait_for(stop.wait(), timeout=CHECK_INTERVAL_SECONDS)
            except TimeoutError:
                pass
    finally:
        await _stop_process(maintenance, maintenance_stop)


def install() -> None:
    """Install the process-isolated auxiliary worker exactly once."""
    global _INSTALLED
    if _INSTALLED:
        return
    observer.resident_worker = resident_worker
    _INSTALLED = True
