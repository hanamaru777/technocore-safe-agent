"""Keep CPU-heavy local Resident maintenance outside the hot Observer process.

Issue #57 long-run Production evidence showed that a Python thread reduced but did
not eliminate lobby continuity loss.  CPython threads still contend on the GIL, so
CPU-heavy Resident scoring can delay the asyncio loop even when it is moved off an
async task.

This overlay runs only the existing local Resident/Autopilot maintenance cycle in
one low-priority spawned Python process.  The child reloads atomically persisted
local state and never receives the Observer's live mutable in-memory state.

There is no shell execution, signing, Technocore write, URL following, or secret
access in this module.
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
    from . import autopilot, resident

    resident.refresh()
    autopilot.build_outbox()


def _maintenance_process(stop) -> None:
    """Child-process loop; expected local refusals remain fail-closed."""
    from . import resident

    try:
        os.nice(10)
    except OSError:
        # Positive niceness is only a scheduling preference.  Failure to apply it
        # must not widen privileges or change safety semantics.
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


async def resident_worker(
    config: dict,
    stop: asyncio.Event,
    state: dict | None = None,
) -> None:
    """Supervise a separate maintenance process without blocking hot-room reads."""
    del config, state
    context = multiprocessing.get_context("spawn")
    process_stop = context.Event()
    process = context.Process(
        target=_maintenance_process,
        args=(process_stop,),
        name=_PROCESS_NAME,
        daemon=True,
    )
    process.start()
    try:
        while not stop.is_set():
            if process.exitcode is not None:
                raise RuntimeError(
                    f"resident maintenance process exited unexpectedly: {process.exitcode}"
                )
            try:
                await asyncio.wait_for(stop.wait(), timeout=CHECK_INTERVAL_SECONDS)
            except TimeoutError:
                pass
    finally:
        process_stop.set()
        await asyncio.to_thread(process.join, _JOIN_TIMEOUT_SECONDS)
        if process.is_alive():
            process.terminate()
            await asyncio.to_thread(process.join, _JOIN_TIMEOUT_SECONDS)


def install() -> None:
    """Install the process-isolated maintenance worker exactly once."""
    global _INSTALLED
    if _INSTALLED:
        return
    observer.resident_worker = resident_worker
    _INSTALLED = True
