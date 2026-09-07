"""Keep expensive local Resident maintenance off the Observer network event loop.

Production evidence for Issue #57 showed unrecoverable ``lobby`` gaps without a
corresponding lobby live-read error while the Resident process was CPU-heavy.
The base daemon runs ``resident.refresh()`` and ``autopilot.build_outbox()``
synchronously inside the same asyncio loop that must keep hot-room reads moving.
Those local operations can traverse thousands of retained agents and large JSON
state, so one slow refresh can starve network polling even when Technocore itself
returns a successful live response.

This overlay moves only that local maintenance cycle onto one daemon thread.  The
thread deliberately reloads the atomically persisted Observer snapshot instead of
receiving the live mutable in-memory state, so no cross-thread mutation is
introduced.  The Observer event loop never waits for the maintenance cycle.

There is no shell/subprocess execution, signing, Technocore write, URL following,
or secret access in this module.
"""
from __future__ import annotations

import asyncio
import threading

from . import observer

CHECK_INTERVAL_SECONDS = 0.25
_THREAD_NAME = "flop-resident-maintenance"
_INSTALLED = False


def maintenance_cycle() -> None:
    """Run one existing local-only Resident/Autopilot maintenance cycle."""
    from . import autopilot, resident

    # Do not pass Observer's live in-memory state across the thread boundary.
    # resident.refresh() reloads the last atomically persisted read-only snapshot.
    resident.refresh()
    autopilot.build_outbox()


def _maintenance_loop(stop: threading.Event, fatal: list[BaseException]) -> None:
    from . import resident

    try:
        while not stop.is_set():
            try:
                maintenance_cycle()
            except RuntimeError:
                # Preserve the base worker's fail-closed behavior for expected
                # local state/config refusal conditions.
                pass
            if stop.is_set():
                break
            interval = float(resident.load_config()["refresh_interval_seconds"])
            stop.wait(max(1.0, interval))
    except BaseException as error:  # pragma: no cover - surfaced by async wrapper
        fatal.append(error)


async def resident_worker(
    config: dict,
    stop: asyncio.Event,
    state: dict | None = None,
) -> None:
    """Run local maintenance without blocking the hot-room asyncio workers."""
    del config, state
    thread_stop = threading.Event()
    fatal: list[BaseException] = []
    thread = threading.Thread(
        target=_maintenance_loop,
        args=(thread_stop, fatal),
        name=_THREAD_NAME,
        daemon=True,
    )
    thread.start()
    try:
        while not stop.is_set():
            if fatal:
                raise fatal[0]
            if not thread.is_alive():
                raise RuntimeError("resident maintenance thread stopped unexpectedly")
            try:
                await asyncio.wait_for(stop.wait(), timeout=CHECK_INTERVAL_SECONDS)
            except TimeoutError:
                pass
    finally:
        # Never make systemd wait for a long scoring cycle during shutdown.  The
        # thread is daemonized and all local file writes it can perform are atomic.
        thread_stop.set()


def install() -> None:
    """Install the isolated maintenance worker exactly once."""
    global _INSTALLED
    if _INSTALLED:
        return
    observer.resident_worker = resident_worker
    _INSTALLED = True
