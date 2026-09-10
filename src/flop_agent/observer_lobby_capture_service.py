"""Standalone service handoff for the read-only lobby capture lane.

PR #88 production acceptance proved that keeping lobby capture as a Resident child
still creates a continuity hole during every Resident restart: the shock absorber
stops at exactly the moment the hot room can outrun server retention.

This module moves that capture lane behind its own systemd lifecycle.  The first
standalone start copies the legacy SQLite spool with SQLite's online backup API into
a new service-owned spool, then keeps capturing there.  The still-running legacy
Resident child can continue writing the old spool during this bootstrap, so the new
lane can be proven fresh before Resident is restarted.  A new Resident switches its
read-side capture module to the service spool during startup.

The service is GET/read-only with respect to Technocore.  It performs no signing,
posting, shell execution, URL following, secret access, or historical counter
rewrite.
"""
from __future__ import annotations

import os
import signal
import sqlite3
import threading
from pathlib import Path

from . import (
    observer,
    observer_lobby_capture as capture,
    observer_lobby_capture_request_deadline,
)

LEGACY_DB_NAME = "lobby-capture.sqlite3"
SERVICE_DB_NAME = "lobby-capture-service.sqlite3"
_BOOTSTRAP_SUFFIX = ".bootstrap"
_INSTALLED = False


def legacy_path() -> Path:
    return observer.observer_dir() / LEGACY_DB_NAME


def service_path() -> Path:
    return observer.observer_dir() / SERVICE_DB_NAME


def install_reader() -> None:
    """Point all capture helpers in this process at the standalone service spool."""
    global _INSTALLED
    capture.DB_NAME = SERVICE_DB_NAME
    _INSTALLED = True


def bootstrap_from_legacy(
    *,
    source: Path | None = None,
    target: Path | None = None,
) -> bool:
    """Atomically seed the service spool from the live legacy SQLite snapshot once."""
    source_path = source or legacy_path()
    target_path = target or service_path()
    if target_path.exists() or not source_path.exists():
        return False

    target_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = target_path.with_name(target_path.name + _BOOTSTRAP_SUFFIX)
    try:
        temp_path.unlink(missing_ok=True)
        source_conn = sqlite3.connect(
            f"file:{source_path.as_posix()}?mode=ro",
            uri=True,
            timeout=2.0,
        )
        destination = sqlite3.connect(str(temp_path), timeout=2.0)
        try:
            source_conn.backup(destination)
            destination.commit()
        finally:
            destination.close()
            source_conn.close()

        # Hard-link publish is atomic and refuses to overwrite a spool that another
        # service instance may have created while the backup was running.
        try:
            os.link(temp_path, target_path)
        except FileExistsError:
            return False
        return True
    finally:
        temp_path.unlink(missing_ok=True)


def main() -> None:
    bootstrap_from_legacy()
    install_reader()
    observer_lobby_capture_request_deadline.install()
    stop = threading.Event()

    def request_stop(_signum, _frame) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    capture.capture_process(stop)


if __name__ == "__main__":
    main()
