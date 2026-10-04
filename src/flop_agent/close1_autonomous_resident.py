"""Low-pressure resident loop for non-binding Close Call execution rehearsal.

The process intentionally has no signer/Vault/post surface.  It keeps Python
resident so short polling does not repeatedly spawn interpreters on the small
Production host, stages one bounded public candidate, immediately revalidates
it, and records whether the handoff would have met the five-second SLA.
"""
from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path

from . import close1_autonomous_rehearsal as rehearsal
from . import close1_autonomous_stage as stage
from . import close_call, core, observer

SCHEMA_VERSION = 1
SCAN_INTERVAL_SECONDS = 2.0
MAX_CONSECUTIVE_ERRORS = 5
TARGET_CAPTURE_TO_HANDOFF_MS = 5_000


def _now() -> datetime:
    return datetime.now(UTC)


def status_path() -> Path:
    return core.STATE / "close1" / "close1-autonomous-resident.json"


def _write_status(value: dict) -> None:
    observer.atomic_json_write(status_path(), value, compact=True, mode=0o660)


def _safe_reason(error: Exception) -> str:
    reason = str(error)
    return reason if reason.startswith("close1_") else "close1_auto_resident_cycle_failed"


def run_cycle(*, now: datetime | None = None) -> dict:
    started = now or _now()
    if started.tzinfo is None:
        raise ValueError("close1_auto_resident_time_timezone_required")
    started = started.astimezone(UTC)
    if started >= close_call.LOCK:
        result = {
            "schema_version": SCHEMA_VERSION,
            "status": "LOCKED",
            "non_binding": True,
            "evaluated_at": started.isoformat(),
        }
        _write_status(result)
        return result

    # Drain a previously staged valid candidate before scanning another one.
    if stage.stage_path().exists():
        rehearsal_result = rehearsal.run_once(now=now)
        completed = now or _now()
        result = {
            "schema_version": SCHEMA_VERSION,
            "status": "REHEARSAL_COMPLETE",
            "non_binding": True,
            "stage_status": "preexisting",
            "rehearsal": rehearsal_result,
            "cycle_to_handoff_complete_ms": int(
                (completed.astimezone(UTC) - started).total_seconds() * 1000
            ),
            "target_capture_to_handoff_ms": TARGET_CAPTURE_TO_HANDOFF_MS,
            "evaluated_at": completed.astimezone(UTC).isoformat(),
        }
        result["target_met"] = (
            result["cycle_to_handoff_complete_ms"] <= TARGET_CAPTURE_TO_HANDOFF_MS
        )
        _write_status(result)
        return result

    staged = stage.run_once()
    if staged.get("status") != "staged":
        result = {
            "schema_version": SCHEMA_VERSION,
            "status": "NO_CANDIDATE",
            "non_binding": True,
            "evaluated_at": (now or _now()).astimezone(UTC).isoformat(),
        }
        _write_status(result)
        return result

    rehearsal_result = rehearsal.run_once(now=now)
    completed = now or _now()
    elapsed_ms = int((completed.astimezone(UTC) - started).total_seconds() * 1000)
    result = {
        "schema_version": SCHEMA_VERSION,
        "status": "REHEARSAL_COMPLETE",
        "non_binding": True,
        "stage_status": "fresh",
        "trade_id": staged["trade_id"],
        "rehearsal": rehearsal_result,
        "cycle_to_handoff_complete_ms": elapsed_ms,
        "target_capture_to_handoff_ms": TARGET_CAPTURE_TO_HANDOFF_MS,
        "target_met": elapsed_ms <= TARGET_CAPTURE_TO_HANDOFF_MS,
        "evaluated_at": completed.astimezone(UTC).isoformat(),
    }
    _write_status(result)
    return result


def run_forever(*, sleep=time.sleep) -> int:
    errors = 0
    while True:
        try:
            result = run_cycle()
        except Exception as error:
            errors += 1
            blocked = {
                "schema_version": SCHEMA_VERSION,
                "status": "BLOCKED",
                "non_binding": True,
                "reason": _safe_reason(error),
                "consecutive_errors": errors,
                "evaluated_at": _now().isoformat(),
            }
            _write_status(blocked)
            print(json.dumps(blocked, sort_keys=True), flush=True)
            if errors >= MAX_CONSECUTIVE_ERRORS:
                return 1
            sleep(SCAN_INTERVAL_SECONDS)
            continue

        errors = 0
        print(json.dumps(result, sort_keys=True), flush=True)
        if result["status"] == "LOCKED":
            return 0
        sleep(SCAN_INTERVAL_SECONDS)


def main() -> int:
    return run_forever()


if __name__ == "__main__":
    raise SystemExit(main())
