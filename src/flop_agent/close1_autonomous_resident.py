"""Low-pressure resident loop for non-binding Close Call execution rehearsal.

The process intentionally has no signer/Vault/post surface. It keeps Python
resident so short polling does not repeatedly spawn interpreters on the small
Production host, stages one bounded public candidate, immediately revalidates
it, and records whether the full capture-to-handoff path met the five-second SLA.
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
TRANSIENT_RETRY_SECONDS = 1.0
HOLD_RETRY_SECONDS = 10.0
MAX_CONSECUTIVE_ERRORS = 5
TARGET_CAPTURE_TO_HANDOFF_MS = 5_000
TRANSIENT_REASONS = {
    "close1_scanner_sweep_mismatch",
    "close1_room_empty",
    "close1_room_payload_invalid",
}
HOLD_REASONS = {
    "close1_auto_pending_reconcile_first",
    "close1_own_state_unreconciled",
}


def _now() -> datetime:
    return datetime.now(UTC)


def status_path() -> Path:
    return core.STATE / "close1" / "close1-autonomous-resident.json"


def _write_status(value: dict) -> None:
    observer.atomic_json_write(status_path(), value, compact=True, mode=0o660)


def _safe_reason(error: Exception) -> str:
    reason = str(error)
    return reason if reason.startswith("close1_") else "close1_auto_resident_cycle_failed"


def _detected_at_from_stage(*, now: datetime | None = None) -> datetime:
    value, _ = rehearsal._load_stage(now=now)
    return rehearsal._time(value["detected_at"])


def _rehearsal_result(
    *,
    detected_at: datetime,
    stage_status: str,
    trade_id: str | None,
    now: datetime | None,
) -> dict:
    rehearsal_result = rehearsal.run_once(now=now)
    completed = now or _now()
    completed = completed.astimezone(UTC)
    elapsed_ms = int((completed - detected_at).total_seconds() * 1000)
    result = {
        "schema_version": SCHEMA_VERSION,
        "status": "REHEARSAL_COMPLETE",
        "non_binding": True,
        "stage_status": stage_status,
        "rehearsal": rehearsal_result,
        "capture_to_handoff_complete_ms": elapsed_ms,
        "target_capture_to_handoff_ms": TARGET_CAPTURE_TO_HANDOFF_MS,
        "target_met": elapsed_ms <= TARGET_CAPTURE_TO_HANDOFF_MS,
        "evaluated_at": completed.isoformat(),
    }
    if trade_id is not None:
        result["trade_id"] = trade_id
    _write_status(result)
    return result


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
        detected_at = _detected_at_from_stage(now=now)
        return _rehearsal_result(
            detected_at=detected_at,
            stage_status="preexisting",
            trade_id=None,
            now=now,
        )

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

    detected_at = _detected_at_from_stage(now=now)
    return _rehearsal_result(
        detected_at=detected_at,
        stage_status="fresh",
        trade_id=staged["trade_id"],
        now=now,
    )


def _exception_status(reason: str, *, errors: int) -> tuple[dict, float, int]:
    if reason in TRANSIENT_REASONS:
        status = "TRANSIENT_RETRY"
        delay = TRANSIENT_RETRY_SECONDS
        next_errors = 0
    elif reason in HOLD_REASONS:
        status = "HOLD"
        delay = HOLD_RETRY_SECONDS
        next_errors = 0
    else:
        status = "BLOCKED"
        delay = SCAN_INTERVAL_SECONDS
        next_errors = errors + 1
    result = {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "non_binding": True,
        "reason": reason,
        "consecutive_errors": next_errors,
        "evaluated_at": _now().isoformat(),
    }
    return result, delay, next_errors


def run_forever(*, sleep=time.sleep) -> int:
    errors = 0
    while True:
        try:
            result = run_cycle()
        except Exception as error:
            reason = _safe_reason(error)
            blocked, delay, errors = _exception_status(reason, errors=errors)
            _write_status(blocked)
            print(json.dumps(blocked, sort_keys=True), flush=True)
            if blocked["status"] == "BLOCKED" and errors >= MAX_CONSECUTIVE_ERRORS:
                return 1
            sleep(delay)
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
