"""Lightweight fail-open prerequisite gate for periodic first-pilot tclk oneshots.

This module intentionally imports only the Python standard library.  It is executed by
systemd ExecCondition before the heavier application modules.  Exit 0 means "run the
existing service"; exit 1 means "confidently idle, skip this invocation".

Unreadable, malformed, or ambiguous local state always fails open (exit 0) so the
existing typed helper remains the authority for validation and error reporting.
"""
from __future__ import annotations

import json
import os
import re
import stat
import sys
import time
from pathlib import Path

MIN_STAGE_MS = 300_000
MIN_PREPARE_MS = 120_000
MAX_ACTIVITY_TAIL_BYTES = 2 * 1024 * 1024
_HEX32 = re.compile(r"^[0-9a-f]{32}$")


class GateAmbiguous(RuntimeError):
    """Local prerequisite state is not safe to classify as idle."""


def _root() -> Path:
    raw = os.environ.get("FLOP_STATE_DIR", "").strip()
    path = Path(raw)
    if not raw or not path.is_absolute():
        raise GateAmbiguous("state_dir_unavailable")
    return path


def _load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GateAmbiguous("state_unreadable") from error
    if not isinstance(value, dict):
        raise GateAmbiguous("state_invalid")
    return value


def _json_files(path: Path) -> list[Path]:
    if not path.exists():
        return []
    try:
        files = sorted(path.glob("*.json"))
    except OSError as error:
        raise GateAmbiguous("state_unreadable") from error
    for item in files:
        if not _HEX32.fullmatch(item.stem):
            raise GateAmbiguous("state_invalid")
    return files


def _stager(root: Path, now_ms: int) -> bool:
    path = root / "resident" / "tclk-review-evidence.json"
    if not path.exists():
        return False
    store = _load(path)
    records = store.get("records")
    if store.get("schema_version") != 1 or not isinstance(records, list):
        raise GateAmbiguous("review_store_invalid")
    for record in records:
        if not isinstance(record, dict):
            raise GateAmbiguous("review_store_invalid")
        offer_id = record.get("offer_id")
        frame_sha256 = record.get("frame_sha256")
        expires_ms = record.get("expires_ms")
        accepted = record.get("accepted")
        if (
            not isinstance(offer_id, str)
            or not isinstance(frame_sha256, str)
            or not isinstance(expires_ms, int)
            or accepted is not False
        ):
            raise GateAmbiguous("review_store_invalid")
        if expires_ms - now_ms >= MIN_STAGE_MS:
            return True
    return False


def _preparer(root: Path, now_ms: int) -> bool:
    stages = root / "autopilot" / "tclk-pilot" / "stages"
    previews = root / "autopilot" / "tclk-pilot" / "previews"
    material_dir = root / "signer" / "tclk-pilot-secrets"
    for path in _json_files(stages):
        stage = _load(path)
        expires_ms = stage.get("expires_ms")
        if not isinstance(expires_ms, int):
            raise GateAmbiguous("stage_invalid")
        if expires_ms - now_ms < MIN_PREPARE_MS:
            continue
        preview = previews / path.name
        material_file = material_dir / path.name
        if not preview.exists() or not material_file.exists():
            return True
    return False


def _activity_tail(root: Path) -> list[dict]:
    path = root / "activities.jsonl"
    if not path.exists():
        return []
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            if size > MAX_ACTIVITY_TAIL_BYTES:
                raise GateAmbiguous("activity_too_large_for_safe_gate")
            start = 0
            handle.seek(0)
            data = handle.read()
    except OSError as error:
        raise GateAmbiguous("activity_unreadable") from error
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise GateAmbiguous("activity_unreadable") from error
    rows: list[dict] = []
    for line in lines[-2000:]:
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise GateAmbiguous("activity_invalid") from error
        if not isinstance(value, dict):
            raise GateAmbiguous("activity_invalid")
        rows.append(value)
    return rows


def _lock(root: Path, _now_ms: int) -> bool:
    previews = root / "autopilot" / "tclk-pilot" / "previews"
    locks = root / "autopilot" / "tclk-pilot" / "locks"
    pending: list[str] = []
    for path in _json_files(previews):
        preview = _load(path)
        if not isinstance(preview.get("accept_line"), str):
            raise GateAmbiguous("preview_invalid")
        lock_path = locks / path.name
        if lock_path.exists():
            existing = _load(lock_path)
            if existing.get("status") != "lock_verified":
                raise GateAmbiguous("lock_invalid")
            continue
        pending.append(preview["accept_line"])
    if not pending:
        return False
    accepted = {
        row.get("text")
        for row in _activity_tail(root)
        if row.get("action") == "tclk_first_pilot_accept" and isinstance(row.get("text"), str)
    }
    return any(line in accepted for line in pending)


def _work(root: Path, _now_ms: int) -> bool:
    locks = root / "autopilot" / "tclk-pilot" / "locks"
    work = root / "autopilot" / "tclk-pilot" / "work"
    for path in _json_files(locks):
        lock = _load(path)
        if lock.get("status") != "lock_verified":
            raise GateAmbiguous("lock_invalid")
        work_path = work / path.name
        if not work_path.exists():
            return True
        existing = _load(work_path)
        if existing.get("status") not in {"work_ready", "work_failed"}:
            raise GateAmbiguous("work_invalid")
    return False


def _reveal(root: Path, _now_ms: int) -> bool:
    work = root / "autopilot" / "tclk-pilot" / "work"
    previews = root / "autopilot" / "tclk-pilot" / "reveal-previews"
    private = root / "signer" / "tclk-pilot-reveals"
    for path in _json_files(work):
        value = _load(path)
        status = value.get("status")
        if status not in {"work_ready", "work_failed"}:
            raise GateAmbiguous("work_invalid")
        if status != "work_ready":
            continue
        preview_path = previews / path.name
        private_path = private / path.name
        if not preview_path.exists():
            return True
        preview = _load(preview_path)
        if preview.get("status") != "prepared":
            raise GateAmbiguous("reveal_preview_invalid")
        try:
            info = private_path.stat()
        except OSError:
            return True
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            return True
    return False


_GATES = {
    "stager": _stager,
    "preparer": _preparer,
    "lock": _lock,
    "work": _work,
    "reveal": _reveal,
}


def should_run(mode: str, *, root: Path | None = None, now_ms: int | None = None) -> bool:
    gate = _GATES.get(mode)
    if gate is None:
        raise GateAmbiguous("mode_invalid")
    target = _root() if root is None else root
    current = int(time.time() * 1000) if now_ms is None else now_ms
    if not isinstance(current, int) or current < 0:
        raise GateAmbiguous("time_invalid")
    return gate(target, current)


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in _GATES:
        raise SystemExit(2)
    try:
        run = should_run(sys.argv[1])
    except GateAmbiguous:
        # Fail open: the existing full helper remains the validation authority.
        run = True
    raise SystemExit(0 if run else 1)


if __name__ == "__main__":
    main()
