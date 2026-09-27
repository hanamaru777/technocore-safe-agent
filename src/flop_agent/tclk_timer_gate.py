"""Minimal fail-open prerequisite gate for periodic first-pilot tclk helpers.

The gate optimizes only the proven WAIT/idle case.  It never attempts to replace
the existing helper's validation once prerequisite state exists.

Exit 0: run the existing helper.
Exit 1: prerequisite state proves there is no work yet.
Unreadable, malformed, or ambiguous state fails open (exit 0).
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

MIN_STAGE_MS = 300_000
MIN_PREPARE_MS = 120_000
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
    if not path.is_dir():
        raise GateAmbiguous("state_path_invalid")
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
        expires_ms = record.get("expires_ms")
        accepted = record.get("accepted")
        if not isinstance(expires_ms, int) or accepted is not False:
            raise GateAmbiguous("review_store_invalid")
        if expires_ms - now_ms >= MIN_STAGE_MS:
            return True
    return False


def _preparer(root: Path, now_ms: int) -> bool:
    stages = _json_files(root / "autopilot" / "tclk-pilot" / "stages")
    if not stages:
        return False
    # Only confidently skip when every retained stage is already outside the
    # existing PREPARE window. Any live/ambiguous stage delegates to the full helper.
    for path in stages:
        stage = _load(path)
        expires_ms = stage.get("expires_ms")
        if not isinstance(expires_ms, int):
            raise GateAmbiguous("stage_invalid")
        if expires_ms - now_ms >= MIN_PREPARE_MS:
            return True
    return False


def _has_prerequisite(root: Path, relative: tuple[str, ...]) -> bool:
    return bool(_json_files(root.joinpath(*relative)))


def _lock(root: Path, _now_ms: int) -> bool:
    return _has_prerequisite(root, ("autopilot", "tclk-pilot", "previews"))


def _work(root: Path, _now_ms: int) -> bool:
    return _has_prerequisite(root, ("autopilot", "tclk-pilot", "locks"))


def _reveal(root: Path, _now_ms: int) -> bool:
    return _has_prerequisite(root, ("autopilot", "tclk-pilot", "work"))


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
        # Fail open: existing typed helper remains the validation authority.
        run = True
    raise SystemExit(0 if run else 1)


if __name__ == "__main__":
    main()
