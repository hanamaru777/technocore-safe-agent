"""Retained-export bootstrap for the approved one-shot Mitsuri contact.

The discovery room is busy and an ordinary tail read can hide an older matching
request. Before any signing/posting, scan the retained export for the exact fixed
request_id. If an exact prior post exists, report it without signing. Any conflict
or duplicate fails closed.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime

from flop_agent import core
from flop_agent.public_record import verify_signed_record

try:
    from flop_agent import sonnet_mitsuri_contact as lane
except ImportError:  # Production extracts the reviewed lane into /run.
    import sonnet_mitsuri_contact as lane  # type: ignore[no-redef]


class BootstrapError(RuntimeError):
    pass


def read_export_rows() -> list[dict]:
    response = core.httpx.get(f"{core.BASE_URL}/r/{lane.ROOM}/export", timeout=20)
    response.raise_for_status()
    rows: list[dict] = []
    for raw in response.text.splitlines():
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except (ValueError, TypeError) as error:
            raise BootstrapError("export_invalid") from error
        if not isinstance(row, dict):
            raise BootstrapError("export_invalid")
        rows.append(row)
    return rows


def find_existing(rows: list[dict]) -> dict | None:
    found: list[dict] = []
    for row in rows:
        if row.get("from") != lane.DID:
            continue
        try:
            verify_signed_record(lane.ROOM, row)
            body = json.loads(row.get("text", ""))
        except (ValueError, TypeError, RuntimeError):
            continue
        if not isinstance(body, dict) or body.get("request_id") != lane.REQUEST_ID:
            continue
        if body != lane.PAYLOAD or row.get("text") != lane.render():
            raise BootstrapError("existing_contact_conflict")
        try:
            datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
        except (KeyError, ValueError, TypeError) as error:
            raise BootstrapError("existing_contact_invalid") from error
        found.append(row)
    if len(found) > 1:
        raise BootstrapError("existing_contact_duplicate")
    return found[0] if found else None


def run_once() -> dict:
    rows = read_export_rows()
    existing = find_existing(rows)
    if existing is not None:
        return {
            "status": "existing_contact_detected",
            "request_id": lane.REQUEST_ID,
            "seq": existing.get("seq"),
            "ts": existing.get("ts"),
        }
    return lane.run_once()


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("Mitsuri contact bootstrap accepts no arguments")
    try:
        result = run_once()
    except Exception:
        print(json.dumps({"ok": False, "error": "bootstrap_failed_closed"}))
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
