"""Safe bootstrap for the approved one-shot hrnb reply.

The ordinary room read returns the newest tail, so a busy discovery room can
hide the exact older source seq even while it remains retained.  This bootstrap
verifies the source invitation and duplicate request_id against the byte-exact
retained room export, then delegates signing/posting to sonnet_hrnb_reply.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime

from flop_agent import core
from flop_agent.public_record import verify_signed_record

try:
    from flop_agent import sonnet_hrnb_reply as lane
except ImportError:  # Production execution extracts the reviewed lane into /run.
    import sonnet_hrnb_reply as lane  # type: ignore[no-redef]


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


def require_source(rows: list[dict]) -> dict:
    matches = [row for row in rows if row.get("seq") == lane.SOURCE_SEQ]
    if len(matches) != 1:
        raise BootstrapError("source_offer_missing_or_duplicate")
    row = matches[0]
    if row.get("from") != lane.TARGET_DID:
        raise BootstrapError("source_offer_sender_mismatch")
    try:
        verify_signed_record(lane.ROOM, row)
        body = json.loads(row.get("text", ""))
        datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
    except (KeyError, ValueError, TypeError, RuntimeError) as error:
        raise BootstrapError("source_offer_invalid") from error
    if body != lane.SOURCE_PAYLOAD:
        raise BootstrapError("source_offer_payload_mismatch")
    return row


def find_existing_reply(rows: list[dict]) -> dict | None:
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
            raise BootstrapError("existing_reply_conflict")
        found.append(row)
    if len(found) > 1:
        raise BootstrapError("existing_reply_duplicate")
    return found[0] if found else None


def run_once() -> dict:
    rows = read_export_rows()
    source = require_source(rows)
    existing = find_existing_reply(rows)
    if existing is not None:
        return {
            "status": "existing_reply_detected",
            "request_id": lane.REQUEST_ID,
            "seq": existing.get("seq"),
            "ts": existing.get("ts"),
        }
    lane.require_source_offer = lambda: source
    return lane.run_once()


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("hrnb reply bootstrap accepts no arguments")
    try:
        result = run_once()
    except Exception:
        print(json.dumps({"ok": False, "error": "bootstrap_failed_closed"}))
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
