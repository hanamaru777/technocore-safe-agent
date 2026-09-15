"""Retained-export bootstrap for the fixed BRUCELEAD-2 application.

The normal room reader returns the newest tail after applying ``since``.  In a
busy discovery room that can hide the exact older source seq even while it is
still retained.  This wrapper verifies the source offer and duplicate request
against the byte-exact retained room export, then delegates the actual fixed
sign/post state machine to :mod:`sonnet_brucelead2_application`.

The first export snapshot is shared by duplicate reconciliation and the
pre-sign offer gate.  A second fresh export is required immediately before the
irreversible POST.  Each export fetch has a hard wall-clock deadline in addition
to httpx transport timeouts.
"""
from __future__ import annotations

import json
import signal
import sys
from datetime import UTC, datetime
from types import FrameType

from flop_agent import core
from flop_agent.public_record import verify_signed_record

try:
    from flop_agent import sonnet_brucelead2_application as lane
except ImportError:  # Production execution extracts the reviewed lane into /run.
    import sonnet_brucelead2_application as lane  # type: ignore[no-redef]


class BootstrapError(RuntimeError):
    pass


EXPORT_WALL_CLOCK_SECONDS = 25


def _alarm(_signum: int, _frame: FrameType | None) -> None:
    raise TimeoutError("export_wall_clock_timeout")


def read_export_rows() -> list[dict]:
    old_handler = signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, EXPORT_WALL_CLOCK_SECONDS)
    try:
        timeout = core.httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0)
        response = core.httpx.get(f"{core.BASE_URL}/r/{lane.ROOM}/export", timeout=timeout)
        response.raise_for_status()
        text = response.text
    except Exception as error:
        raise BootstrapError("export_read_failed") from error
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)

    rows: list[dict] = []
    for raw in text.splitlines():
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


def _decode(row: dict) -> dict | None:
    try:
        value = json.loads(row.get("text", ""))
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def require_source(rows: list[dict], *, now: datetime | None = None) -> dict:
    matches = [row for row in rows if row.get("seq") == lane.SOURCE_SEQ]
    if len(matches) != 1:
        raise BootstrapError("source_offer_missing_or_duplicate")
    row = matches[0]
    try:
        verify_signed_record(lane.ROOM, row)
        body = _decode(row)
        source_time = lane._stamp(row.get("ts"))
    except Exception as error:
        raise BootstrapError("source_offer_invalid") from error
    if body is None or body.get("request_id") != lane.SOURCE_REQUEST_ID:
        raise BootstrapError("source_offer_binding_invalid")
    target = body.get("target_did")
    if target is not None and target != lane.DID:
        raise BootstrapError("source_offer_target_mismatch")
    visible = (str(body.get("text") or "") + " " + str(row.get("text") or "")).lower()
    for required in ("brucelead-2", "current seat offer", "d-sonnet-2-team-brucelead-2"):
        if required not in visible:
            raise BootstrapError("source_offer_binding_invalid")
    sender = row.get("from")
    if not isinstance(sender, str) or sender == lane.DID:
        raise BootstrapError("source_offer_sender_invalid")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    age = (current - source_time).total_seconds()
    if not 0 <= age <= lane.MAX_OFFER_AGE_SECONDS:
        raise BootstrapError("source_offer_stale")
    return row


def require_not_closed(rows: list[dict], source: dict) -> None:
    sender = source.get("from")
    close_terms = ("team full", "seats filled", "no seats", "offer closed", "offer withdrawn")
    for row in rows:
        if row.get("from") != sender or type(row.get("seq")) is not int or row["seq"] <= lane.SOURCE_SEQ:
            continue
        try:
            verify_signed_record(lane.ROOM, row)
        except Exception:
            continue
        body = _decode(row)
        text = (str(body.get("text") if body else "") + " " + str(row.get("text") or "")).lower()
        if lane.GAME_ID in text and any(term in text for term in close_terms):
            raise BootstrapError("source_offer_withdrawn_or_full")


def find_existing(rows: list[dict], state: dict) -> dict | None:
    found: list[dict] = []
    for row in rows:
        if row.get("from") != lane.DID:
            continue
        try:
            verify_signed_record(lane.ROOM, row)
            body = _decode(row)
        except Exception:
            continue
        if body is None or body.get("request_id") != lane.REQUEST_ID:
            continue
        if body != lane.PAYLOAD or row.get("text") != lane.render():
            raise BootstrapError("existing_application_conflict")
        if type(row.get("seq")) is not int or not isinstance(row.get("ts"), str):
            raise BootstrapError("existing_application_invalid")
        found.append(row)
    if len(found) > 1:
        raise BootstrapError("existing_application_duplicate")
    if not found:
        return None
    row = found[0]
    if state.get("state") in {"attempting", "ambiguous"} and str(row.get("nonce")) != state.get("nonce"):
        raise BootstrapError("existing_application_conflict")
    return row


def run_once() -> dict:
    cache: dict[str, list[dict] | None] = {"rows": None}

    def reconcile(state: dict) -> dict | None:
        rows = read_export_rows()
        source = require_source(rows)
        require_not_closed(rows, source)
        cache["rows"] = rows
        return find_existing(rows, state)

    def live_offer() -> dict:
        rows = cache.get("rows")
        if rows is not None:
            cache["rows"] = None
        else:
            rows = read_export_rows()
        source = require_source(rows)
        require_not_closed(rows, source)
        return source

    lane.reconcile_existing = reconcile
    lane.require_live_offer = live_offer
    return lane.run_once()


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("BRUCELEAD-2 v2 application accepts no arguments")
    try:
        result = run_once()
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
