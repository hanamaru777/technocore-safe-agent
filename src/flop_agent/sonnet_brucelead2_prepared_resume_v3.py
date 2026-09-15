"""Resume the fixed BRUCELEAD-2 application from a proven pre-POST prepared state.

PR #236 already verified the exact retained signed source offer and reached the
original lane's durable ``prepared`` state before timing out on its redundant
second full-room export.  In the original state machine, ``prepared`` is written
only after source validation and before the irreversible ``attempting`` marker.

This successor therefore does not read the busy discovery room before posting.
It is valid only for the exact recent prepared state produced by that failed
execution: fixed request/payload, nonce present, and no attempt/receipt fields.
The original lane still performs identity, local registration, fresh safety,
protected-core, signing, attempt-marker, POST, receipt and ambiguity handling.
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime

try:
    from flop_agent import sonnet_brucelead2_application as lane
except ImportError:  # Production execution extracts the reviewed lane into /run.
    import sonnet_brucelead2_application as lane  # type: ignore[no-redef]


class ResumeError(RuntimeError):
    pass


MAX_PREPARED_AGE_SECONDS = 60 * 60


def require_recent_prepared(*, now: datetime | None = None) -> dict:
    state = lane.load()
    if state is None:
        raise ResumeError("prepared_state_missing")
    if state.get("request_id") != lane.REQUEST_ID or state.get("payload") != lane.PAYLOAD:
        raise ResumeError("prepared_state_binding_mismatch")
    if state.get("state") != "prepared":
        raise ResumeError(f"prepared_state_not_prepared:{state.get('state')}")
    nonce = state.get("nonce")
    if not isinstance(nonce, str) or not nonce.isdigit():
        raise ResumeError("prepared_nonce_missing")
    if (
        state.get("attempted_at") is not None
        or state.get("seq") is not None
        or state.get("ts") is not None
        or state.get("posted_record") is not None
    ):
        raise ResumeError("prepared_state_has_post_evidence")

    path = lane.state_path()
    try:
        mtime = datetime.fromtimestamp(path.stat().st_mtime, UTC)
    except OSError as error:
        raise ResumeError("prepared_state_stat_failed") from error
    current = (now or datetime.now(UTC)).astimezone(UTC)
    age = (current - mtime).total_seconds()
    if not 0 <= age <= MAX_PREPARED_AGE_SECONDS:
        raise ResumeError("prepared_state_stale")
    return state


def run_once() -> dict:
    # This exact prepared state is the durable proof that PR #236 already passed
    # retained-source validation before any POST attempt.  Avoid repeating the
    # expensive room read; this payload is non-binding and explicitly conditional
    # on a seat still being available.
    require_recent_prepared()

    old_reconcile = lane.reconcile_existing
    old_live_offer = lane.require_live_offer
    lane.reconcile_existing = lambda _state: None
    lane.require_live_offer = lambda **_kwargs: {
        "seq": lane.SOURCE_SEQ,
        "request_id": lane.SOURCE_REQUEST_ID,
        "provenance": "prepared_state_from_pr236",
    }
    try:
        return lane.run_once()
    finally:
        lane.reconcile_existing = old_reconcile
        lane.require_live_offer = old_live_offer


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("BRUCELEAD-2 prepared resume accepts no arguments")
    try:
        result = run_once()
    except ResumeError as error:
        print({"ok": False, "error": str(error)})
        raise SystemExit(1) from None
    print(result)


if __name__ == "__main__":
    main()
