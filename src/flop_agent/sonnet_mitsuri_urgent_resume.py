"""Resume the exact prepared urgent Mitsuri contact after a pre-POST timeout.

This module accepts only the durable `prepared` state produced by
sonnet_mitsuri_urgent_contact. It reuses the same immutable request, payload and
nonce. It performs no discovery-room read. The irreversible `attempting` marker
is persisted before the single POST; ambiguous outcomes are terminal.
"""
from __future__ import annotations

import json
import signal
import sys
from contextlib import contextmanager
from datetime import UTC, datetime

from flop_agent import core, oracle_signer
from flop_agent.public_record import verify_signed_record

try:
    import sonnet_mitsuri_urgent_contact as lane
except ImportError:
    from flop_agent import sonnet_mitsuri_urgent_contact as lane


class ResumeError(RuntimeError):
    pass


@contextmanager
def signing_deadline(seconds: int = 100):
    if not hasattr(signal, "SIGALRM"):
        yield
        return

    previous = signal.getsignal(signal.SIGALRM)

    def _timeout(_signum, _frame):
        raise ResumeError("signing_timeout")

    signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def require_exact_prepared(state: dict | None) -> dict:
    if state is None:
        raise ResumeError("prepared_state_missing")
    if (
        state.get("state") != "prepared"
        or state.get("request_id") != lane.REQUEST_ID
        or state.get("payload") != lane.PAYLOAD
        or not state.get("nonce")
        or state.get("attempted_at") is not None
        or state.get("seq") is not None
        or state.get("ts") is not None
        or state.get("posted_record") is not None
    ):
        raise ResumeError("prepared_state_not_exact")
    return state


def run_once() -> dict:
    with lane.contact_lock():
        lane.require_identity()
        lane.require_registration_posted()
        lane.require_safety()
        if not lane.OPEN <= datetime.now(UTC) < lane.CLOSE:
            raise ResumeError("contact_window_closed")

        state = require_exact_prepared(lane.load())
        text = lane.render()
        if core.clean_text(text) != text:
            raise ResumeError("text_invalid")

        with signing_deadline():
            signed = oracle_signer.with_vault_seed(
                lambda: core.invoke_signer("say", lane.ROOM, state["nonce"], text)
            )
        if len(signed) != 2 or signed[0] != lane.DID:
            raise ResumeError("did_mismatch")
        verify_signed_record(
            lane.ROOM,
            {"from": lane.DID, "nonce": state["nonce"], "text": text, "sig": signed[1]},
        )

        lane.require_identity()
        lane.require_safety()
        if not lane.OPEN <= datetime.now(UTC) < lane.CLOSE:
            raise ResumeError("contact_window_closed")

        # Irreversible boundary: from here onward a blind retry is forbidden.
        state["state"] = "attempting"
        state["attempted_at"] = oracle_signer.now()
        lane.save(state)

        try:
            response = core.httpx.post(
                f"{core.BASE_URL}/r/{lane.ROOM}?format=json",
                json={
                    "did": lane.DID,
                    "nonce": state["nonce"],
                    "text": text,
                    "sig": signed[1],
                },
                timeout=20,
            )
            response.raise_for_status()
            row = response.json().get("posted")
            if (
                not isinstance(row, dict)
                or row.get("from") != lane.DID
                or str(row.get("nonce")) != state["nonce"]
                or row.get("text") != text
                or row.get("sig") != signed[1]
                or type(row.get("seq")) is not int
                or not isinstance(row.get("ts"), str)
            ):
                raise ResumeError("receipt_mismatch")
            verify_signed_record(lane.ROOM, row)
            return lane.mark_posted(state, row)
        except BaseException:
            state["state"] = "ambiguous"
            state["posted_record"] = None
            lane.save(state)
            raise ResumeError("submission_unknown") from None


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("Mitsuri urgent resume accepts no arguments")
    try:
        print(json.dumps(run_once(), sort_keys=True))
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
