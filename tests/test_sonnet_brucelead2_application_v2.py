import json
from datetime import UTC, datetime

import pytest

from flop_agent import sonnet_brucelead2_application as lane
from flop_agent import sonnet_brucelead2_application_v2 as v2


def _offer(*, seq=lane.SOURCE_SEQ, sender="did:key:z6MkBruce", text=None, request_id=lane.SOURCE_REQUEST_ID):
    body = {
        "type": "sonnet.reply.v1",
        "request_id": request_id,
        "target_did": lane.DID,
        "text": text
        or (
            "BRUCELEAD-2 — current seat offer. 3 external seats open. "
            "Room: d-sonnet-2-team-brucelead-2"
        ),
    }
    return {
        "from": sender,
        "seq": seq,
        "ts": "2026-09-15T10:54:00Z",
        "nonce": "123",
        "sig": "sig",
        "text": json.dumps(body, sort_keys=True, separators=(",", ":")),
    }


def _state():
    return lane.new_state()


def test_require_source_uses_exact_retained_seq(monkeypatch):
    source = _offer()
    monkeypatch.setattr(v2, "verify_signed_record", lambda room, row: None)
    result = v2.require_source([_offer(seq=105000), source, _offer(seq=105500)], now=datetime(2026, 9, 15, 11, 0, tzinfo=UTC))
    assert result is source


def test_require_source_rejects_missing_source(monkeypatch):
    monkeypatch.setattr(v2, "verify_signed_record", lambda room, row: None)
    with pytest.raises(v2.BootstrapError, match="source_offer_missing_or_duplicate"):
        v2.require_source([_offer(seq=lane.SOURCE_SEQ + 1)], now=datetime(2026, 9, 15, 11, 0, tzinfo=UTC))


def test_require_not_closed_scans_all_later_export_rows(monkeypatch):
    source = _offer()
    closed = _offer(
        seq=lane.SOURCE_SEQ + 600,
        text="BRUCELEAD-2 team full — no seats remain.",
        request_id="brucelead-2-close-1",
    )
    monkeypatch.setattr(v2, "verify_signed_record", lambda room, row: None)
    with pytest.raises(v2.BootstrapError, match="source_offer_withdrawn_or_full"):
        v2.require_not_closed([source, closed], source)


def test_find_existing_reconciles_exact_request(monkeypatch):
    state = _state()
    existing = {
        "from": lane.DID,
        "seq": lane.SOURCE_SEQ + 1,
        "ts": "2026-09-15T11:00:00Z",
        "nonce": "999",
        "sig": "sig",
        "text": lane.render(),
    }
    monkeypatch.setattr(v2, "verify_signed_record", lambda room, row: None)
    assert v2.find_existing([_offer(), existing], state) is existing


def test_run_once_reuses_first_export_pre_sign_and_refetches_before_post(monkeypatch):
    source = _offer()
    calls = []
    snapshots = [[source], [source]]

    def export_rows():
        calls.append("export")
        return snapshots.pop(0)

    monkeypatch.setattr(v2, "read_export_rows", export_rows)
    monkeypatch.setattr(v2, "verify_signed_record", lambda room, row: None)

    observed = {}

    def delegated_run_once():
        state = _state()
        assert lane.reconcile_existing(state) is None
        observed["pre"] = lane.require_live_offer()["seq"]
        observed["post"] = lane.require_live_offer()["seq"]
        return {"status": "test"}

    monkeypatch.setattr(lane, "run_once", delegated_run_once)
    assert v2.run_once() == {"status": "test"}
    assert observed == {"pre": lane.SOURCE_SEQ, "post": lane.SOURCE_SEQ}
    assert calls == ["export", "export"]
