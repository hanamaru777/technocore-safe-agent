import json

import pytest

from flop_agent import core
from flop_agent import sonnet_hrnb_reply as lane
from flop_agent import sonnet_hrnb_reply_v2 as bootstrap


def source_row():
    return {
        "from": lane.TARGET_DID,
        "nonce": "1789446281418",
        "text": json.dumps(lane.SOURCE_PAYLOAD, separators=(",", ":")),
        "sig": "source-sig",
        "seq": lane.SOURCE_SEQ,
        "ts": "2026-09-15T04:24:43.212561Z",
    }


def test_export_source_is_found_even_with_many_newer_rows(monkeypatch):
    rows = [source_row()] + [
        {"from": "did:key:z6Mkother", "nonce": str(i), "text": "x", "sig": "s", "seq": lane.SOURCE_SEQ + i, "ts": "2026-09-15T04:25:00Z"}
        for i in range(1, 401)
    ]
    monkeypatch.setattr(bootstrap, "verify_signed_record", lambda *args, **kwargs: None)
    assert bootstrap.require_source(rows)["seq"] == lane.SOURCE_SEQ


def test_existing_exact_reply_blocks_second_post(monkeypatch):
    exact = {
        "from": lane.DID,
        "nonce": "1789447000000",
        "text": lane.render(),
        "sig": "reply-sig",
        "seq": 99001,
        "ts": "2026-09-15T04:30:00Z",
    }
    monkeypatch.setattr(bootstrap, "read_export_rows", lambda: [source_row(), exact])
    monkeypatch.setattr(bootstrap, "verify_signed_record", lambda *args, **kwargs: None)
    monkeypatch.setattr(lane, "run_once", lambda: pytest.fail("must not post twice"))
    result = bootstrap.run_once()
    assert result["status"] == "existing_reply_detected"
    assert result["seq"] == 99001


def test_missing_source_fails_closed(monkeypatch):
    monkeypatch.setattr(bootstrap, "verify_signed_record", lambda *args, **kwargs: None)
    with pytest.raises(bootstrap.BootstrapError, match="source_offer_missing_or_duplicate"):
        bootstrap.require_source([])


def test_export_reader_uses_retained_export(monkeypatch):
    payload = json.dumps(source_row()) + "\n"

    class Response:
        text = payload
        def raise_for_status(self):
            return None

    def get(url, *, timeout):
        assert url == f"{core.BASE_URL}/r/{lane.ROOM}/export"
        assert timeout == 20
        return Response()

    monkeypatch.setattr(core.httpx, "get", get)
    assert bootstrap.read_export_rows() == [source_row()]
