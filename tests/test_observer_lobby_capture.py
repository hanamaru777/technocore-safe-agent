from __future__ import annotations

import sqlite3

from flop_agent import observer_lobby_capture as capture


def test_spool_round_trip_and_complete_range(tmp_path):
    path = tmp_path / "capture.sqlite3"
    connection = capture._connect(path)
    try:
        assert capture.initialize_cursor(connection, 10) == 10
        rows = [
            {"seq": 11, "text": "a", "from": "did:key:test"},
            {"seq": 12, "text": "b", "from": "did:key:test"},
            {"seq": 13, "text": "c", "from": "did:key:test"},
        ]
        assert capture.store_rows(connection, rows) == 3
        assert capture._advance_contiguous(connection, 10) == 13
    finally:
        connection.close()

    assert capture.range_complete(11, 13, path)
    assert not capture.range_complete(10, 13, path)
    assert [row["seq"] for row in capture.read_range(11, 13, path)] == [11, 12, 13]
    assert capture.contiguous_end(11, path) == 13


def test_incomplete_range_fails_closed(tmp_path):
    path = tmp_path / "capture.sqlite3"
    connection = capture._connect(path)
    try:
        capture.store_rows(
            connection,
            [
                {"seq": 21, "text": "a"},
                {"seq": 23, "text": "c"},
            ],
        )
    finally:
        connection.close()

    assert not capture.range_complete(21, 23, path)
    assert capture.read_range(21, 23, path) == []
    assert capture.contiguous_end(21, path) == 21


def test_capture_budget_stays_below_combined_published_ceiling():
    # Production main Observer is currently capped at 300 reads/min. This capture
    # lane adds at most 250 reads/min, leaving headroom below the published 600/IP.
    assert capture.CAPTURE_READS_PER_MINUTE == 250
    assert capture.CAPTURE_READS_PER_MINUTE + 300 < 600


def test_capture_is_get_only_source():
    import inspect

    source = inspect.getsource(capture)
    assert ".post(" not in source
    assert "subprocess" not in source
    assert "SIGN_SEED" not in source
