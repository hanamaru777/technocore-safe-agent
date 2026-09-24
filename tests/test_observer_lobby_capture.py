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


def test_first_available_seq_finds_bounded_local_suffix(tmp_path):
    path = tmp_path / "capture.sqlite3"
    connection = capture._connect(path)
    try:
        capture.store_rows(
            connection,
            [
                {"seq": 30, "text": "a"},
                {"seq": 40, "text": "b"},
                {"seq": 50, "text": "c"},
            ],
        )
    finally:
        connection.close()

    assert capture.first_available_seq(1, path=path) == 30
    assert capture.first_available_seq(31, path=path) == 40
    assert capture.first_available_seq(31, 39, path) is None
    assert capture.first_available_seq(31, 40, path) == 40
    assert capture.first_available_seq(51, path=path) is None


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



def _seqs(path):
    connection = sqlite3.connect(path)
    try:
        return [
            int(row[0])
            for row in connection.execute("SELECT seq FROM messages ORDER BY seq").fetchall()
        ]
    finally:
        connection.close()


def test_prune_never_deletes_unread_rows(tmp_path, monkeypatch):
    path = tmp_path / "capture.sqlite3"
    connection = capture._connect(path)
    try:
        capture.store_rows(
            connection,
            [{"seq": seq, "text": str(seq)} for seq in range(1, 7)],
        )
        monkeypatch.setattr(capture, "MAX_ROWS", 3)

        # Latest-three policy alone would keep only 4..6. Rich Observer has consumed
        # through 2, so seq 3 is still protected and must survive.
        assert capture._prune(connection, observer_cursor=2) == 4
    finally:
        connection.close()

    assert _seqs(path) == [3, 4, 5, 6]


def test_prune_returns_to_soft_target_after_observer_advances(tmp_path, monkeypatch):
    path = tmp_path / "capture.sqlite3"
    connection = capture._connect(path)
    try:
        capture.store_rows(
            connection,
            [{"seq": seq, "text": str(seq)} for seq in range(1, 7)],
        )
        monkeypatch.setattr(capture, "MAX_ROWS", 3)

        assert capture._prune(connection, observer_cursor=5) == 3
    finally:
        connection.close()

    assert _seqs(path) == [4, 5, 6]


def test_prune_fails_closed_when_observer_cursor_is_unknown(tmp_path, monkeypatch):
    path = tmp_path / "capture.sqlite3"
    connection = capture._connect(path)
    try:
        capture.store_rows(
            connection,
            [{"seq": seq, "text": str(seq)} for seq in range(1, 7)],
        )
        monkeypatch.setattr(capture, "MAX_ROWS", 3)

        assert capture._prune(connection, observer_cursor=0) == 6
    finally:
        connection.close()

    assert _seqs(path) == [1, 2, 3, 4, 5, 6]


def test_hard_capacity_pauses_until_safe_prune_can_free_rows(tmp_path, monkeypatch):
    path = tmp_path / "capture.sqlite3"
    connection = capture._connect(path)
    try:
        capture.store_rows(
            connection,
            [{"seq": seq, "text": str(seq)} for seq in range(1, 9)],
        )
        monkeypatch.setattr(capture, "MAX_ROWS", 3)
        monkeypatch.setattr(capture, "MAX_PROTECTED_ROWS", 5)

        # Observer is too far behind: safe pruning can remove consumed 1..2 only,
        # leaving six protected rows, so capture must pause rather than delete them.
        assert capture._protected_backlog_full(connection, observer_cursor=2) is True
        assert [
            int(row[0])
            for row in connection.execute("SELECT seq FROM messages ORDER BY seq")
        ] == [3, 4, 5, 6, 7, 8]

        # Once Observer advances, the same safe prune can return to the normal
        # three-row target and capture may resume automatically.
        assert capture._protected_backlog_full(connection, observer_cursor=6) is False
        assert [
            int(row[0])
            for row in connection.execute("SELECT seq FROM messages ORDER BY seq")
        ] == [6, 7, 8]
    finally:
        connection.close()


def test_capture_checks_protected_capacity_before_network_fetch():
    import inspect

    source = inspect.getsource(capture.capture_process)
    assert source.index("if row_count >= MAX_PROTECTED_ROWS") < source.index("_fetch_live(client, cursor)")
    assert "row_count = _prune(connection)" in source
    assert "protected_backlog_capacity" in source
