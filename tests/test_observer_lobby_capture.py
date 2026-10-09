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


def test_capture_cursor_gap_stops_scanning_unread_suffix(tmp_path):
    """A large stored suffix after a hole must not be fetched every 240 ms."""
    connection = capture._connect(tmp_path / "gap.sqlite3")
    try:
        capture.store_rows(
            connection,
            [{"seq": seq, "text": "x"} for seq in range(12, 5212)],
        )

        class CountingCursor:
            def __init__(self, actual):
                self.actual = actual
                self.rows_consumed = 0

            def __iter__(self):
                return self

            def __next__(self):
                row = next(self.actual)
                self.rows_consumed += 1
                return row

            def close(self):
                self.actual.close()

        class CountingConnection:
            def __init__(self, actual):
                self.actual = actual
                self.queries = []

            def execute(self, sql, params=()):
                cursor = self.actual.execute(sql, params)
                if sql.startswith("SELECT seq FROM messages WHERE seq>?"):
                    metered = CountingCursor(cursor)
                    self.queries.append(metered)
                    return metered
                return cursor

            def commit(self):
                self.actual.commit()

        metered = CountingConnection(connection)
        assert capture._advance_contiguous(metered, 10) == 10
        assert len(metered.queries) == 1
        assert metered.queries[0].rows_consumed == 1
        assert capture._meta_get(connection, "capture_cursor") == "10"
        # The missing sequence remains unresolved; never jump to stored 12+.
        assert capture.contiguous_end(11, tmp_path / "gap.sqlite3") == 10
    finally:
        connection.close()


def test_capture_cursor_preserves_partial_and_multibatch_contiguity(tmp_path):
    connection = capture._connect(tmp_path / "batch.sqlite3")
    try:
        rows = [{"seq": seq, "text": "x"} for seq in range(1, 5002)]
        rows.extend([{"seq": 5003, "text": "after-gap"}])
        assert capture.store_rows(connection, rows) == 5002
        assert capture._advance_contiguous(connection, 0) == 5001
        assert capture._meta_get(connection, "capture_cursor") == "5001"
        assert capture._advance_contiguous(connection, 5001) == 5001

        # Only a genuine filled gap may advance into previously retained rows.
        assert capture.store_rows(connection, [{"seq": 5002, "text": "filled"}]) == 1
        assert capture._advance_contiguous(connection, 5001) == 5003
        assert capture._meta_get(connection, "capture_cursor") == "5003"
    finally:
        connection.close()


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


def test_prune_batches_large_safe_backlog_without_crossing_cursor(tmp_path, monkeypatch):
    path = tmp_path / "capture.sqlite3"
    connection = capture._connect(path)
    try:
        capture.store_rows(
            connection,
            [{"seq": seq, "text": str(seq)} for seq in range(1, 11)],
        )
        monkeypatch.setattr(capture, "MAX_ROWS", 3)
        monkeypatch.setattr(capture, "MAX_PRUNE_ROWS_PER_PASS", 2)

        # A cursor suddenly catching up must not issue one unbounded DELETE.
        assert capture._prune(connection, observer_cursor=9) == 8
        assert _seqs(path) == list(range(3, 11))
        assert capture._prune(connection, observer_cursor=9) == 6
        assert _seqs(path) == list(range(5, 11))
        assert capture._prune(connection, observer_cursor=9) == 4
        assert _seqs(path) == list(range(7, 11))
        assert capture._prune(connection, observer_cursor=9) == 3
        assert _seqs(path) == [8, 9, 10]
    finally:
        connection.close()


def test_bounded_prune_remains_fail_closed_on_unread_rows(tmp_path, monkeypatch):
    path = tmp_path / "capture.sqlite3"
    connection = capture._connect(path)
    try:
        capture.store_rows(
            connection,
            [{"seq": seq, "text": str(seq)} for seq in range(1, 9)],
        )
        monkeypatch.setattr(capture, "MAX_ROWS", 3)
        monkeypatch.setattr(capture, "MAX_PRUNE_ROWS_PER_PASS", 2)
        assert capture._prune(connection, observer_cursor=2) == 6
        assert _seqs(path) == [3, 4, 5, 6, 7, 8]
        assert capture._prune(connection, observer_cursor=2) == 6
        assert _seqs(path) == [3, 4, 5, 6, 7, 8]
        assert capture._prune(connection, observer_cursor=5) == 4
        assert _seqs(path) == [5, 6, 7, 8]
        assert capture._prune(connection, observer_cursor=5) == 3
        assert _seqs(path) == [6, 7, 8]
    finally:
        connection.close()


def test_bounded_capacity_only_resumes_after_safe_prune_below_hard_cap(tmp_path, monkeypatch):
    path = tmp_path / "capture.sqlite3"
    connection = capture._connect(path)
    try:
        capture.store_rows(
            connection,
            [{"seq": seq, "text": str(seq)} for seq in range(1, 13)],
        )
        monkeypatch.setattr(capture, "MAX_ROWS", 3)
        monkeypatch.setattr(capture, "MAX_PROTECTED_ROWS", 6)
        monkeypatch.setattr(capture, "MAX_PRUNE_ROWS_PER_PASS", 2)

        assert capture._protected_backlog_full(connection, observer_cursor=2) is True
        assert _seqs(path) == list(range(3, 13))
        assert capture._protected_backlog_full(connection, observer_cursor=8) is True
        assert _seqs(path) == list(range(5, 13))
        assert capture._protected_backlog_full(connection, observer_cursor=8) is True
        assert _seqs(path) == list(range(7, 13))
        assert capture._protected_backlog_full(connection, observer_cursor=8) is False
        assert _seqs(path) == list(range(9, 13))
    finally:
        connection.close()


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



def test_normalize_export_result_supports_legacy_and_partial_shapes():
    rows = [{"seq": 11, "text": "a"}]
    assert capture._normalize_export_result((rows, None)) == (rows, None, True)
    assert capture._normalize_export_result((rows, None, False)) == (rows, None, False)


def test_incomplete_export_does_not_prove_hole_until_retained_start_is_past_gap():
    cursor = 10
    assert capture._export_proves_permanent_capture_hole(
        cursor,
        [{"seq": 9, "text": "old"}],
        False,
    ) is False
    assert capture._export_proves_permanent_capture_hole(
        cursor,
        [],
        False,
    ) is False

    # The first ordered retained row being past cursor+1 proves the missing prefix
    # has already fallen out of the server snapshot even if we stop streaming later.
    assert capture._export_proves_permanent_capture_hole(
        cursor,
        [{"seq": 15, "text": "retained-start"}],
        False,
    ) is True


def test_complete_export_can_prove_permanent_hole():
    assert capture._export_proves_permanent_capture_hole(
        10,
        [{"seq": 1, "text": "old"}],
        True,
    ) is True
    assert capture._export_proves_permanent_capture_hole(10, [], True) is True


def test_capture_runtime_error_label_preserves_semantic_reason():
    assert capture._capture_error_label(RuntimeError("capture_total_timeout")) == "capture_total_timeout"
    assert capture._capture_error_label(RuntimeError("capture_invalid_export")) == "capture_invalid_export"


def test_capture_process_requires_export_proof_before_permanent_skip():
    import inspect

    source = inspect.getsource(capture.capture_process)
    assert source.index("_export_proves_permanent_capture_hole") < source.index(
        "_skip_permanent_capture_hole"
    )
    assert "capture_export_partial_before_gap" in source


def test_observer_cursor_prefers_tiny_heartbeat_without_bootstrap(monkeypatch, tmp_path):
    heartbeat = tmp_path / "observer-heartbeat.json"
    heartbeat.write_text(
        '{"schema_version":1,"lobby_cursor":123}',
        encoding="utf-8",
    )

    class BombBootstrapPath:
        def read_text(self, *args, **kwargs):
            raise AssertionError("bootstrap must not be read when heartbeat has a cursor")

    monkeypatch.setattr(capture, "heartbeat_path", lambda: heartbeat)
    monkeypatch.setattr(capture, "observer_cursor_bootstrap_path", lambda: BombBootstrapPath())
    assert capture._observer_cursor() == 123


def test_observer_cursor_accepts_zero_heartbeat_cursor_without_fallback(monkeypatch, tmp_path):
    heartbeat = tmp_path / "observer-heartbeat.json"
    heartbeat.write_text(
        '{"schema_version":1,"lobby_cursor":0}',
        encoding="utf-8",
    )

    class BombBootstrapPath:
        def read_text(self, *args, **kwargs):
            raise AssertionError("zero is a valid fail-closed heartbeat cursor")

    monkeypatch.setattr(capture, "heartbeat_path", lambda: heartbeat)
    monkeypatch.setattr(capture, "observer_cursor_bootstrap_path", lambda: BombBootstrapPath())
    assert capture._observer_cursor() == 0


def test_observer_cursor_rolling_fallback_reads_tiny_bootstrap(monkeypatch, tmp_path):
    heartbeat = tmp_path / "old-heartbeat.json"
    heartbeat.write_text(
        '{"schema_version":1,"updated_at":"x","status":"ok"}',
        encoding="utf-8",
    )
    bootstrap = tmp_path / "observer-lobby-prune-cursor-bootstrap.json"
    bootstrap.write_text(
        '{"schema_version":1,"lobby_cursor":456}',
        encoding="utf-8",
    )
    monkeypatch.setattr(capture, "heartbeat_path", lambda: heartbeat)
    monkeypatch.setattr(capture, "observer_cursor_bootstrap_path", lambda: bootstrap)

    assert capture._observer_cursor() == 456

    import inspect
    source = inspect.getsource(capture._observer_cursor_from_bootstrap)
    assert "read_text" in source
    assert "observer.state_path" not in source


def test_observer_cursor_bootstrap_fails_closed_when_missing_or_invalid(monkeypatch, tmp_path):
    heartbeat = tmp_path / "old-heartbeat.json"
    heartbeat.write_text('{"schema_version":1}', encoding="utf-8")
    bootstrap = tmp_path / "missing-bootstrap.json"
    monkeypatch.setattr(capture, "heartbeat_path", lambda: heartbeat)
    monkeypatch.setattr(capture, "observer_cursor_bootstrap_path", lambda: bootstrap)

    assert capture._observer_cursor() == 0

    bootstrap.write_text('{"schema_version":2,"lobby_cursor":999}', encoding="utf-8")
    assert capture._observer_cursor() == 0

    bootstrap.write_text('{"schema_version":1,"lobby_cursor":-1}', encoding="utf-8")
    assert capture._observer_cursor() == 0


def test_capture_source_has_no_rich_observer_state_cursor_fallback():
    import inspect

    source = inspect.getsource(capture)
    assert "_observer_cursor_from_state_prefix" not in source
    assert "OBSERVER_CURSOR_PREFIX_BYTES" not in source
