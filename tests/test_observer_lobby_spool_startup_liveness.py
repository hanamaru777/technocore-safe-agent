from __future__ import annotations

import asyncio

from flop_agent import (
    observer,
    observer_lobby_capture as capture,
    observer_lobby_spool_recovery as spool,
    observer_resilience as resilience,
)


def test_complete_startup_range_uses_only_bounded_chunk_reads(tmp_path, monkeypatch):
    """Large startup recovery must not rescan the whole remaining suffix per slice."""
    path = tmp_path / "capture.sqlite3"
    monkeypatch.setattr(capture, "capture_path", lambda: path)
    connection = capture._connect(path)
    try:
        capture.store_rows(
            connection,
            [
                {"seq": seq, "text": f"startup row {seq}", "from": f"did:key:test{seq}"}
                for seq in range(2, 1002)
            ],
        )
    finally:
        connection.close()

    state = resilience.default_state()
    state["cursors"]["lobby"] = 1

    original_read_range = capture.read_range
    spans = []

    def bounded_read_range(start, end, path_arg=None):
        spans.append(end - start + 1)
        return original_read_range(start, end, path_arg)

    def forbidden_contiguous_scan(*args, **kwargs):
        raise AssertionError("complete startup drain must not rescan remaining suffix")

    monkeypatch.setattr(capture, "read_range", bounded_read_range)
    monkeypatch.setattr(capture, "contiguous_end", forbidden_contiguous_scan)

    changed, recovered = asyncio.run(
        spool._drain_complete_spool_range(
            state,
            observer.DEFAULT_CONFIG,
            2,
            1001,
            None,
            None,
        )
    )

    assert changed is True
    assert recovered == 1000
    assert state["cursors"]["lobby"] == 1001
    assert len(spans) == 10
    assert max(spans) <= spool.SPOOL_CHUNK_MESSAGES
    assert state["metrics"].get("unrecoverable_core_gap_events", 0) == 0
