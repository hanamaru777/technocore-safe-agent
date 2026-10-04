from __future__ import annotations

import inspect
from datetime import timedelta

from flop_agent import close1_autonomous_resident as resident
from flop_agent import close1_autonomous_rehearsal as rehearsal
from flop_agent import close1_autonomous_stage as stage
from flop_agent import close_call, core


NOW = close_call.LOCK - timedelta(hours=1)


def test_locked_cycle_exits_without_scanning(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    (tmp_path / "close1").mkdir()
    called = []
    monkeypatch.setattr(stage, "run_once", lambda: called.append(True))
    result = resident.run_cycle(now=close_call.LOCK)
    assert result["status"] == "LOCKED"
    assert called == []


def test_fresh_stage_is_rehearsed_in_same_cycle(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    (tmp_path / "close1").mkdir()
    monkeypatch.setattr(
        stage,
        "run_once",
        lambda: {
            "status": "staged",
            "trade_id": "fresh-1",
            "offer_seq": 12,
            "qty": "20",
            "taker_side": "buy",
        },
    )
    monkeypatch.setattr(
        rehearsal,
        "run_once",
        lambda now=None: {"status": "WOULD_EXECUTE", "target_met": True},
    )
    result = resident.run_cycle(now=NOW)
    assert result["status"] == "REHEARSAL_COMPLETE"
    assert result["stage_status"] == "fresh"
    assert result["trade_id"] == "fresh-1"
    assert result["target_met"] is True
    assert result["cycle_to_handoff_complete_ms"] == 0


def test_preexisting_stage_is_drained_before_new_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    close1 = tmp_path / "close1"
    close1.mkdir()
    stage.stage_path().write_text("{}", encoding="utf-8")
    scanned = []
    monkeypatch.setattr(stage, "run_once", lambda: scanned.append(True))
    monkeypatch.setattr(
        rehearsal,
        "run_once",
        lambda now=None: {"status": "BLOCKED_PREFLIGHT"},
    )
    result = resident.run_cycle(now=NOW)
    assert result["status"] == "REHEARSAL_COMPLETE"
    assert result["stage_status"] == "preexisting"
    assert scanned == []


def test_resident_stops_after_bounded_consecutive_errors(monkeypatch):
    monkeypatch.setattr(
        resident,
        "run_cycle",
        lambda: (_ for _ in ()).throw(RuntimeError("close1_test_failure")),
    )
    writes = []
    monkeypatch.setattr(resident, "_write_status", writes.append)
    sleeps = []
    rc = resident.run_forever(sleep=lambda seconds: sleeps.append(seconds))
    assert rc == 1
    assert len(writes) == resident.MAX_CONSECUTIVE_ERRORS
    assert writes[-1]["consecutive_errors"] == resident.MAX_CONSECUTIVE_ERRORS
    assert sleeps == [resident.SCAN_INTERVAL_SECONDS] * (resident.MAX_CONSECUTIVE_ERRORS - 1)


def test_resident_has_no_signer_or_external_write_surface():
    source = inspect.getsource(resident)
    forbidden = (
        "vault_seed(",
        "oracle_signer",
        "close1_approved_trade",
        "approval_path(",
        "httpx.post(",
        "post_signed(",
        "subprocess",
        "systemctl",
    )
    assert all(token not in source for token in forbidden)
