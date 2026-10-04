from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import close1_autonomous_rehearsal as rehearsal
from flop_agent import close1_autonomous_stage as stage_mod
from flop_agent import core


NOW = datetime(2026, 10, 3, 0, 0, tzinfo=UTC)


def stage(*, detected=None, staged=None):
    detected = detected or (NOW - timedelta(seconds=2))
    staged = staged or (NOW - timedelta(seconds=1))
    return {
        "schema_version": 1,
        "owner_did": stage_mod.OWNER_DID,
        "offer_room": "close1-offers",
        "offer_seq": 123,
        "trade_id": "abc-123",
        "maker": "did:key:z6MktVwQqJbSVfLfDUHRVkJShspL49A2d6EbhzKvXV9zPLF5",
        "maker_side": "sell",
        "taker_side": "buy",
        "qty": "20",
        "px": "233.92",
        "until": 2500,
        "maker_sig": "public-maker-signature",
        "detected_sweep": 2478,
        "reference": "234.86",
        "reference_age_s": 10,
        "current_cash": "10000",
        "current_position": "0",
        "required_cash": "4725.184",
        "price_edge_bps": "40.02",
        "detected_at": detected.isoformat(),
        "raw_captured_at": (detected + timedelta(milliseconds=250)).isoformat(),
        "staged_at": staged.isoformat(),
    }


@pytest.fixture
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    (tmp_path / "close1").mkdir()
    return tmp_path


def test_stage_older_than_fifteen_seconds_is_rejected(isolated_state):
    value = stage(staged=NOW - timedelta(seconds=16))
    stage_mod.stage_path().write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(RuntimeError, match="stage_stale"):
        rehearsal._load_stage(now=NOW)


def test_duplicate_json_field_is_rejected(isolated_state):
    path = stage_mod.stage_path()
    path.write_text(
        '{"schema_version":1,"schema_version":1}', encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="duplicate_field"):
        rehearsal._load_stage(now=NOW)


def _mock_nonbinding_handoff(monkeypatch, value, digest):
    skipped = []
    consumed = []
    monkeypatch.setattr(rehearsal, "_load_stage", lambda now=None: (value, digest))
    monkeypatch.setattr(
        rehearsal,
        "_fresh_revalidate",
        lambda value, now=None: {
            "wall_sweep": 2478,
            "cash": "10000",
            "position": "0",
            "required_cash": "4725.184",
            "price_edge_bps": "40.02",
            "offer_fresh": True,
            "price_fresh": True,
            "account_ready": True,
        },
    )
    monkeypatch.setattr(rehearsal, "_record_skip", skipped.append)
    monkeypatch.setattr(rehearsal, "_consume_stage", consumed.append)
    return skipped, consumed


def test_run_once_reports_latency_without_binding_action(isolated_state, monkeypatch):
    value = stage()
    skipped, consumed = _mock_nonbinding_handoff(monkeypatch, value, "a" * 64)
    result = rehearsal.run_once(now=NOW)
    assert result["status"] == "WOULD_EXECUTE"
    assert result["capture_to_rehearsal_ms"] == 2000
    assert result["capture_to_stage_ms"] == 1000
    assert result["target_met"] is True
    assert result["signer_access"] is False
    assert result["approval_written"] is False
    assert result["post_attempted"] is False
    assert skipped == ["abc-123"]
    assert consumed == ["a" * 64]


def test_latency_over_target_is_visible_not_silently_passed(isolated_state, monkeypatch):
    value = stage(detected=NOW - timedelta(seconds=6), staged=NOW - timedelta(seconds=1))
    skipped, consumed = _mock_nonbinding_handoff(monkeypatch, value, "b" * 64)
    result = rehearsal.run_once(now=NOW)
    assert result["target_met"] is False
    assert result["capture_to_rehearsal_ms"] == 6000
    assert skipped == ["abc-123"]
    assert consumed == ["b" * 64]


def test_stage_digest_change_is_rejected_before_unlink(isolated_state):
    path = stage_mod.stage_path()
    value = stage()
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(RuntimeError, match="stage_changed"):
        rehearsal._consume_stage("0" * 64)
    assert path.exists()


def test_rehearsal_module_has_no_signer_or_external_write_surface():
    source = inspect.getsource(rehearsal)
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
