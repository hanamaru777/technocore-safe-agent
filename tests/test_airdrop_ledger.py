from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from flop_agent import airdrop_ledger


def _fact(key: str, value: object, *, source: str = "yellowpaper", status: str = "normative") -> dict:
    return {
        "key": key,
        "value": value,
        "unit": "FLOP" if isinstance(value, int) else None,
        "source": source,
        "tier": 1,
        "authority": "normative",
        "status": status,
        "evidence_sha256": "e" * 64,
        "evidence_excerpt": f"{key}={value}",
    }


def _resolved(fact: dict) -> dict:
    return {
        "value": fact["value"],
        "unit": fact.get("unit"),
        "source": fact["source"],
        "tier": fact["tier"],
        "authority": fact["authority"],
        "status": fact["status"],
        "conflict": False,
        "variants": [fact],
    }


def _source(
    *,
    value: int = 1_200_000_000,
    status: str = "ok",
    content_hash: str = "a" * 64,
    version: str = "0.5.0 (draft)",
    error_type: str = "ReadTimeout",
) -> dict:
    if status != "ok":
        return {
            "name": "yellowpaper",
            "url": "https://flop.finance/intro/yellowpaper/",
            "tier": 1,
            "authority": "normative",
            "critical": True,
            "status": "error",
            "error_type": error_type,
            "error": "temporary",
        }
    fact = _fact("genesis_agent_airdrop", value)
    return {
        "name": "yellowpaper",
        "url": "https://flop.finance/intro/yellowpaper/",
        "final_url": "https://flop.finance/intro/yellowpaper/",
        "tier": 1,
        "authority": "normative",
        "critical": True,
        "status": "ok",
        "attempts": 1,
        "latency_ms": 8,
        "content_sha256": content_hash,
        "content_bytes": 1234,
        "meta": {"version": version, "updated": "2026-09-18"},
        "facts": [fact],
        "deadlines": [],
        "interest_links": [],
    }


def _snapshot(
    snapshot_id: str,
    at: datetime,
    *,
    value: int = 1_200_000_000,
    source_status: str = "ok",
    content_hash: str = "a" * 64,
    version: str = "0.5.0 (draft)",
) -> dict:
    source = _source(
        value=value,
        status=source_status,
        content_hash=content_hash,
        version=version,
    )
    facts = {}
    if source_status == "ok":
        facts["genesis_agent_airdrop"] = _resolved(source["facts"][0])
    failed = [] if source_status == "ok" else ["yellowpaper"]
    return {
        "schema_version": 2,
        "read_only": True,
        "scanned_at": at.astimezone(UTC).isoformat(),
        "health": "ok" if source_status == "ok" else "degraded",
        "snapshot_id": snapshot_id,
        "source_precedence": ["Tier 1 live FLOP-hosted Yellow Paper"],
        "sources": [source],
        "resolved_facts": facts,
        "deadlines": [],
        "summary": {
            "available_sources": 1 if source_status == "ok" else 0,
            "failed_sources": failed,
            "conflicts": [],
        },
        "warnings": [],
    }


def _event_files(root: Path) -> list[Path]:
    events = root / "airdrop-radar" / "events"
    return sorted(events.glob("*.json")) if events.exists() else []


def test_baseline_creates_isolated_snapshot_without_fake_events(tmp_path: Path) -> None:
    now = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
    result = airdrop_ledger.record_snapshot(_snapshot("s1", now), tmp_path)
    assert result["ok"] is True
    assert result["baseline"] is True
    assert result["events_recorded"] == 0
    assert (tmp_path / "airdrop-radar" / "state.json").is_file()
    assert (tmp_path / "airdrop-radar" / "current-snapshot.json").is_file()
    assert not (tmp_path / "observer").exists()
    status = airdrop_ledger.ledger_status(tmp_path)
    assert status["event_count"] == 0
    assert status["last_good_source_count"] == 1


def test_material_change_is_hash_chained_and_verifiable(tmp_path: Path) -> None:
    t0 = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
    airdrop_ledger.record_snapshot(_snapshot("s1", t0), tmp_path)
    result = airdrop_ledger.record_snapshot(
        _snapshot(
            "s2",
            t0 + timedelta(minutes=15),
            value=1_350_000_000,
            content_hash="b" * 64,
        ),
        tmp_path,
    )
    assert result["events_recorded"] >= 1
    files = _event_files(tmp_path)
    assert files
    records = airdrop_ledger._scan_event_chain(tmp_path)
    assert records[0]["previous_hash"] == ""
    for index in range(1, len(records)):
        assert records[index]["previous_hash"] == records[index - 1]["hash"]
    assert airdrop_ledger.verify_ledger(tmp_path)["ok"] is True


def test_tampered_event_is_detected_fail_closed(tmp_path: Path) -> None:
    t0 = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
    airdrop_ledger.record_snapshot(_snapshot("s1", t0), tmp_path)
    airdrop_ledger.record_snapshot(
        _snapshot("s2", t0 + timedelta(minutes=15), value=1_350_000_000, content_hash="b" * 64),
        tmp_path,
    )
    path = _event_files(tmp_path)[0]
    record = json.loads(path.read_text("utf-8"))
    record["severity"] = "INFO"
    path.write_text(json.dumps(record), "utf-8")
    with pytest.raises(RuntimeError, match="event_hash_mismatch"):
        airdrop_ledger.verify_ledger(tmp_path)


def test_state_hash_tampering_is_detected(tmp_path: Path) -> None:
    now = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
    airdrop_ledger.record_snapshot(_snapshot("s1", now), tmp_path)
    path = tmp_path / "airdrop-radar" / "state.json"
    state = json.loads(path.read_text("utf-8"))
    state["last_health"] = "tampered"
    path.write_text(json.dumps(state), "utf-8")
    with pytest.raises(RuntimeError, match="state_hash_mismatch"):
        airdrop_ledger.verify_ledger(tmp_path)


def test_crash_stale_state_is_recovered_from_event_chain_and_snapshot(tmp_path: Path) -> None:
    t0 = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
    airdrop_ledger.record_snapshot(_snapshot("s1", t0), tmp_path)
    state_path = tmp_path / "airdrop-radar" / "state.json"
    baseline_state = state_path.read_bytes()

    airdrop_ledger.record_snapshot(
        _snapshot("s2", t0 + timedelta(minutes=15), value=1_350_000_000, content_hash="b" * 64),
        tmp_path,
    )
    assert _event_files(tmp_path)
    state_path.write_bytes(baseline_state)

    result = airdrop_ledger.verify_ledger(tmp_path, recover=True)
    assert result["recovered"] is True
    assert result["event_count"] >= 1
    state, _ = airdrop_ledger._read_state(tmp_path)
    assert state["event_count"] == result["event_count"]
    assert state["last_snapshot_id"] == "s2"


def test_orphan_atomic_temp_is_removed_on_startup(tmp_path: Path) -> None:
    now = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
    airdrop_ledger.record_snapshot(_snapshot("s1", now), tmp_path)
    temp = tmp_path / "airdrop-radar" / ".state.json.crash.tmp"
    temp.write_text("partial", "utf-8")
    result = airdrop_ledger.verify_ledger(tmp_path)
    assert result["orphan_temps_removed"] == 1
    assert not temp.exists()


def test_degraded_scan_does_not_erase_last_good_source(tmp_path: Path) -> None:
    t0 = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
    airdrop_ledger.record_snapshot(_snapshot("s1", t0), tmp_path)
    before, _ = airdrop_ledger._read_state(tmp_path)
    old_hash = before["last_good_sources"]["yellowpaper"]["content_sha256"]

    airdrop_ledger.record_snapshot(
        _snapshot("s2", t0 + timedelta(minutes=15), source_status="error"),
        tmp_path,
    )
    after, _ = airdrop_ledger._read_state(tmp_path)
    assert after["last_good_sources"]["yellowpaper"]["content_sha256"] == old_hash
    assert after["last_health"] == "degraded"
    assert after["last_failed_sources"] == ["yellowpaper"]


def test_recovery_compares_against_last_success_not_failed_snapshot(tmp_path: Path) -> None:
    t0 = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
    airdrop_ledger.record_snapshot(_snapshot("s1", t0, value=1_200_000_000), tmp_path)
    airdrop_ledger.record_snapshot(
        _snapshot("s2", t0 + timedelta(minutes=15), source_status="error"),
        tmp_path,
    )
    result = airdrop_ledger.record_snapshot(
        _snapshot(
            "s3",
            t0 + timedelta(minutes=30),
            value=1_350_000_000,
            content_hash="c" * 64,
        ),
        tmp_path,
    )
    assert result["recovery_events"]
    records = airdrop_ledger._scan_event_chain(tmp_path)
    recovery = next(row for row in records if row["type"] == "RECOVERED_SOURCE_FACT_CHANGED")
    assert recovery["key"] == "genesis_agent_airdrop"
    assert recovery["severity"] == "HIGH"
    assert recovery["source"] == "yellowpaper"
    assert recovery["before"][0]["value"] == 1_200_000_000
    assert recovery["after"][0]["value"] == 1_350_000_000


def test_duplicate_event_id_updates_last_seen_without_appending(tmp_path: Path) -> None:
    t0 = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
    airdrop_ledger.record_snapshot(_snapshot("s1", t0), tmp_path)
    airdrop_ledger.record_snapshot(
        _snapshot("s2", t0 + timedelta(minutes=15), value=1_350_000_000, content_hash="b" * 64),
        tmp_path,
    )
    records = airdrop_ledger._scan_event_chain(tmp_path)
    original_count = len(records)
    record = records[0]
    event = {
        key: record[key]
        for key in (
            "event_id", "type", "key", "severity", "before", "after",
            "source", "deadline", "deadline_gate", "evidence_sources",
        )
        if key in record
    }
    state, _ = airdrop_ledger._read_state(tmp_path)
    later = (t0 + timedelta(hours=2)).isoformat()
    written, duplicate = airdrop_ledger._write_event_record(
        event,
        observed_at=later,
        state=state,
        root=tmp_path,
    )
    assert duplicate is True
    assert written is None
    airdrop_ledger._write_state(state, tmp_path)
    assert len(airdrop_ledger._scan_event_chain(tmp_path)) == original_count
    reloaded, _ = airdrop_ledger._read_state(tmp_path)
    assert reloaded["seen_events"][record["event_id"]]["last_seen"] == later


def test_forbidden_full_body_material_is_refused(tmp_path: Path) -> None:
    now = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
    snapshot = _snapshot("s1", now)
    snapshot["sources"][0]["body"] = "<html>full page</html>"
    with pytest.raises(RuntimeError, match="forbidden_field"):
        airdrop_ledger.record_snapshot(snapshot, tmp_path)


def test_schema_mismatch_stops_instead_of_migrating_silently(tmp_path: Path) -> None:
    now = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
    airdrop_ledger.record_snapshot(_snapshot("s1", now), tmp_path)
    path = tmp_path / "airdrop-radar" / "state.json"
    state = json.loads(path.read_text("utf-8"))
    state["schema_version"] = 999
    state["state_hash"] = airdrop_ledger._state_hash(state)
    path.write_text(json.dumps(state), "utf-8")
    with pytest.raises(RuntimeError, match="state_schema_mismatch"):
        airdrop_ledger.verify_ledger(tmp_path)


def test_export_contains_chain_facts_sources_and_last_seen(tmp_path: Path) -> None:
    t0 = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
    airdrop_ledger.record_snapshot(_snapshot("s1", t0), tmp_path)
    airdrop_ledger.record_snapshot(
        _snapshot("s2", t0 + timedelta(minutes=15), value=1_350_000_000, content_hash="b" * 64),
        tmp_path,
    )
    output = tmp_path / "evidence.json"
    result = airdrop_ledger.export_bundle(output, tmp_path)
    assert result["ok"] is True
    bundle = json.loads(output.read_text("utf-8"))
    assert bundle["ledger"]["event_count"] >= 1
    assert bundle["ledger"]["last_event_hash"]
    assert bundle["current"]["resolved_facts"]["genesis_agent_airdrop"]["value"] == 1_350_000_000
    assert bundle["last_good_sources"]["yellowpaper"]["content_sha256"] == "b" * 64
    assert bundle["events"][0]["first_seen"]
    assert bundle["events"][0]["last_seen"]


def test_ledger_module_has_no_network_or_process_execution_paths() -> None:
    source = inspect.getsource(airdrop_ledger)
    assert "httpx" not in source
    assert "requests." not in source
    assert "subprocess" not in source
    assert "socket" not in source
    assert "technocore.chat" not in source


def test_ledger_default_path_is_separate_from_observer(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(airdrop_ledger.core, "STATE", tmp_path)
    assert airdrop_ledger.ledger_dir() == tmp_path / "airdrop-radar"
    assert airdrop_ledger.ledger_dir() != tmp_path / "observer"
