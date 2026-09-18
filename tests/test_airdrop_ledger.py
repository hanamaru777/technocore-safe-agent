from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from flop_agent import airdrop_ledger, airdrop_radar, core


NOW1 = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
NOW2 = datetime(2026, 9, 18, 12, 15, tzinfo=UTC)
NOW3 = datetime(2026, 9, 18, 12, 30, tzinfo=UTC)


def fact(
    key: str,
    value: object,
    *,
    source: str = "yellowpaper",
    tier: int = 1,
    status: str = "normative",
) -> dict:
    return {
        "key": key,
        "value": value,
        "unit": "FLOP" if isinstance(value, int) else None,
        "source": source,
        "tier": tier,
        "authority": "normative" if tier == 1 else "provisional",
        "status": status,
        "evidence_sha256": ("a" if source == "yellowpaper" else "b") * 64,
        "evidence_excerpt": f"evidence for {key}={value}",
    }


def source(
    name: str,
    *,
    facts: list[dict] | None = None,
    status: str = "ok",
    content_sha: str | None = None,
    critical: bool | None = None,
    version: str = "0.5.0 (draft)",
) -> dict:
    tier = 1 if name == "yellowpaper" else 2
    authority = "normative" if tier == 1 else "provisional"
    row = {
        "name": name,
        "url": f"https://flop.finance/{name}/",
        "tier": tier,
        "authority": authority,
        "critical": (name in {"yellowpaper", "teaser"}) if critical is None else critical,
        "status": status,
    }
    if status == "ok":
        row.update(
            {
                "final_url": f"https://flop.finance/{name}/",
                "attempts": 1,
                "latency_ms": 5,
                "content_sha256": content_sha or (name[0] * 64),
                "content_bytes": 100,
                "meta": {"version": version, "updated": "2026-09-18"},
                "facts": facts or [],
                "deadlines": [],
                "interest_links": [],
            }
        )
    else:
        row.update({"error_type": "ReadTimeout", "error": "not persisted"})
    return row


def snapshot(
    snapshot_id: str,
    rows: list[dict],
    *,
    scanned_at: str,
) -> dict:
    facts = [
        item
        for row in rows
        if row.get("status") == "ok"
        for item in row.get("facts", [])
    ]
    resolved = airdrop_radar._resolve_facts(facts)
    failed = [row["name"] for row in rows if row.get("status") != "ok"]
    return {
        "schema_version": airdrop_radar.SCHEMA_VERSION,
        "read_only": True,
        "scanned_at": scanned_at,
        "health": "degraded" if failed else "ok",
        "snapshot_id": snapshot_id,
        "source_precedence": ["Tier 1", "Tier 2"],
        "sources": rows,
        "resolved_facts": resolved,
        "deadlines": [],
        "summary": {
            "available_sources": len(rows) - len(failed),
            "failed_sources": failed,
            "conflicts": sorted(
                key for key, row in resolved.items() if row.get("conflict")
            ),
        },
        "warnings": ["not persisted"],
    }


@pytest.fixture
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(core, "STATE", tmp_path)
    return tmp_path


def test_baseline_persists_only_whitelisted_evidence(isolated_state: Path) -> None:
    yp = source(
        "yellowpaper",
        facts=[fact("genesis_agent_airdrop", 1_200_000_000)],
    )
    yp["raw_body"] = "SHOULD_NOT_PERSIST_RAW_HTML"
    yp["headers"] = {"cookie": "SHOULD_NOT_PERSIST_COOKIE"}
    current = snapshot("snap-1", [yp], scanned_at=NOW1.isoformat())
    current["future_raw_field"] = "SHOULD_NOT_PERSIST_FUTURE_FIELD"

    result = airdrop_ledger.record_scan(current, now=NOW1)

    assert result["baseline"] is True
    assert result["new_events"] == []
    assert result["ledger"]["count"] == 0
    base = isolated_state / "airdrop-radar"
    persisted = (base / "current-snapshot.json").read_text("utf-8")
    assert "SHOULD_NOT_PERSIST" not in persisted
    wrapper = json.loads(persisted)
    assert wrapper["schema_version"] == airdrop_ledger.SCHEMA_VERSION
    assert wrapper["snapshot"]["schema_version"] == airdrop_radar.SCHEMA_VERSION
    assert wrapper["snapshot"]["resolved_facts"]["genesis_agent_airdrop"]["value"] == 1_200_000_000

    last = json.loads((base / "last-success.json").read_text("utf-8"))
    assert last["sources"]["yellowpaper"]["status"] == "ok"
    assert last["sources"]["yellowpaper"]["facts"][0]["evidence_excerpt"]


def test_material_change_is_hash_chained_and_tamper_is_detected(isolated_state: Path) -> None:
    first = snapshot(
        "snap-a",
        [source("yellowpaper", facts=[fact("genesis_agent_airdrop", 1)])],
        scanned_at=NOW1.isoformat(),
    )
    second = snapshot(
        "snap-b",
        [source("yellowpaper", facts=[fact("genesis_agent_airdrop", 2)], content_sha="2" * 64)],
        scanned_at=NOW2.isoformat(),
    )
    airdrop_ledger.record_scan(first, now=NOW1)
    result = airdrop_ledger.record_scan(second, now=NOW2)

    assert len(result["new_events"]) == 1
    assert result["new_events"][0]["key"] == "genesis_agent_airdrop"
    verified = airdrop_ledger.verify_ledger()
    assert verified["valid"] is True
    assert verified["count"] == 1
    record = verified["records"][0]
    assert record["previous_hash"] == ""
    assert record["hash"] == verified["tip_hash"]
    assert record["source_evidence"]

    path = isolated_state / "airdrop-radar" / "events.jsonl"
    tampered = json.loads(path.read_text("utf-8"))
    tampered["event"]["severity"] = "INFO"
    path.write_text(json.dumps(tampered) + "\n", "utf-8")
    with pytest.raises(airdrop_ledger.LedgerIntegrityError, match="hash_mismatch"):
        airdrop_ledger.verify_ledger()


def test_deterministic_event_id_dedupes_repeated_same_transition(isolated_state: Path) -> None:
    one = snapshot(
        "one",
        [source("yellowpaper", facts=[fact("genesis_agent_airdrop", 1)])],
        scanned_at=NOW1.isoformat(),
    )
    two = snapshot(
        "two",
        [source("yellowpaper", facts=[fact("genesis_agent_airdrop", 2)], content_sha="2" * 64)],
        scanned_at=NOW2.isoformat(),
    )
    back = snapshot(
        "back",
        [source("yellowpaper", facts=[fact("genesis_agent_airdrop", 1)], content_sha="3" * 64)],
        scanned_at=NOW3.isoformat(),
    )
    repeat = snapshot(
        "repeat",
        [source("yellowpaper", facts=[fact("genesis_agent_airdrop", 2)], content_sha="4" * 64)],
        scanned_at="2026-09-18T12:45:00+00:00",
    )

    airdrop_ledger.record_scan(one, now=NOW1)
    first_change = airdrop_ledger.record_scan(two, now=NOW2)
    forward_id = first_change["new_events"][0]["event_id"]
    airdrop_ledger.record_scan(back, now=NOW3)
    repeated = airdrop_ledger.record_scan(
        repeat,
        now=datetime(2026, 9, 18, 12, 45, tzinfo=UTC),
    )

    assert forward_id in repeated["repeated_event_ids"]
    verified = airdrop_ledger.verify_ledger()
    assert verified["count"] == 2
    index = json.loads(
        (isolated_state / "airdrop-radar" / "event-index.json").read_text("utf-8")
    )
    assert index["events"][forward_id]["seen_count"] == 2


def test_source_recovery_compares_against_its_own_last_success(isolated_state: Path) -> None:
    first = snapshot(
        "good-1",
        [
            source("yellowpaper", facts=[fact("agent_identity_min_stake", 10)]),
            source(
                "teaser",
                facts=[
                    fact(
                        "agent_identity_min_stake",
                        10,
                        source="teaser",
                        tier=2,
                        status="provisional",
                    )
                ],
            ),
        ],
        scanned_at=NOW1.isoformat(),
    )
    down = snapshot(
        "down",
        [
            source("yellowpaper", status="error"),
            source(
                "teaser",
                facts=[
                    fact(
                        "agent_identity_min_stake",
                        10,
                        source="teaser",
                        tier=2,
                        status="provisional",
                    )
                ],
            ),
        ],
        scanned_at=NOW2.isoformat(),
    )
    recovered = snapshot(
        "good-2",
        [
            source(
                "yellowpaper",
                facts=[fact("agent_identity_min_stake", 25)],
                content_sha="9" * 64,
            ),
            source(
                "teaser",
                facts=[
                    fact(
                        "agent_identity_min_stake",
                        10,
                        source="teaser",
                        tier=2,
                        status="provisional",
                    )
                ],
            ),
        ],
        scanned_at=NOW3.isoformat(),
    )

    airdrop_ledger.record_scan(first, now=NOW1)
    airdrop_ledger.record_scan(down, now=NOW2)

    last_during_outage = json.loads(
        (isolated_state / "airdrop-radar" / "last-success.json").read_text("utf-8")
    )
    cached = last_during_outage["sources"]["yellowpaper"]
    assert cached["status"] == "ok"
    assert cached["facts"][0]["value"] == 10

    result = airdrop_ledger.record_scan(recovered, now=NOW3)
    semantic = next(
        row
        for row in result["new_events"]
        if row["type"] == "RECOVERED_SOURCE_FACT_CHANGED"
    )
    assert semantic["key"] == "agent_identity_min_stake"
    assert semantic["before"]["value"] == 10
    assert semantic["after"]["value"] == 25
    assert semantic["severity"] == "HIGH"

    last_after = json.loads(
        (isolated_state / "airdrop-radar" / "last-success.json").read_text("utf-8")
    )
    assert last_after["sources"]["yellowpaper"]["facts"][0]["value"] == 25


def test_atomic_write_failure_keeps_previous_file_and_cleans_temp(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = isolated_state / "airdrop-radar" / "atomic.json"
    airdrop_ledger._atomic_json_write(path, {"schema_version": 1, "value": "before"})

    def fail_replace(_src: str, _dst: Path) -> None:
        raise OSError("simulated interruption")

    monkeypatch.setattr(airdrop_ledger.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated interruption"):
        airdrop_ledger._atomic_json_write(
            path,
            {"schema_version": 1, "value": "after"},
        )

    assert json.loads(path.read_text("utf-8"))["value"] == "before"
    assert not list(path.parent.glob(".atomic.json.*.tmp"))


def test_stale_index_is_rebuilt_from_valid_ledger_after_interruption(
    isolated_state: Path,
) -> None:
    first = snapshot(
        "s1",
        [source("yellowpaper", facts=[fact("genesis_agent_airdrop", 1)])],
        scanned_at=NOW1.isoformat(),
    )
    second = snapshot(
        "s2",
        [source("yellowpaper", facts=[fact("genesis_agent_airdrop", 2)], content_sha="2" * 64)],
        scanned_at=NOW2.isoformat(),
    )
    airdrop_ledger.record_scan(first, now=NOW1)
    changed = airdrop_ledger.record_scan(second, now=NOW2)
    event_id = changed["new_events"][0]["event_id"]

    index_path = isolated_state / "airdrop-radar" / "event-index.json"
    stale = json.loads(index_path.read_text("utf-8"))
    stale["ledger_count"] = 0
    stale["ledger_tip_hash"] = ""
    stale["events"] = {}
    index_path.write_text(json.dumps(stale), "utf-8")

    status = airdrop_ledger.status()
    assert status["integrity_valid"] is True
    assert status["index_recovered_after_interruption"] is True
    repaired = json.loads(index_path.read_text("utf-8"))
    assert event_id in repaired["events"]


def test_schema_mismatch_stops_instead_of_silently_migrating(isolated_state: Path) -> None:
    base = isolated_state / "airdrop-radar"
    base.mkdir()
    (base / "state.json").write_text(
        json.dumps({"schema_version": 999}),
        "utf-8",
    )
    with pytest.raises(airdrop_ledger.LedgerIntegrityError, match="schema_mismatch_state"):
        airdrop_ledger.status()


def test_acknowledgement_fails_closed_when_ledger_is_corrupt(isolated_state: Path) -> None:
    first = snapshot(
        "s1",
        [source("yellowpaper", facts=[fact("genesis_agent_airdrop", 1)])],
        scanned_at=NOW1.isoformat(),
    )
    second = snapshot(
        "s2",
        [source("yellowpaper", facts=[fact("genesis_agent_airdrop", 2)], content_sha="2" * 64)],
        scanned_at=NOW2.isoformat(),
    )
    airdrop_ledger.record_scan(first, now=NOW1)
    result = airdrop_ledger.record_scan(second, now=NOW2)
    event_id = result["new_events"][0]["event_id"]

    ledger_path = isolated_state / "airdrop-radar" / "events.jsonl"
    row = json.loads(ledger_path.read_text("utf-8"))
    row["event_id"] = "tampered"
    ledger_path.write_text(json.dumps(row) + "\n", "utf-8")

    with pytest.raises(airdrop_ledger.LedgerIntegrityError):
        airdrop_ledger.acknowledge_event(event_id, now=NOW3)

    index = json.loads(
        (isolated_state / "airdrop-radar" / "event-index.json").read_text("utf-8")
    )
    assert index["events"][event_id]["acknowledged_at"] is None


def test_local_acknowledgement_is_idempotent_after_integrity_check(
    isolated_state: Path,
) -> None:
    first = snapshot(
        "s1",
        [source("yellowpaper", facts=[fact("genesis_agent_airdrop", 1)])],
        scanned_at=NOW1.isoformat(),
    )
    second = snapshot(
        "s2",
        [source("yellowpaper", facts=[fact("genesis_agent_airdrop", 2)], content_sha="2" * 64)],
        scanned_at=NOW2.isoformat(),
    )
    airdrop_ledger.record_scan(first, now=NOW1)
    result = airdrop_ledger.record_scan(second, now=NOW2)
    event_id = result["new_events"][0]["event_id"]

    first_ack = airdrop_ledger.acknowledge_event(event_id, now=NOW3)
    second_ack = airdrop_ledger.acknowledge_event(
        event_id,
        now=datetime(2026, 9, 18, 13, 0, tzinfo=UTC),
    )
    assert first_ack["acknowledged_at"] == second_ack["acknowledged_at"]


def test_export_bundle_is_concise_and_preserves_eligibility_evidence(
    isolated_state: Path,
) -> None:
    current = snapshot(
        "bundle",
        [
            source(
                "yellowpaper",
                facts=[
                    fact("genesis_agent_airdrop", 1_200_000_000),
                    fact("agent_identity_min_stake", 10),
                ],
            )
        ],
        scanned_at=NOW1.isoformat(),
    )
    airdrop_ledger.record_scan(current, now=NOW1)
    bundle = airdrop_ledger.export_bundle(now=NOW2)

    assert bundle["integrity"]["valid"] is True
    assert bundle["current"]["facts"]["genesis_agent_airdrop"]["value"] == 1_200_000_000
    assert bundle["current"]["facts"]["agent_identity_min_stake"]["value"] == 10
    assert len(bundle["recent_events"]) <= airdrop_ledger.MAX_EXPORT_EVENTS
    rendered = json.dumps(bundle)
    assert "raw_body" not in rendered
    assert "cookie" not in rendered


def test_ledger_is_isolated_from_observer_and_has_no_network_or_process_calls(
    isolated_state: Path,
) -> None:
    assert airdrop_ledger.ledger_dir() == isolated_state / "airdrop-radar"
    source_code = inspect.getsource(airdrop_ledger)
    lowered = source_code.lower()
    assert "httpx" not in lowered
    assert "requests." not in lowered
    assert "subprocess" not in lowered
    assert ' / "observer"' not in source_code
    assert "post(" not in lowered
    assert "put(" not in lowered
    assert "delete(" not in lowered
