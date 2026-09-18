from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from flop_agent import airdrop_ledger, airdrop_monitor, airdrop_radar, core


T0 = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)


def make_fact(
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
        "authority": "normative" if tier == 1 else "engineering",
        "status": status,
        "evidence_sha256": ("a" if source == "yellowpaper" else "b") * 64,
        "evidence_excerpt": f"{key} evidence {value}",
    }


def make_source(
    name: str,
    *,
    facts: list[dict],
    tier: int = 1,
    authority: str = "normative",
    content_hash: str = "a" * 64,
    critical: bool = True,
) -> dict:
    return {
        "name": name,
        "url": (
            f"https://api.github.com/orgs/flop-labs/{name}"
            if tier == 3
            else f"https://flop.finance/{name}/"
        ),
        "final_url": (
            f"https://api.github.com/orgs/flop-labs/{name}"
            if tier == 3
            else f"https://flop.finance/{name}/"
        ),
        "tier": tier,
        "authority": authority,
        "critical": critical,
        "status": "ok",
        "attempts": 1,
        "latency_ms": 5,
        "content_sha256": content_hash,
        "content_bytes": 100,
        "meta": {"version": "0.5.0 (draft)", "updated": "2026-09-18"},
        "facts": facts,
        "deadlines": [],
        "interest_links": [],
    }


def make_snapshot(snapshot_id: str, rows: list[dict], at: datetime) -> dict:
    facts = [fact for row in rows for fact in row.get("facts", [])]
    resolved = airdrop_radar._resolve_facts(facts)
    return {
        "schema_version": airdrop_radar.SCHEMA_VERSION,
        "read_only": True,
        "scanned_at": at.isoformat(),
        "health": "ok",
        "snapshot_id": snapshot_id,
        "source_precedence": ["Tier 1", "Tier 3"],
        "sources": rows,
        "resolved_facts": resolved,
        "deadlines": [],
        "summary": {
            "available_sources": len(rows),
            "failed_sources": [],
            "conflicts": sorted(
                key for key, value in resolved.items() if value.get("conflict")
            ),
        },
        "warnings": [],
    }


def high_snapshot(snapshot_id: str, value: int, at: datetime, hash_char: str) -> dict:
    return make_snapshot(
        snapshot_id,
        [
            make_source(
                "yellowpaper",
                facts=[make_fact("genesis_agent_airdrop", value)],
                content_hash=hash_char * 64,
            )
        ],
        at,
    )


@pytest.fixture
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(core, "STATE", tmp_path)
    return tmp_path


def test_default_schedule_is_15_minutes_with_hard_5_minute_floor(
    isolated_state: Path,
) -> None:
    config = airdrop_monitor.load_config()
    assert config["interval_seconds"] == 900
    assert config["minimum_scan_interval_seconds"] == 300
    assert airdrop_monitor.monitor_dir() == isolated_state / "airdrop-radar"


def test_invalid_too_fast_config_fails_closed(isolated_state: Path) -> None:
    base = isolated_state / "airdrop-radar"
    base.mkdir(parents=True)
    (base / "monitor-config.json").write_text(
        json.dumps(
            {
                **airdrop_monitor.DEFAULT_CONFIG,
                "minimum_scan_interval_seconds": 60,
            }
        ),
        "utf-8",
    )
    with pytest.raises(RuntimeError, match="minimum_interval_too_fast"):
        airdrop_monitor.load_config()


def test_baseline_cycle_writes_heartbeat_but_no_alerts(isolated_state: Path) -> None:
    snap = high_snapshot("s1", 1_200_000_000, T0, "a")
    result = airdrop_monitor.run_once(scanner=lambda: snap, now=T0)

    assert result["outcome"] == "recorded"
    assert result["baseline"] is True
    assert result["immediate_alerts"] == []
    assert result["digest_alerts"] == []

    status = airdrop_monitor.monitor_status(now=T0 + timedelta(seconds=10))
    assert status["outcome"] == "recorded"
    assert status["heartbeat_stale"] is False
    assert status["snapshot_id"] == "s1"
    assert status["ledger_integrity_valid"] is True


def test_high_change_becomes_immediate_actionable_alert(isolated_state: Path) -> None:
    first = high_snapshot("s1", 1_200_000_000, T0, "a")
    second = high_snapshot("s2", 1_250_000_000, T0 + timedelta(minutes=15), "b")

    airdrop_monitor.run_once(scanner=lambda: first, now=T0)
    result = airdrop_monitor.run_once(
        scanner=lambda: second,
        now=T0 + timedelta(minutes=15),
    )

    assert len(result["immediate_alerts"]) == 1
    alert = result["immediate_alerts"][0]
    assert alert["severity"] == "HIGH"
    assert alert["key"] == "genesis_agent_airdrop"
    assert alert["route"] == "immediate"
    assert alert["source"] == "yellowpaper"
    assert alert["tier"] == 1
    assert alert["before"]["value"] == 1_200_000_000
    assert alert["after"]["value"] == 1_250_000_000
    assert "binding" in alert["safe_next_step"].lower()

    pending = airdrop_monitor.pending_alerts()["alerts"]
    assert len(pending) == 1
    assert pending[0]["event_id"] == alert["event_id"]


def test_medium_is_digest_and_info_stays_ledger_only(isolated_state: Path) -> None:
    at1 = T0
    at2 = T0 + timedelta(minutes=15)
    at3 = T0 + timedelta(minutes=30)

    base = make_snapshot(
        "m1",
        [
            make_source(
                "github_org",
                facts=[
                    make_fact(
                        "github_interest_repo_names",
                        ["yellowpaper"],
                        source="github_org",
                        tier=3,
                        status="engineering",
                    ),
                    make_fact(
                        "unclassified_info",
                        "v1",
                        source="github_org",
                        tier=3,
                        status="engineering",
                    ),
                ],
                tier=3,
                authority="engineering",
                critical=False,
                content_hash="1" * 64,
            )
        ],
        at1,
    )
    medium = make_snapshot(
        "m2",
        [
            make_source(
                "github_org",
                facts=[
                    make_fact(
                        "github_interest_repo_names",
                        ["yellowpaper", "challenge"],
                        source="github_org",
                        tier=3,
                        status="engineering",
                    ),
                    make_fact(
                        "unclassified_info",
                        "v1",
                        source="github_org",
                        tier=3,
                        status="engineering",
                    ),
                ],
                tier=3,
                authority="engineering",
                critical=False,
                content_hash="2" * 64,
            )
        ],
        at2,
    )
    info = make_snapshot(
        "m3",
        [
            make_source(
                "github_org",
                facts=[
                    make_fact(
                        "github_interest_repo_names",
                        ["yellowpaper", "challenge"],
                        source="github_org",
                        tier=3,
                        status="engineering",
                    ),
                    make_fact(
                        "unclassified_info",
                        "v2",
                        source="github_org",
                        tier=3,
                        status="engineering",
                    ),
                ],
                tier=3,
                authority="engineering",
                critical=False,
                content_hash="3" * 64,
            )
        ],
        at3,
    )

    airdrop_monitor.run_once(scanner=lambda: base, now=at1)
    second = airdrop_monitor.run_once(scanner=lambda: medium, now=at2)
    assert second["immediate_alerts"] == []
    assert len(second["digest_alerts"]) == 1
    assert second["digest_alerts"][0]["key"] == "github_interest_repo_names"

    third = airdrop_monitor.run_once(scanner=lambda: info, now=at3)
    assert third["immediate_alerts"] == []
    assert third["digest_alerts"] == []
    assert any(
        row["key"] == "unclassified_info"
        for row in third["new_events"]
    )


def test_deadline_sensitive_medium_routes_immediately() -> None:
    event = {
        "severity": "MEDIUM",
        "deadline_gate": {"seconds_remaining": 3600},
    }
    assert airdrop_monitor._route(event) == "immediate"


def test_scan_floor_skips_without_calling_scanner(isolated_state: Path) -> None:
    snap = high_snapshot("s1", 1_200_000_000, T0, "a")
    airdrop_monitor.run_once(scanner=lambda: snap, now=T0)

    calls = 0

    def scanner() -> dict:
        nonlocal calls
        calls += 1
        return snap

    skipped = airdrop_monitor.run_once(
        scanner=scanner,
        now=T0 + timedelta(seconds=60),
    )
    assert skipped["outcome"] == "skipped_too_soon"
    assert calls == 0
    assert skipped["seconds_until_eligible"] == 240


def test_transient_scan_failure_does_not_kill_future_cycle(isolated_state: Path) -> None:
    def failing() -> dict:
        raise TimeoutError("temporary read timeout")

    failed = airdrop_monitor.run_once(scanner=failing, now=T0)
    assert failed == {
        "outcome": "scan_failed",
        "recorded": False,
        "error_type": "TimeoutError",
    }
    status = airdrop_monitor.monitor_status(now=T0 + timedelta(seconds=10))
    assert status["outcome"] == "scan_failed"

    snap = high_snapshot("recovered", 1_200_000_000, T0 + timedelta(minutes=15), "a")
    recovered = airdrop_monitor.run_once(
        scanner=lambda: snap,
        now=T0 + timedelta(minutes=15),
    )
    assert recovered["outcome"] == "recorded"
    assert recovered["baseline"] is True


def test_corrupt_evidence_blocks_monitor_and_marks_heartbeat(isolated_state: Path) -> None:
    first = high_snapshot("s1", 1_200_000_000, T0, "a")
    second = high_snapshot("s2", 1_250_000_000, T0 + timedelta(minutes=15), "b")
    airdrop_monitor.run_once(scanner=lambda: first, now=T0)
    airdrop_monitor.run_once(
        scanner=lambda: second,
        now=T0 + timedelta(minutes=15),
    )

    ledger = isolated_state / "airdrop-radar" / "events.jsonl"
    row = json.loads(ledger.read_text("utf-8"))
    row["event"]["severity"] = "INFO"
    ledger.write_text(json.dumps(row) + "\n", "utf-8")

    third = high_snapshot("s3", 1_300_000_000, T0 + timedelta(minutes=30), "c")
    with pytest.raises(airdrop_ledger.LedgerIntegrityError):
        airdrop_monitor.run_once(
            scanner=lambda: third,
            now=T0 + timedelta(minutes=30),
        )
    heartbeat = json.loads(
        (isolated_state / "airdrop-radar" / "monitor-heartbeat.json").read_text("utf-8")
    )
    assert heartbeat["outcome"] == "blocked_integrity"


def test_repeated_same_event_is_not_requeued(isolated_state: Path) -> None:
    s1 = high_snapshot("s1", 1, T0, "a")
    s2 = high_snapshot("s2", 2, T0 + timedelta(minutes=15), "b")
    s3 = high_snapshot("s3", 1, T0 + timedelta(minutes=30), "c")
    s4 = high_snapshot("s4", 2, T0 + timedelta(minutes=45), "d")

    airdrop_monitor.run_once(scanner=lambda: s1, now=T0)
    first = airdrop_monitor.run_once(scanner=lambda: s2, now=T0 + timedelta(minutes=15))
    forward_id = first["immediate_alerts"][0]["event_id"]
    airdrop_monitor.run_once(scanner=lambda: s3, now=T0 + timedelta(minutes=30))
    repeat = airdrop_monitor.run_once(scanner=lambda: s4, now=T0 + timedelta(minutes=45))

    assert repeat["immediate_alerts"] == []
    outbox = airdrop_monitor.pending_alerts()["alerts"]
    assert sum(item["event_id"] == forward_id for item in outbox) == 1


def test_alert_capacity_failure_is_visible_and_does_not_evict_pending(
    isolated_state: Path,
) -> None:
    base = isolated_state / "airdrop-radar"
    base.mkdir(parents=True, exist_ok=True)
    config = {
        **airdrop_monitor.DEFAULT_CONFIG,
        "max_alerts": 10,
    }
    (base / "monitor-config.json").write_text(json.dumps(config), "utf-8")

    existing = {
        "schema_version": airdrop_monitor.SCHEMA_VERSION,
        "updated_at": T0.isoformat(),
        "events": {
            f"existing-{i}": {
                "event_id": f"existing-{i}",
                "first_queued_at": T0.isoformat(),
                "last_seen": T0.isoformat(),
                "route": "immediate",
                "delivery_state": "pending",
                "payload": {"event_id": f"existing-{i}"},
            }
            for i in range(10)
        },
    }
    (base / "alert-outbox.json").write_text(json.dumps(existing), "utf-8")

    first = high_snapshot("s1", 1, T0, "a")
    second = high_snapshot("s2", 2, T0 + timedelta(minutes=15), "b")
    airdrop_monitor.run_once(scanner=lambda: first, now=T0)

    with pytest.raises(RuntimeError, match="alert_capacity_exceeded"):
        airdrop_monitor.run_once(
            scanner=lambda: second,
            now=T0 + timedelta(minutes=15),
        )

    persisted = json.loads((base / "alert-outbox.json").read_text("utf-8"))
    assert len(persisted["events"]) == 10
    assert all(
        item["delivery_state"] == "pending"
        for item in persisted["events"].values()
    )
    heartbeat = json.loads((base / "monitor-heartbeat.json").read_text("utf-8"))
    assert heartbeat["outcome"] == "alert_routing_failed"


def test_status_exposes_heartbeat_age_and_staleness(isolated_state: Path) -> None:
    snap = high_snapshot("s1", 1, T0, "a")
    airdrop_monitor.run_once(scanner=lambda: snap, now=T0)

    fresh = airdrop_monitor.monitor_status(now=T0 + timedelta(minutes=5))
    assert fresh["heartbeat_age_seconds"] == 300
    assert fresh["heartbeat_stale"] is False

    stale = airdrop_monitor.monitor_status(now=T0 + timedelta(minutes=31))
    assert stale["heartbeat_age_seconds"] == 1860
    assert stale["heartbeat_stale"] is True


def test_daily_summary_answers_changed_matters_and_next_steps(isolated_state: Path) -> None:
    first = high_snapshot("s1", 1_200_000_000, T0, "a")
    second = high_snapshot("s2", 1_250_000_000, T0 + timedelta(minutes=15), "b")
    airdrop_monitor.run_once(scanner=lambda: first, now=T0)
    airdrop_monitor.run_once(scanner=lambda: second, now=T0 + timedelta(minutes=15))

    summary = airdrop_monitor.daily_summary(now=T0 + timedelta(hours=1))
    assert summary["ledger_integrity_valid"] is True
    assert summary["counts"]["HIGH"] >= 1
    assert any(
        row["key"] == "genesis_agent_airdrop"
        for row in summary["what_changed"]
    )
    assert any(
        row["key"] == "genesis_agent_airdrop"
        for row in summary["what_matters"]
    )
    assert summary["what_to_do"]


def test_link_discovery_wording_never_claims_action_is_open() -> None:
    event = {
        "type": "OFFICIAL_LINK_DISCOVERED",
        "key": "official_link:https://flop.finance/testnet/",
    }
    step = airdrop_monitor.safe_next_step(event).lower()
    assert "does not mean the action is open" in step


def test_source_outage_wording_never_claims_rule_change() -> None:
    event = {
        "type": "SOURCE_UNAVAILABLE",
        "key": "source:yellowpaper:availability",
    }
    step = airdrop_monitor.safe_next_step(event).lower()
    assert "do not treat the outage as a rule change" in step


def test_monitor_core_has_no_external_write_transport_or_observer_path(
    isolated_state: Path,
) -> None:
    source_code = inspect.getsource(airdrop_monitor)
    lowered = source_code.lower()
    assert "httpx" not in lowered
    assert "requests." not in lowered
    assert "subprocess" not in lowered
    assert ' / "observer"' not in source_code
    assert "discord" not in lowered
    assert "sign_seed" not in lowered
