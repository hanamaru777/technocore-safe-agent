from datetime import UTC, datetime
from pathlib import Path

from flop_agent import airdrop_monitor
from flop_agent import airdrop_monitor_challenge_routing as routing
from flop_agent import airdrop_radar


NOW = datetime(2026, 10, 6, 4, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[1]


def _activity(*rows):
    return {
        "value": list(rows),
        "source": "github_org",
        "tier": 3,
        "authority": "engineering",
        "status": "engineering",
        "conflict": False,
        "variants": [],
    }


def _repo(name, *, archived=False, pushed="2026-10-06T03:00:00+00:00"):
    return {
        "name": name,
        "archived": archived,
        "default_branch": "main",
        "pushed_at": pushed,
    }


def _snapshot(snapshot_id, fact):
    return {
        "schema_version": airdrop_radar.SCHEMA_VERSION,
        "read_only": True,
        "scanned_at": NOW.isoformat(),
        "health": "ok",
        "snapshot_id": snapshot_id,
        "source_precedence": ["Tier 3"],
        "sources": [],
        "resolved_facts": {"github_critical_repo_activity": fact},
        "deadlines": [],
        "summary": {"available_sources": 1, "failed_sources": [], "conflicts": []},
        "warnings": [],
    }


def test_baseline_never_emits_special_event():
    current = _snapshot("s1", _activity(_repo("first-challenge")))

    result = routing.compare_snapshots(None, current, now=NOW)

    assert result["baseline"] is True
    assert result["events"] == []


def test_new_non_archived_challenge_repo_emits_one_high_special_event():
    before = _snapshot("s1", _activity(_repo("existing-challenge")))
    after = _snapshot(
        "s2",
        _activity(
            _repo("existing-challenge"),
            _repo("next-alpha-challenge"),
        ),
    )

    result = routing.compare_snapshots(before, after, now=NOW)

    special = [row for row in result["events"] if row["type"] == routing.SPECIAL_TYPE]
    assert len(special) == 1
    assert special[0]["severity"] == "HIGH"
    assert special[0]["key"] == "challenge_repo:next-alpha-challenge"
    assert special[0]["after"]["repo_name"] == "next-alpha-challenge"
    assert special[0]["after"]["source"] == "github_org"
    assert routing.route(special[0]) == "immediate"
    assert "spec" in routing.safe_next_step(special[0])
    assert "binding action" in routing.safe_next_step(special[0])

    generic = [
        row
        for row in result["events"]
        if row.get("key") == "github_critical_repo_activity"
    ]
    assert len(generic) == 1
    assert routing.route(generic[0]) == "ledger_only"


def test_existing_repo_push_update_does_not_emit_special_event():
    before = _snapshot(
        "s1",
        _activity(_repo("existing-challenge", pushed="2026-10-06T02:00:00+00:00")),
    )
    after = _snapshot(
        "s2",
        _activity(_repo("existing-challenge", pushed="2026-10-06T03:00:00+00:00")),
    )

    result = routing.compare_snapshots(before, after, now=NOW)

    assert not any(row["type"] == routing.SPECIAL_TYPE for row in result["events"])
    generic = [row for row in result["events"] if row.get("key") == "github_critical_repo_activity"]
    assert len(generic) == 1
    assert routing.route(generic[0]) == airdrop_monitor._route(generic[0])


def test_archived_or_nonchallenge_addition_does_not_emit_special_event():
    before = _snapshot("s1", _activity())
    after = _snapshot(
        "s2",
        _activity(
            _repo("old-challenge", archived=True),
            _repo("flop-core"),
        ),
    )

    result = routing.compare_snapshots(before, after, now=NOW)

    assert not any(row["type"] == routing.SPECIAL_TYPE for row in result["events"])


def test_packaging_uses_reviewed_overlay_without_adding_privileges():
    service = (ROOT / "packaging/oracle/airdrop-monitor.service").read_text("utf-8")

    assert "flop_agent.airdrop_monitor_challenge_routing" in service
    assert "User=technocore" in service
    assert "NoNewPrivileges=true" in service
    assert "ProtectSystem=strict" in service
    assert "CapabilityBoundingSet=" in service
    assert "signer" not in service.lower()
    assert "vault" not in service.lower()
