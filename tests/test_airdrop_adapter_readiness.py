from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from flop_agent import (
    airdrop_adapter_readiness,
    airdrop_ledger,
    airdrop_monitor,
    core,
)


T0 = datetime(2026, 9, 19, 0, 0, tzinfo=UTC)


def fact(value, *, status="official", conflict=False, source="home", tier=1, authority="official"):
    return {
        "value": value,
        "source": source,
        "tier": tier,
        "authority": authority,
        "status": status,
        "conflict": conflict,
        "variants": [],
    }


def snapshot(
    *,
    testnet="planned",
    faucet="planned",
    registration=None,
    claim=None,
    claim_path="unspecified",
    e38="TBD",
) -> dict:
    facts = {
        "testnet_status": fact(testnet, status="provisional", source="teaser", tier=2, authority="provisional"),
        "faucet_status": fact(faucet, status="provisional", source="teaser", tier=2, authority="provisional"),
        "claim_path_status": fact(claim_path, status="TBD" if claim_path == "unspecified" else "normative", authority="normative"),
        "e38_status": fact(e38, status="TBD" if str(e38).upper() == "TBD" else "normative", authority="normative"),
    }
    if registration is not None:
        facts["registration_status"] = fact(registration)
    if claim is not None:
        facts["claim_status"] = fact(claim)
    return {
        "schema_version": 2,
        "read_only": True,
        "scanned_at": T0.isoformat(),
        "health": "ok",
        "snapshot_id": "s" * 64,
        "source_precedence": [],
        "sources": [],
        "resolved_facts": facts,
        "deadlines": [],
        "summary": {
            "available_sources": 1,
            "failed_sources": [],
            "conflicts": [],
        },
    }


def durable(
    action_class: str,
    *,
    candidate: bool = True,
    authority: str = "official",
    tier: int = 1,
    observation: str = "current",
    status: str = "ok",
    expires_at: datetime | None = None,
) -> dict:
    key = {
        "faucet": "faucet_status",
        "registration": "registration_status",
        "claim": "claim_status",
    }[action_class]
    before = {"value": "planned"}
    after = {"value": "open"}
    event_id = hashlib.sha256(
        json.dumps(
            {
                "type": "CHANGED",
                "key": key,
                "before": before,
                "after": after,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()[:24]
    event = {
        "event_id": event_id,
        "type": "CHANGED",
        "key": key,
        "severity": "ACTION_NOW",
        "before": before,
        "after": after,
    }
    if candidate:
        event["action_candidate"] = {
            "schema_version": 1,
            "action_class": action_class,
            "payload": {
                "action": action_class,
                "url": f"https://flop.finance/{action_class}",
                "subject": "did:flop:maru",
            },
            "summary": f"Exact {action_class} implementation candidate.",
            "cost_note": "0 FLOP / implementation evidence only",
            "reversible": False,
            "expires_at": (expires_at or T0 + timedelta(hours=2)).isoformat(),
        }
    row = {
        "schema_version": 1,
        "sequence": 1,
        "record_type": "material_event",
        "event_id": event_id,
        "first_seen": T0.isoformat(),
        "last_seen": T0.isoformat(),
        "observed_at": T0.isoformat(),
        "previous_hash": "",
        "event": event,
        "source_evidence": [
            {
                "observation": observation,
                "name": "official",
                "url": "https://flop.finance/",
                "final_url": "https://flop.finance/",
                "tier": tier,
                "authority": authority,
                "status": status,
                "content_sha256": "b" * 64,
            }
        ],
    }
    row["hash"] = hashlib.sha256(
        json.dumps(
            {k: v for k, v in row.items() if k != "hash"},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return row


def verified(*rows: dict) -> dict:
    return {
        "valid": True,
        "count": len(rows),
        "tip_hash": rows[-1]["hash"] if rows else "",
        "records": list(rows),
    }


def test_current_official_shape_is_blocked_for_all_three() -> None:
    report = airdrop_adapter_readiness.evaluate(
        snapshot=snapshot(),
        verified_ledger=verified(),
        now=T0,
    )

    assert report["overall"] == "BLOCKED"
    assert report["actions"]["faucet"]["state"] == "BLOCKED"
    assert "not_open:testnet_status:planned" in report["actions"]["faucet"]["blockers"]
    assert "not_open:faucet_status:planned" in report["actions"]["faucet"]["blockers"]
    assert report["actions"]["registration"]["state"] == "BLOCKED"
    assert "missing_fact:registration_status" in report["actions"]["registration"]["blockers"]
    assert report["actions"]["claim"]["state"] == "BLOCKED"
    assert "missing_fact:claim_status" in report["actions"]["claim"]["blockers"]
    assert "claim_path_unresolved" in report["actions"]["claim"]["blockers"]
    assert "e38_unresolved" in report["actions"]["claim"]["blockers"]


@pytest.mark.parametrize("action_class", ["faucet", "registration", "claim"])
def test_open_status_without_exact_candidate_remains_blocked(action_class: str) -> None:
    snap = snapshot(
        testnet="live",
        faucet="open",
        registration="open",
        claim="open",
        claim_path="specified",
        e38="RATIFIED",
    )
    row = durable(action_class, candidate=False)
    report = airdrop_adapter_readiness.evaluate(
        snapshot=snap,
        verified_ledger=verified(row),
        now=T0,
    )
    assert report["actions"][action_class]["state"] == "BLOCKED"
    assert "action_candidate_missing" in report["actions"][action_class]["blockers"]


@pytest.mark.parametrize(
    "authority,tier,observation,status",
    [
        ("engineering", 3, "current", "ok"),
        ("official", 2, "previous", "ok"),
        ("official", 2, "last_success", "ok"),
        ("official", 2, "current", "error"),
        ("provisional", 2, "current", "ok"),
    ],
)
def test_untrusted_candidate_evidence_is_blocked(
    authority: str,
    tier: int,
    observation: str,
    status: str,
) -> None:
    snap = snapshot(testnet="live", registration="open")
    row = durable(
        "registration",
        authority=authority,
        tier=tier,
        observation=observation,
        status=status,
    )
    report = airdrop_adapter_readiness.evaluate(
        snapshot=snap,
        verified_ledger=verified(row),
        now=T0,
    )
    blockers = report["actions"]["registration"]["blockers"]
    assert report["actions"]["registration"]["state"] == "BLOCKED"
    assert any(code.startswith("action_candidate_invalid:") for code in blockers)


def test_expired_candidate_is_blocked() -> None:
    snap = snapshot(testnet="live", faucet="open")
    row = durable(
        "faucet",
        expires_at=T0 - timedelta(seconds=1),
    )
    report = airdrop_adapter_readiness.evaluate(
        snapshot=snap,
        verified_ledger=verified(row),
        now=T0,
    )
    assert report["actions"]["faucet"]["state"] == "BLOCKED"
    assert any(
        "airdrop_stager_expiry_invalid" in code
        for code in report["actions"]["faucet"]["blockers"]
    )


def test_tampered_candidate_is_blocked() -> None:
    snap = snapshot(testnet="live", registration="open")
    row = durable("registration")
    row["event"]["action_candidate"]["action_class"] = "claim"

    report = airdrop_adapter_readiness.evaluate(
        snapshot=snap,
        verified_ledger=verified(row),
        now=T0,
    )
    assert report["actions"]["registration"]["state"] == "BLOCKED"
    assert any(
        "action_key_mismatch" in code
        for code in report["actions"]["registration"]["blockers"]
    )


def test_exact_canonical_candidate_can_become_implementation_ready() -> None:
    snap = snapshot(testnet="live", registration="open")
    row = durable("registration")
    report = airdrop_adapter_readiness.evaluate(
        snapshot=snap,
        verified_ledger=verified(row),
        now=T0,
    )

    registration = report["actions"]["registration"]
    assert registration["state"] == "IMPLEMENTATION_READY"
    assert registration["blockers"] == []
    assert registration["candidate"]["source_event_id"] == row["event_id"]
    assert registration["candidate"]["source_ledger_hash"] == row["hash"]
    assert registration["candidate"]["expires_at"] == (
        T0 + timedelta(hours=2)
    ).isoformat()


def test_claim_stays_blocked_until_e38_and_claim_path_resolve() -> None:
    row = durable("claim")
    blocked = airdrop_adapter_readiness.evaluate(
        snapshot=snapshot(
            testnet="live",
            claim="open",
            claim_path="unspecified",
            e38="TBD",
        ),
        verified_ledger=verified(row),
        now=T0,
    )
    assert blocked["actions"]["claim"]["state"] == "BLOCKED"
    assert "claim_path_unresolved" in blocked["actions"]["claim"]["blockers"]
    assert "e38_unresolved" in blocked["actions"]["claim"]["blockers"]

    ready = airdrop_adapter_readiness.evaluate(
        snapshot=snapshot(
            testnet="live",
            claim="open",
            claim_path="specified",
            e38="RATIFIED",
        ),
        verified_ledger=verified(row),
        now=T0,
    )
    assert ready["actions"]["claim"]["state"] == "IMPLEMENTATION_READY"


def test_conflicting_open_fact_is_blocked() -> None:
    snap = snapshot(testnet="live", faucet="open")
    snap["resolved_facts"]["faucet_status"]["conflict"] = True
    row = durable("faucet")
    report = airdrop_adapter_readiness.evaluate(
        snapshot=snap,
        verified_ledger=verified(row),
        now=T0,
    )
    assert "conflicting_fact:faucet_status" in report["actions"]["faucet"]["blockers"]


def test_readiness_never_stages_candidate_or_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(core, "STATE", tmp_path)
    snap = snapshot(testnet="live", registration="open")
    row = durable("registration")

    report = airdrop_adapter_readiness.evaluate(
        snapshot=snap,
        verified_ledger=verified(row),
        now=T0,
    )
    assert report["actions"]["registration"]["state"] == "IMPLEMENTATION_READY"
    radar_dir = tmp_path / "airdrop-radar"
    assert not (radar_dir / "action-candidates.json").exists()
    assert not (radar_dir / "action-inbox.json").exists()
    assert not (radar_dir / "action-executions.json").exists()


def test_current_snapshot_returns_defensive_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(core, "STATE", tmp_path)
    directory = tmp_path / "airdrop-radar"
    directory.mkdir(parents=True)
    snap = snapshot()
    (directory / "current-snapshot.json").write_text(
        json.dumps({"schema_version": 1, "snapshot": snap}),
        encoding="utf-8",
    )

    first = airdrop_ledger.current_snapshot()
    first["resolved_facts"]["testnet_status"]["value"] = "tampered"
    second = airdrop_ledger.current_snapshot()

    assert second["resolved_facts"]["testnet_status"]["value"] == "planned"


def test_monitor_status_and_daily_summary_surface_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = {
        "overall": "BLOCKED",
        "snapshot_id": "s" * 64,
        "ledger_valid": True,
        "actions": {
            "faucet": {"state": "BLOCKED", "blockers": ["not_open:testnet_status:planned"]},
            "registration": {"state": "BLOCKED", "blockers": ["missing_fact:registration_status"]},
            "claim": {"state": "BLOCKED", "blockers": ["e38_unresolved"]},
        },
    }
    monkeypatch.setattr(
        airdrop_monitor.airdrop_adapter_readiness,
        "evaluate",
        lambda now=None: report,
    )

    concise = airdrop_monitor._adapter_readiness_status(now=T0)
    assert concise["overall"] == "BLOCKED"
    assert concise["actions"]["claim"]["blockers"] == ["e38_unresolved"]


def test_gate_source_has_no_external_transport_or_executor_registration() -> None:
    source = (
        core.ROOT / "src" / "flop_agent" / "airdrop_adapter_readiness.py"
    ).read_text("utf-8").lower()

    for forbidden in (
        "httpx",
        "requests",
        "urllib.request",
        "oracle_signer",
        "technocore_signing_key",
        "discord_bot_token",
        "subprocess",
        "socket",
        "_adapters[",
        "stage_request(",
        "stage_durable_event(",
        "execute_prepared(",
    ):
        assert forbidden not in source


def test_cli_exposes_readiness_command() -> None:
    source = (core.ROOT / "src" / "flop_agent" / "cli.py").read_text("utf-8")
    assert '"airdrop-adapter-readiness"' in source
    assert "airdrop_adapter_readiness.evaluate()" in source
