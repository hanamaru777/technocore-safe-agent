from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from flop_agent import (
    airdrop_action_stager,
    airdrop_approval,
    airdrop_ledger,
    airdrop_monitor,
    airdrop_notifier,
    core,
)


T0 = datetime(2026, 9, 19, 0, 0, tzinfo=UTC)


@pytest.fixture
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setattr(airdrop_approval, "_FAILURE_NOTIFIED", False)
    return tmp_path


def _event_id(action_class: str, key: str) -> str:
    return hashlib.sha256(f"{action_class}:{key}".encode()).hexdigest()[:24]


def durable(
    action_class: str = "registration",
    *,
    authority: str = "official",
    tier: int = 2,
    status: str = "ok",
    observation: str = "current",
    after: str = "open",
    severity: str = "ACTION_NOW",
    payload: dict | None = None,
) -> dict:
    key = {
        "registration": "registration_status",
        "faucet": "faucet_status",
        "claim": "claim_status",
        "spend": "spend_to_unlock_status",
    }[action_class]
    event_id = _event_id(action_class, key)
    event = {
        "event_id": event_id,
        "type": "CHANGED",
        "key": key,
        "severity": severity,
        "before": {"value": "closed"},
        "after": {"value": after},
        "action_candidate": {
            "schema_version": 1,
            "action_class": action_class,
            "payload": payload
            or {
                "action": action_class,
                "subject": "did:flop:maru",
                "url": f"https://flop.finance/{action_class}",
            },
            "summary": f"Execute exact {action_class} action for MARU.",
            "cost_note": "0 FLOP / no real-value spend",
            "reversible": False,
            "expires_at": (T0 + timedelta(hours=2)).isoformat(),
        },
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
                "name": "home",
                "url": "https://flop.finance/",
                "final_url": "https://flop.finance/",
                "tier": tier,
                "authority": authority,
                "status": status,
                "content_sha256": "b" * 64,
            }
        ],
    }
    basis = {k: v for k, v in row.items() if k != "hash"}
    row["hash"] = hashlib.sha256(
        json.dumps(
            basis,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return row


def patch_ledger(monkeypatch: pytest.MonkeyPatch, rows: list[dict]) -> None:
    monkeypatch.setattr(
        airdrop_ledger,
        "verify_ledger",
        lambda: {
            "valid": True,
            "count": len(rows),
            "tip_hash": rows[-1]["hash"] if rows else "",
            "records": rows,
        },
    )


@pytest.mark.parametrize("action_class", ["registration", "faucet", "claim"])
def test_trusted_open_event_stages_exact_durable_candidate(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
    action_class: str,
) -> None:
    row = durable(action_class)
    patch_ledger(monkeypatch, [row])

    result = airdrop_action_stager.stage_new_events(
        [row["event_id"]],
        {row["event_id"]: row},
        now=T0,
    )

    assert len(result["staged"]) == 1
    staged = result["staged"][0]
    assert staged["action_class"] == action_class
    assert staged["request_id"]
    assert staged["approval_digest"]
    assert airdrop_action_stager.store_path().exists()

    approval = airdrop_approval.get_request(staged["request_id"], now=T0)
    assert approval["status"] == "pending"
    assert approval["payload_sha256"] == staged["payload_sha256"]
    assert approval["source_event_id"] == row["event_id"]

    exact = airdrop_action_stager.get_candidate_for_request(staged["request_id"])
    assert exact["payload"] == row["event"]["action_candidate"]["payload"]


def test_noncanonical_durable_event_is_rejected(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = durable()
    patch_ledger(monkeypatch, [row])
    fake = json.loads(json.dumps(row))
    fake["event"]["after"] = {"value": "live"}

    with pytest.raises(
        airdrop_action_stager.StagingBridgeError,
        match="not_canonical_ledger_record",
    ):
        airdrop_action_stager.stage_durable_event(fake, now=T0)


def test_no_embedded_candidate_is_noop(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = durable()
    row["event"].pop("action_candidate")
    patch_ledger(monkeypatch, [row])

    result = airdrop_action_stager.stage_new_events(
        [row["event_id"]],
        {row["event_id"]: row},
        now=T0,
    )

    assert result["staged"] == []
    assert result["skipped_without_candidate"] == 1
    assert not airdrop_action_stager.store_path().exists()


@pytest.mark.parametrize(
    "authority,tier,status,observation",
    [
        ("engineering", 3, "ok", "current"),
        ("provisional", 2, "ok", "current"),
        ("official", 2, "error", "current"),
        ("official", 2, "ok", "previous"),
    ],
)
def test_untrusted_evidence_never_stages(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority: str,
    tier: int,
    status: str,
    observation: str,
) -> None:
    row = durable(
        authority=authority,
        tier=tier,
        status=status,
        observation=observation,
    )
    patch_ledger(monkeypatch, [row])

    with pytest.raises(
        airdrop_action_stager.StagingBridgeError,
        match="trusted_evidence_missing",
    ):
        airdrop_action_stager.stage_new_events(
            [row["event_id"]],
            {row["event_id"]: row},
            now=T0,
        )


def test_class_key_and_open_state_are_exact(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = durable("registration", after="closed")
    patch_ledger(monkeypatch, [row])

    with pytest.raises(
        airdrop_action_stager.StagingBridgeError,
        match="action_not_open",
    ):
        airdrop_action_stager.stage_new_events(
            [row["event_id"]],
            {row["event_id"]: row},
            now=T0,
        )

    row = durable("registration")
    row["event"]["key"] = "claim_status"
    patch_ledger(monkeypatch, [row])
    with pytest.raises(
        airdrop_action_stager.StagingBridgeError,
        match="action_key_mismatch",
    ):
        airdrop_action_stager.stage_new_events(
            [row["event_id"]],
            {row["event_id"]: row},
            now=T0,
        )


def test_unsupported_auto_stage_class_is_blocked(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = durable("spend")
    patch_ledger(monkeypatch, [row])

    with pytest.raises(
        airdrop_action_stager.StagingBridgeError,
        match="not_auto_stageable",
    ):
        airdrop_action_stager.stage_new_events(
            [row["event_id"]],
            {row["event_id"]: row},
            now=T0,
        )


def test_secret_like_and_external_url_payloads_are_blocked(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for payload, error in [
        ({"private_key": "never"}, "secret_like_key"),
        ({"url": "https://evil.example/claim"}, "url_not_allowlisted"),
    ]:
        row = durable(payload=payload)
        patch_ledger(monkeypatch, [row])
        with pytest.raises(airdrop_action_stager.StagingBridgeError, match=error):
            airdrop_action_stager.stage_new_events(
                [row["event_id"]],
                {row["event_id"]: row},
                now=T0,
            )


def test_staging_is_idempotent_and_payload_digest_is_canonical(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = durable(payload={"b": 2, "a": 1})
    patch_ledger(monkeypatch, [row])

    first = airdrop_action_stager.stage_new_events(
        [row["event_id"]],
        {row["event_id"]: row},
        now=T0,
    )["staged"][0]
    second = airdrop_action_stager.stage_new_events(
        [row["event_id"]],
        {row["event_id"]: row},
        now=T0,
    )["staged"][0]

    assert first == second
    assert first["payload_sha256"] == hashlib.sha256(b'{"a":1,"b":2}').hexdigest()
    assert len(airdrop_approval.list_requests(now=T0)) == 1


def test_expiry_and_severity_guards(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = durable()
    row["event"]["action_candidate"]["expires_at"] = (
        T0 + timedelta(days=8)
    ).isoformat()
    patch_ledger(monkeypatch, [row])
    with pytest.raises(
        airdrop_action_stager.StagingBridgeError,
        match="expiry_invalid",
    ):
        airdrop_action_stager.stage_new_events(
            [row["event_id"]],
            {row["event_id"]: row},
            now=T0,
        )

    row = durable(severity="MEDIUM")
    patch_ledger(monkeypatch, [row])
    with pytest.raises(
        airdrop_action_stager.StagingBridgeError,
        match="severity_not_actionable",
    ):
        airdrop_action_stager.stage_new_events(
            [row["event_id"]],
            {row["event_id"]: row},
            now=T0,
        )


def test_bound_candidate_tamper_fails_closed(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = durable()
    patch_ledger(monkeypatch, [row])
    staged = airdrop_action_stager.stage_new_events(
        [row["event_id"]],
        {row["event_id"]: row},
        now=T0,
    )["staged"][0]

    raw = json.loads(airdrop_action_stager.store_path().read_text("utf-8"))
    raw["candidates"][staged["candidate_id"]]["summary"] = "tampered"
    airdrop_action_stager.store_path().write_text(
        json.dumps(raw),
        encoding="utf-8",
    )

    with pytest.raises(
        airdrop_action_stager.StagingBridgeError,
        match="approval_binding_mismatch",
    ):
        airdrop_action_stager.get_candidate_for_request(staged["request_id"])


def test_incomplete_candidate_reconciles_on_next_cycle(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = durable()
    patch_ledger(monkeypatch, [row])
    candidate = airdrop_action_stager._validate_candidate(
        row,
        row["event"]["action_candidate"],
        T0,
    )
    stored = airdrop_action_stager._persist_candidate(candidate, T0)
    assert stored["request_id"] is None

    repaired = airdrop_action_stager.reconcile_incomplete(now=T0)

    assert len(repaired) == 1
    assert repaired[0]["request_id"]


def test_monitor_calls_stager_without_changing_alert_routing(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    monkeypatch.setattr(
        airdrop_monitor.airdrop_action_stager,
        "stage_new_events",
        lambda event_ids, records_by_id, now=None: (
            calls.append(list(event_ids))
            or {
                "outcome": "ok",
                "staged": [],
                "repaired": [],
                "skipped_without_candidate": len(event_ids),
            }
        ),
    )
    monkeypatch.setattr(
        airdrop_monitor.airdrop_ledger,
        "record_scan",
        lambda snapshot, now=None: {
            "baseline": False,
            "snapshot_id": "s1",
            "health": "ok",
            "new_events": [],
            "ledger": {"count": 0, "integrity_valid": True},
        },
    )
    monkeypatch.setattr(
        airdrop_monitor.airdrop_ledger,
        "verify_ledger",
        lambda: {"valid": True, "count": 0, "tip_hash": "", "records": []},
    )

    result = airdrop_monitor.run_once(
        scanner=lambda: {"snapshot_id": "s1", "health": "ok"},
        now=T0,
    )

    assert result["outcome"] == "recorded"
    assert result["staging_outcome"] == "ok"
    assert result["staged_approvals"] == 0
    assert calls == [[]]


def test_monitor_staging_failure_is_visible_but_radar_recording_survives(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        airdrop_monitor.airdrop_action_stager,
        "stage_new_events",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            airdrop_action_stager.StagingBridgeError("blocked")
        ),
    )
    monkeypatch.setattr(
        airdrop_monitor.airdrop_ledger,
        "record_scan",
        lambda snapshot, now=None: {
            "baseline": False,
            "snapshot_id": "s1",
            "health": "ok",
            "new_events": [],
            "ledger": {"count": 0, "integrity_valid": True},
        },
    )
    monkeypatch.setattr(
        airdrop_monitor.airdrop_ledger,
        "verify_ledger",
        lambda: {"valid": True, "count": 0, "tip_hash": "", "records": []},
    )

    result = airdrop_monitor.run_once(
        scanner=lambda: {"snapshot_id": "s1", "health": "ok"},
        now=T0,
    )

    assert result["outcome"] == "recorded"
    assert result["staging_outcome"] == "failed"
    status = airdrop_monitor.monitor_status(now=T0)
    assert status["staging_outcome"] == "failed"
    assert status["staging_error_type"] == "StagingBridgeError"


def test_staging_failure_is_a_discord_health_problem() -> None:
    status = {
        "outcome": "recorded",
        "heartbeat_stale": False,
        "last_attempt_at": T0.isoformat(),
        "last_completed_at": T0.isoformat(),
        "radar_health": "ok",
        "staging_outcome": "failed",
        "staging_error_type": "StagingBridgeError",
    }
    assert airdrop_notifier._health_class(status) == "problem"
    rendered = airdrop_notifier._render_health_problem(status)
    assert "action_staging_failed:StagingBridgeError" in rendered


def test_stager_has_no_network_signer_or_execution_capability() -> None:
    source = (
        core.ROOT / "src" / "flop_agent" / "airdrop_action_stager.py"
    ).read_text("utf-8")
    lowered = source.lower()
    assert "httpx" not in lowered
    assert "oracle_signer" not in lowered
    assert "discord_bot_token" not in lowered
    assert "client.post" not in lowered
