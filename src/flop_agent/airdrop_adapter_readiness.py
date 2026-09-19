"""Read-only FLOP adapter implementation-readiness gate.

This module never performs network access, stages approvals, registers adapters,
or executes actions. It converts already-recorded official evidence into a
stable READY/BLOCKED matrix for future adapter implementation work.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from . import airdrop_action_stager, airdrop_ledger

SCHEMA_VERSION = 1
READY = "IMPLEMENTATION_READY"
BLOCKED = "BLOCKED"
OPEN_VALUES = frozenset({"open", "live", "enabled"})
ACTION_STATUS_KEYS = {
    "faucet": "faucet_status",
    "registration": "registration_status",
    "claim": "claim_status",
}


class AdapterReadinessError(RuntimeError):
    """Stable fail-closed readiness error."""


def _fact(snapshot: dict, key: str) -> dict | None:
    row = snapshot.get("resolved_facts", {}).get(key)
    return row if isinstance(row, dict) else None


def _fact_open(snapshot: dict, key: str) -> tuple[bool, str | None]:
    row = _fact(snapshot, key)
    if row is None:
        return False, f"missing_fact:{key}"
    if row.get("conflict"):
        return False, f"conflicting_fact:{key}"
    value = str(row.get("value") or "").strip().lower()
    if value not in OPEN_VALUES:
        return False, f"not_open:{key}:{value or 'missing'}"
    return True, None


def _claim_normative_blockers(snapshot: dict) -> list[str]:
    blockers: list[str] = []

    path = _fact(snapshot, "claim_path_status")
    if path is None:
        blockers.append("missing_fact:claim_path_status")
    else:
        value = str(path.get("value") or "").strip().lower()
        status = str(path.get("status") or "").strip().lower()
        if path.get("conflict"):
            blockers.append("conflicting_fact:claim_path_status")
        elif value in {"", "open", "unspecified", "tbd", "unknown"} or status in {
            "tbd",
            "open",
            "unconfirmed",
        }:
            blockers.append("claim_path_unresolved")

    e38 = _fact(snapshot, "e38_status")
    if e38 is None:
        blockers.append("missing_fact:e38_status")
    else:
        value = str(e38.get("value") or "").strip().lower()
        status = str(e38.get("status") or "").strip().lower()
        if e38.get("conflict"):
            blockers.append("conflicting_fact:e38_status")
        elif value in {"", "open", "tbd", "unknown"} or status in {
            "tbd",
            "open",
            "unconfirmed",
        }:
            blockers.append("e38_unresolved")

    return blockers


def _candidate_for_action(
    action_class: str,
    *,
    records: list[dict],
    current: datetime,
) -> tuple[dict | None, list[str]]:
    key = ACTION_STATUS_KEYS[action_class]
    matching: list[dict] = []
    for durable in records:
        if not isinstance(durable, dict):
            continue
        event = durable.get("event")
        if not isinstance(event, dict) or event.get("key") != key:
            continue
        after = event.get("after")
        value = after.get("value") if isinstance(after, dict) else after
        if str(value).strip().lower() not in OPEN_VALUES:
            continue
        matching.append(durable)

    if not matching:
        return None, ["canonical_open_event_missing"]

    # Prefer the latest canonical occurrence. Ledger sequence is validated by
    # verify_ledger(), so max(sequence) is stable and deterministic.
    durable = max(matching, key=lambda row: int(row.get("sequence", 0) or 0))
    event = durable.get("event") or {}
    raw = event.get("action_candidate")
    if raw is None:
        return None, ["action_candidate_missing"]

    try:
        candidate = airdrop_action_stager._validate_candidate(
            durable,
            raw,
            current,
        )
    except airdrop_action_stager.StagingBridgeError as error:
        return None, [f"action_candidate_invalid:{error}"]

    if candidate.get("action_class") != action_class:
        return None, ["action_candidate_class_mismatch"]

    return candidate, []


def evaluate(
    *,
    snapshot: dict | None = None,
    verified_ledger: dict | None = None,
    now: datetime | None = None,
) -> dict:
    """Evaluate adapter implementation readiness from local evidence only."""
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise AdapterReadinessError("airdrop_readiness_timestamp_timezone_required")
    current = current.astimezone(UTC)

    if snapshot is None:
        try:
            snapshot = airdrop_ledger.current_snapshot()
        except Exception as error:
            return {
                "schema_version": SCHEMA_VERSION,
                "generated_at": current.isoformat(),
                "snapshot_id": None,
                "ledger_valid": False,
                "overall": BLOCKED,
                "actions": {
                    action: {
                        "state": BLOCKED,
                        "blockers": ["current_snapshot_unavailable"],
                        "candidate": None,
                    }
                    for action in ACTION_STATUS_KEYS
                },
                "warnings": [
                    "Readiness never authorizes external action.",
                    f"snapshot_error:{error.__class__.__name__}",
                ],
            }

    if not isinstance(snapshot, dict):
        raise AdapterReadinessError("airdrop_readiness_snapshot_invalid")

    try:
        verified = verified_ledger or airdrop_ledger.verify_ledger()
    except Exception as error:
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at": current.isoformat(),
            "snapshot_id": snapshot.get("snapshot_id"),
            "ledger_valid": False,
            "overall": BLOCKED,
            "actions": {
                action: {
                    "state": BLOCKED,
                    "blockers": ["ledger_unavailable_or_invalid"],
                    "candidate": None,
                }
                for action in ACTION_STATUS_KEYS
            },
            "warnings": [
                "Readiness never authorizes external action.",
                f"ledger_error:{error.__class__.__name__}",
            ],
        }

    if not isinstance(verified, dict) or verified.get("valid") is not True:
        raise AdapterReadinessError("airdrop_readiness_ledger_invalid")
    records = verified.get("records")
    if not isinstance(records, list):
        raise AdapterReadinessError("airdrop_readiness_ledger_records_invalid")

    actions: dict[str, dict] = {}
    testnet_ok, testnet_blocker = _fact_open(snapshot, "testnet_status")

    for action_class, status_key in ACTION_STATUS_KEYS.items():
        blockers: list[str] = []
        if not testnet_ok and testnet_blocker:
            blockers.append(testnet_blocker)

        action_ok, action_blocker = _fact_open(snapshot, status_key)
        if not action_ok and action_blocker:
            blockers.append(action_blocker)

        if action_class == "claim":
            blockers.extend(_claim_normative_blockers(snapshot))

        candidate, candidate_blockers = _candidate_for_action(
            action_class,
            records=records,
            current=current,
        )
        blockers.extend(candidate_blockers)

        # Stable order / no duplicate codes.
        blockers = list(dict.fromkeys(blockers))
        state = READY if not blockers else BLOCKED
        actions[action_class] = {
            "state": state,
            "blockers": blockers,
            "status_fact_key": status_key,
            "candidate": (
                {
                    "source_event_id": candidate.get("source_event_id"),
                    "source_ledger_hash": candidate.get("source_ledger_hash"),
                    "payload_sha256": candidate.get("payload_sha256"),
                    "expires_at": candidate.get("expires_at"),
                }
                if candidate is not None
                else None
            ),
        }

    overall = (
        READY
        if all(row["state"] == READY for row in actions.values())
        else BLOCKED
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": current.isoformat(),
        "snapshot_id": snapshot.get("snapshot_id"),
        "ledger_valid": True,
        "ledger_count": verified.get("count"),
        "overall": overall,
        "actions": actions,
        "warnings": [
            "IMPLEMENTATION_READY is not execution approval.",
            "This gate does not register an adapter, stage an approval, sign, post, spend, claim, register, or submit.",
        ],
    }


def concise(report: dict) -> dict:
    """Return a compact operator-friendly readiness summary."""
    actions = report.get("actions", {})
    return {
        "overall": report.get("overall"),
        "snapshot_id": report.get("snapshot_id"),
        "ledger_valid": report.get("ledger_valid"),
        "actions": {
            action: {
                "state": row.get("state"),
                "blockers": list(row.get("blockers", [])),
            }
            for action, row in actions.items()
            if isinstance(row, dict)
        },
    }


def render_json(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2)
