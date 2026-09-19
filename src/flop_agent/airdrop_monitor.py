"""Scheduled, read-only FLOP airdrop monitor and local alert router.

The monitor orchestrates the already read-only Radar and local Evidence Ledger.
It never signs, registers, claims, spends, submits, posts, or sends network
notifications. Alerts are written to a local outbox for a separately audited
transport to deliver later.
"""
from __future__ import annotations

import fcntl
import json
import os
import tempfile
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

from . import airdrop_action_stager, airdrop_adapter_readiness, airdrop_ledger, airdrop_radar

SCHEMA_VERSION = 1
CONFIG_NAME = "monitor-config.json"
HEARTBEAT_NAME = "monitor-heartbeat.json"
ALERTS_NAME = "alert-outbox.json"
ALERT_LOCK_NAME = "alert-outbox.lock"

ABSOLUTE_MINIMUM_SCAN_SECONDS = 300
DEFAULT_INTERVAL_SECONDS = 900
DEFAULT_CONFIG = {
    "schema_version": SCHEMA_VERSION,
    "interval_seconds": DEFAULT_INTERVAL_SECONDS,
    "minimum_scan_interval_seconds": ABSOLUTE_MINIMUM_SCAN_SECONDS,
    "heartbeat_stale_after_seconds": 1800,
    "max_daily_summary_events": 100,
    "max_alerts": 1000,
}


def monitor_dir() -> Path:
    return airdrop_ledger.ledger_dir()


def _path(name: str) -> Path:
    return monitor_dir() / name


def _utc(value: datetime | None = None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("airdrop_monitor_timestamp_timezone_required")
    return current.astimezone(UTC).isoformat()


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("airdrop_monitor_timestamp_timezone_required")
    return parsed.astimezone(UTC)


def _atomic_json_write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
        newline="\n",
    )
    try:
        with handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    finally:
        if os.path.exists(handle.name):
            os.unlink(handle.name)


def _read_json(path: Path, *, default: dict) -> dict:
    if not path.exists():
        return default
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"airdrop_monitor_state_corrupt:{path.name}") from error
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError(f"airdrop_monitor_schema_mismatch:{path.name}")
    return value


def _validate_config(config: dict) -> dict:
    merged = {**DEFAULT_CONFIG, **config}
    for key in (
        "interval_seconds",
        "minimum_scan_interval_seconds",
        "heartbeat_stale_after_seconds",
        "max_daily_summary_events",
        "max_alerts",
    ):
        if not isinstance(merged.get(key), int):
            raise RuntimeError(f"airdrop_monitor_config_invalid:{key}")
    if merged["minimum_scan_interval_seconds"] < ABSOLUTE_MINIMUM_SCAN_SECONDS:
        raise RuntimeError("airdrop_monitor_minimum_interval_too_fast")
    if merged["interval_seconds"] < merged["minimum_scan_interval_seconds"]:
        raise RuntimeError("airdrop_monitor_interval_below_floor")
    if merged["heartbeat_stale_after_seconds"] < merged["interval_seconds"]:
        raise RuntimeError("airdrop_monitor_stale_threshold_too_short")
    if not 1 <= merged["max_daily_summary_events"] <= 1000:
        raise RuntimeError("airdrop_monitor_daily_summary_limit_invalid")
    if not 10 <= merged["max_alerts"] <= 10000:
        raise RuntimeError("airdrop_monitor_alert_limit_invalid")
    return merged


def load_config() -> dict:
    path = _path(CONFIG_NAME)
    if not path.exists():
        monitor_dir().mkdir(parents=True, exist_ok=True)
        _atomic_json_write(path, DEFAULT_CONFIG)
        return dict(DEFAULT_CONFIG)
    return _validate_config(_read_json(path, default=dict(DEFAULT_CONFIG)))


@contextmanager
def _alert_lock():
    monitor_dir().mkdir(parents=True, exist_ok=True)
    path = _path(ALERT_LOCK_NAME)
    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _empty_alerts() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "updated_at": None,
        "events": {},
    }


def _load_alerts() -> dict:
    value = _read_json(_path(ALERTS_NAME), default=_empty_alerts())
    if not isinstance(value.get("events"), dict):
        raise RuntimeError("airdrop_monitor_alert_state_invalid")
    return value


def _heartbeat_default() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "last_attempt_at": None,
        "last_completed_at": None,
        "outcome": "never_run",
        "radar_health": None,
        "snapshot_id": None,
        "new_events": 0,
        "immediate_alerts": 0,
        "digest_alerts": 0,
        "staging_outcome": None,
        "staged_approvals": 0,
        "staging_error_type": None,
        "error_type": None,
    }


def _load_heartbeat() -> dict:
    return _read_json(_path(HEARTBEAT_NAME), default=_heartbeat_default())


def _write_heartbeat(**updates: object) -> dict:
    value = {**_heartbeat_default(), **_load_heartbeat(), **updates}
    value["schema_version"] = SCHEMA_VERSION
    _atomic_json_write(_path(HEARTBEAT_NAME), value)
    return value


def _source_context(evidence: list[dict]) -> dict:
    rows = [
        row
        for row in evidence
        if isinstance(row, dict)
        and row.get("observation") in {"current", "last_success", "previous"}
    ]
    rows.sort(
        key=lambda row: (
            {"current": 0, "last_success": 1, "previous": 2}.get(
                str(row.get("observation")), 9
            ),
            int(row.get("tier") or 999),
            str(row.get("name") or ""),
        )
    )
    row = rows[0] if rows else {}
    return {
        "source": row.get("name"),
        "source_url": row.get("final_url") or row.get("url"),
        "authority": row.get("authority"),
        "tier": row.get("tier"),
        "source_version": row.get("version"),
    }


def safe_next_step(event: dict) -> str:
    event_type = str(event.get("type") or "")
    key = str(event.get("key") or "")

    if event_type == "SOURCE_UNAVAILABLE":
        return "Wait for the official source to recover; do not treat the outage as a rule change."
    if event_type in {
        "OFFICIAL_LINK_DISCOVERED",
        "RECOVERED_OFFICIAL_LINK_DISCOVERED",
    }:
        return "Review the official link and its terms; link discovery alone does not mean the action is open."
    if event_type in {"NEW_DEADLINE", "RECOVERED_SOURCE_NEW_DEADLINE"}:
        return "Verify the exact official deadline, eligibility, and submission path now; any binding action still needs separate approval."
    if key in {
        "testnet_status",
        "faucet_status",
        "registration_status",
        "claim_status",
    }:
        return "Verify the official procedure and eligibility first; registration, faucet, claim, spend, and signing remain separate approved actions."
    if key.startswith("kol_"):
        return "Review the official KOL terms and avoid duplicate applications unless FLOP explicitly requests a new submission."
    if key.startswith("source:") and key.endswith(":version"):
        return "Review the new official source version for rules not covered by current extractors before taking action."
    if key.startswith("github_"):
        return "Review the official engineering change as an early signal; it does not override the live FLOP-hosted specification."
    return "Review the official evidence and before→after change; do not take binding or value-bearing action without the required approval."


def _deadline_sensitive(event: dict) -> bool:
    gate = event.get("deadline_gate")
    if not isinstance(gate, dict):
        return False
    seconds = gate.get("seconds_remaining")
    return isinstance(seconds, int) and 0 <= seconds <= 86400


def _route(event: dict) -> str:
    severity = event.get("severity")
    if severity in {"ACTION_NOW", "HIGH"}:
        return "immediate"
    if severity == "MEDIUM":
        return "immediate" if _deadline_sensitive(event) else "digest"
    return "ledger_only"


def _build_alert(event_record: dict) -> dict:
    event = event_record.get("event")
    if not isinstance(event, dict):
        raise RuntimeError("airdrop_monitor_event_missing")
    context = _source_context(event_record.get("source_evidence", []))
    return {
        "event_id": event.get("event_id"),
        "severity": event.get("severity"),
        "type": event.get("type"),
        "key": event.get("key"),
        "route": _route(event),
        "source": context["source"],
        "source_url": context["source_url"],
        "authority": context["authority"],
        "tier": context["tier"],
        "source_version": context["source_version"],
        "before": event.get("before"),
        "after": event.get("after"),
        "deadline": event.get("deadline"),
        "deadline_gate": event.get("deadline_gate"),
        "safe_next_step": safe_next_step(event),
    }


def _enforce_alert_capacity(alerts: dict, limit: int) -> None:
    events = alerts["events"]
    if len(events) <= limit:
        return

    delivered = sorted(
        (
            (event_id, item)
            for event_id, item in events.items()
            if isinstance(item, dict) and item.get("delivery_state") == "delivered"
        ),
        key=lambda pair: (
            str(pair[1].get("delivered_at") or pair[1].get("last_seen") or ""),
            str(pair[0]),
        ),
    )
    for event_id, _item in delivered:
        if len(events) <= limit:
            break
        events.pop(event_id, None)

    # Pending alerts are evidence-backed operator work. Never silently evict one.
    if len(events) > limit:
        raise RuntimeError("airdrop_monitor_alert_capacity_exceeded")


def _queue_alerts(
    new_event_ids: list[str],
    records_by_id: dict[str, dict],
    *,
    observed_at: str,
    config: dict,
) -> tuple[list[dict], list[dict]]:
    by_id = records_by_id
    immediate: list[dict] = []
    digest: list[dict] = []

    with _alert_lock():
        state = _load_alerts()
        for event_id in new_event_ids:
            durable = by_id.get(event_id)
            if not durable:
                raise RuntimeError("airdrop_monitor_event_missing_from_evidence_bundle")
            payload = _build_alert(durable)
            route = payload["route"]
            if route == "ledger_only":
                continue

            known = state["events"].get(event_id)
            if isinstance(known, dict):
                known["last_seen"] = observed_at
                continue

            item = {
                "event_id": event_id,
                "first_queued_at": observed_at,
                "last_seen": observed_at,
                "route": route,
                "delivery_state": "pending",
                "payload": payload,
            }
            state["events"][event_id] = item
            if route == "immediate":
                immediate.append(payload)
            else:
                digest.append(payload)

        state["updated_at"] = observed_at
        _enforce_alert_capacity(state, config["max_alerts"])
        _atomic_json_write(_path(ALERTS_NAME), state)
    return immediate, digest


def _scan_floor(heartbeat: dict, config: dict, current: datetime) -> dict | None:
    previous = heartbeat.get("last_attempt_at")
    if not isinstance(previous, str):
        return None
    last = _parse_utc(previous)
    elapsed = int((current - last).total_seconds())
    if elapsed < 0:
        raise RuntimeError("airdrop_monitor_clock_moved_backwards")
    floor = config["minimum_scan_interval_seconds"]
    if elapsed >= floor:
        return None
    remaining = floor - elapsed
    return {
        "outcome": "skipped_too_soon",
        "seconds_until_eligible": remaining,
        "next_eligible_at": datetime.fromtimestamp(
            current.timestamp() + remaining,
            tz=UTC,
        ).isoformat(),
    }


def run_once(
    *,
    scanner: Callable[[], dict] | None = None,
    now: datetime | None = None,
) -> dict:
    """Run one scheduled monitor cycle without any external write action."""
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("airdrop_monitor_timestamp_timezone_required")
    current = current.astimezone(UTC)
    observed_at = current.isoformat()
    config = load_config()
    heartbeat = _load_heartbeat()
    floor = _scan_floor(heartbeat, config, current)
    if floor:
        return {**floor, "recorded": False}

    _write_heartbeat(
        last_attempt_at=observed_at,
        outcome="running",
        error_type=None,
    )

    scan = scanner or airdrop_radar.scan_official_sources
    try:
        snapshot = scan()
    except Exception as error:
        # A transient read-side failure must not kill the scheduler. No rule
        # change is fabricated and no Ledger state is mutated.
        _write_heartbeat(
            last_attempt_at=observed_at,
            last_completed_at=observed_at,
            outcome="scan_failed",
            error_type=error.__class__.__name__,
            new_events=0,
            immediate_alerts=0,
            digest_alerts=0,
        )
        return {
            "outcome": "scan_failed",
            "recorded": False,
            "error_type": error.__class__.__name__,
        }

    try:
        recorded = airdrop_ledger.record_scan(snapshot, now=current)
    except airdrop_ledger.LedgerIntegrityError as error:
        _write_heartbeat(
            last_attempt_at=observed_at,
            last_completed_at=observed_at,
            outcome="blocked_integrity",
            radar_health=snapshot.get("health"),
            snapshot_id=snapshot.get("snapshot_id"),
            error_type=error.__class__.__name__,
            new_events=0,
            immediate_alerts=0,
            digest_alerts=0,
        )
        raise

    new_event_ids = [
        row["event_id"]
        for row in recorded.get("new_events", [])
        if isinstance(row, dict) and isinstance(row.get("event_id"), str)
    ]
    try:
        verified = airdrop_ledger.verify_ledger()
        records_by_id = {
            str(row["event_id"]): row
            for row in verified.get("records", [])
            if isinstance(row, dict) and isinstance(row.get("event_id"), str)
        }
        immediate, digest = _queue_alerts(
            new_event_ids,
            records_by_id,
            observed_at=observed_at,
            config=config,
        )
    except airdrop_ledger.LedgerIntegrityError as error:
        _write_heartbeat(
            last_attempt_at=observed_at,
            last_completed_at=observed_at,
            outcome="blocked_integrity",
            radar_health=recorded.get("health"),
            snapshot_id=recorded.get("snapshot_id"),
            error_type=error.__class__.__name__,
            new_events=len(new_event_ids),
            immediate_alerts=0,
            digest_alerts=0,
        )
        raise
    except Exception as error:
        _write_heartbeat(
            last_attempt_at=observed_at,
            last_completed_at=observed_at,
            outcome="alert_routing_failed",
            radar_health=recorded.get("health"),
            snapshot_id=recorded.get("snapshot_id"),
            error_type=error.__class__.__name__,
            new_events=len(new_event_ids),
            immediate_alerts=0,
            digest_alerts=0,
        )
        raise
    staging_outcome = "ok"
    staging_error_type = None
    staged_approvals = 0
    repaired_approvals = 0
    try:
        staging = airdrop_action_stager.stage_new_events(
            new_event_ids,
            records_by_id,
            now=current,
        )
        staged_approvals = len(staging.get("staged", []))
        repaired_approvals = len(staging.get("repaired", []))
    except Exception as error:
        # Approval staging is fail-closed but isolated from Radar evidence and
        # ordinary alert delivery. Operator health reporting exposes the error.
        staging_outcome = "failed"
        staging_error_type = error.__class__.__name__

    _write_heartbeat(
        last_attempt_at=observed_at,
        last_completed_at=observed_at,
        outcome="recorded",
        radar_health=recorded.get("health"),
        snapshot_id=recorded.get("snapshot_id"),
        error_type=None,
        new_events=len(new_event_ids),
        immediate_alerts=len(immediate),
        digest_alerts=len(digest),
        staging_outcome=staging_outcome,
        staged_approvals=staged_approvals,
        staging_error_type=staging_error_type,
    )
    return {
        "outcome": "recorded",
        "recorded": True,
        "baseline": recorded.get("baseline"),
        "snapshot_id": recorded.get("snapshot_id"),
        "radar_health": recorded.get("health"),
        "new_events": recorded.get("new_events", []),
        "immediate_alerts": immediate,
        "digest_alerts": digest,
        "staging_outcome": staging_outcome,
        "staging_error_type": staging_error_type,
        "staged_approvals": staged_approvals,
        "repaired_approvals": repaired_approvals,
        "ledger": recorded.get("ledger"),
    }


def _adapter_readiness_status(*, now: datetime | None = None) -> dict:
    try:
        return airdrop_adapter_readiness.concise(
            airdrop_adapter_readiness.evaluate(now=now)
        )
    except Exception as error:
        return {
            "overall": "BLOCKED",
            "snapshot_id": None,
            "ledger_valid": False,
            "actions": {},
            "error_type": error.__class__.__name__,
        }


def monitor_status(*, now: datetime | None = None) -> dict:
    config = load_config()
    heartbeat = _load_heartbeat()
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("airdrop_monitor_timestamp_timezone_required")
    current = current.astimezone(UTC)

    completed = heartbeat.get("last_completed_at")
    age = None
    stale = True
    if isinstance(completed, str):
        age = max(0, int((current - _parse_utc(completed)).total_seconds()))
        stale = age > config["heartbeat_stale_after_seconds"]

    with _alert_lock():
        alerts = _load_alerts()
        pending_immediate = 0
        pending_digest = 0
        for item in alerts.get("events", {}).values():
            if not isinstance(item, dict) or item.get("delivery_state") != "pending":
                continue
            if item.get("route") == "immediate":
                pending_immediate += 1
            elif item.get("route") == "digest":
                pending_digest += 1

    ledger_status = airdrop_ledger.status()
    return {
        "schema_version": SCHEMA_VERSION,
        "outcome": heartbeat.get("outcome"),
        "last_attempt_at": heartbeat.get("last_attempt_at"),
        "last_completed_at": completed,
        "heartbeat_age_seconds": age,
        "heartbeat_stale": stale,
        "radar_health": heartbeat.get("radar_health"),
        "snapshot_id": heartbeat.get("snapshot_id"),
        "pending_immediate_alerts": pending_immediate,
        "pending_digest_alerts": pending_digest,
        "staging_outcome": heartbeat.get("staging_outcome"),
        "staged_approvals": heartbeat.get("staged_approvals", 0),
        "staging_error_type": heartbeat.get("staging_error_type"),
        "ledger_integrity_valid": ledger_status["integrity_valid"],
        "ledger_count": ledger_status["ledger_count"],
        "scan_interval_seconds": config["interval_seconds"],
        "minimum_scan_interval_seconds": config["minimum_scan_interval_seconds"],
        "adapter_readiness": _adapter_readiness_status(now=current),
    }


def pending_alerts() -> dict:
    with _alert_lock():
        state = _load_alerts()
        rows = [
            dict(item)
            for item in state.get("events", {}).values()
            if isinstance(item, dict) and item.get("delivery_state") == "pending"
        ]
    rows.sort(
        key=lambda item: (
            0 if item.get("route") == "immediate" else 1,
            str(item.get("first_queued_at") or ""),
            str(item.get("event_id") or ""),
        )
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "alerts": rows,
    }


def mark_alerts_delivered(
    event_ids: list[str],
    *,
    transport: str,
    receipt: str,
    now: datetime | None = None,
) -> list[dict]:
    if (
        not isinstance(event_ids, list)
        or not event_ids
        or len(event_ids) > 100
        or not all(isinstance(event_id, str) and event_id for event_id in event_ids)
        or len(set(event_ids)) != len(event_ids)
    ):
        raise ValueError("airdrop_monitor_event_ids_invalid")
    if not isinstance(transport, str) or not 1 <= len(transport) <= 40:
        raise ValueError("airdrop_monitor_delivery_transport_invalid")
    if not isinstance(receipt, str) or not 1 <= len(receipt) <= 200:
        raise ValueError("airdrop_monitor_delivery_receipt_invalid")
    delivered_at = _utc(now)

    with _alert_lock():
        state = _load_alerts()
        selected: list[dict] = []
        for event_id in event_ids:
            item = state.get("events", {}).get(event_id)
            if not isinstance(item, dict):
                raise RuntimeError("airdrop_monitor_alert_not_found")
            if item.get("delivery_state") not in {"pending", "delivered"}:
                raise RuntimeError("airdrop_monitor_alert_delivery_state_invalid")
            selected.append(item)

        for item in selected:
            if item.get("delivery_state") == "delivered":
                continue
            item["delivery_state"] = "delivered"
            item["delivered_at"] = delivered_at
            item["delivery_transport"] = transport
            item["delivery_receipt"] = receipt

        state["updated_at"] = delivered_at
        _enforce_alert_capacity(state, load_config()["max_alerts"])
        _atomic_json_write(_path(ALERTS_NAME), state)
        return [dict(item) for item in selected]


def mark_alert_delivered(
    event_id: str,
    *,
    transport: str,
    receipt: str,
    now: datetime | None = None,
) -> dict:
    rows = mark_alerts_delivered(
        [event_id],
        transport=transport,
        receipt=receipt,
        now=now,
    )
    return rows[0]


def alert_delivery_status(event_id: str) -> dict:
    with _alert_lock():
        state = _load_alerts()
        item = state.get("events", {}).get(event_id)
        if not isinstance(item, dict):
            raise RuntimeError("airdrop_monitor_alert_not_found")
        return {
            "event_id": event_id,
            "delivery_state": item.get("delivery_state"),
            "delivered_at": item.get("delivered_at"),
            "delivery_transport": item.get("delivery_transport"),
            "delivery_receipt": item.get("delivery_receipt"),
        }


def daily_summary(*, now: datetime | None = None) -> dict:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("airdrop_monitor_timestamp_timezone_required")
    current = current.astimezone(UTC)
    config = load_config()
    bundle = airdrop_ledger.export_bundle(now=current)
    start = datetime(current.year, current.month, current.day, tzinfo=UTC)

    rows: list[dict] = []
    for item in bundle.get("recent_events", []):
        if not isinstance(item, dict) or not isinstance(item.get("last_seen"), str):
            continue
        if _parse_utc(item["last_seen"]) < start:
            continue
        event = item.get("event")
        if not isinstance(event, dict):
            continue
        rows.append(
            {
                "event_id": item.get("event_id"),
                "severity": item.get("severity"),
                "type": item.get("type"),
                "key": item.get("key"),
                "before": event.get("before"),
                "after": event.get("after"),
                "safe_next_step": safe_next_step(event),
            }
        )

    rows = rows[: config["max_daily_summary_events"]]
    counts = {
        severity: sum(1 for row in rows if row.get("severity") == severity)
        for severity in airdrop_radar.SEVERITY_ORDER
    }
    what_matters = [
        row
        for row in rows
        if row.get("severity") in {"ACTION_NOW", "HIGH"}
    ][:20]
    next_steps: list[str] = []
    for row in rows:
        step = row["safe_next_step"]
        if step not in next_steps:
            next_steps.append(step)

    current_facts = bundle.get("current", {}).get("facts", {})
    key_facts = {
        key: current_facts.get(key)
        for key in (
            "genesis_agent_airdrop",
            "agent_scoring_basis",
            "testnet_status",
            "testnet_window",
            "claim_status",
            "e38_status",
            "e40_status",
            "kol_application_status",
        )
        if key in current_facts
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "date_utc": current.date().isoformat(),
        "snapshot_id": bundle.get("current", {}).get("snapshot_id"),
        "counts": counts,
        "what_changed": rows,
        "what_matters": what_matters,
        "what_to_do": next_steps[:20],
        "key_facts": key_facts,
        "adapter_readiness": _adapter_readiness_status(now=current),
        "ledger_integrity_valid": bundle.get("integrity", {}).get("valid"),
    }


def run_forever(
    *,
    scanner: Callable[[], dict] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
    stop: Callable[[], bool] | None = None,
) -> None:
    """Foreground scheduler. Packaging/deployment is intentionally out of scope."""
    while True:
        if stop and stop():
            return
        run_once(scanner=scanner)
        interval = load_config()["interval_seconds"]
        sleeper(float(interval))
