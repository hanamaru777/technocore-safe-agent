"""Tamper-evident local evidence ledger for the FLOP Airdrop Radar.

This module has no network client and no external write path. It accepts a
structured Radar snapshot, persists only an explicit safe subset under
FLOP_STATE_DIR/airdrop-radar/, and maintains a hash-chained event ledger.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable

from . import airdrop_radar, core

SCHEMA_VERSION = 1
DIR_NAME = "airdrop-radar"
STATE_NAME = "state.json"
CURRENT_NAME = "current-snapshot.json"
LAST_SUCCESS_NAME = "last-success.json"
INDEX_NAME = "event-index.json"
LEDGER_NAME = "events.jsonl"
MAX_EVIDENCE_EXCERPT = 420
MAX_LEDGER_BYTES = 32 * 1024 * 1024
MAX_EXPORT_EVENTS = 100

ELIGIBILITY_KEYS = {
    "genesis_agent_airdrop",
    "genesis_supply",
    "genesis_reserve",
    "agent_scoring_basis",
    "agent_scoring_accounting_unit",
    "activity_minimums_status",
    "sublinear_conversion_status",
    "conversion_cap_status",
    "testnet_to_mainnet_conversion_status",
    "spend_to_unlock_status",
    "spend_to_unlock_ratio",
    "airdrop_vesting_duration_blocks",
    "agent_vesting_status",
    "claim_path_status",
    "claim_status",
    "eligibility_status",
    "testnet_window",
    "testnet_status",
    "faucet_status",
    "registration_status",
    "mainnet_window",
    "e38_status",
    "e40_status",
    "official_airdrop_x_handle",
    "kol_application_status",
    "kol_compensation_guaranteed",
    "kol_program_terms_status",
    "agent_identity_min_stake",
    "circuit_breaker_tx_count",
    "circuit_breaker_flop_cap",
    "agent_daily_cap_autonomous",
    "agent_per_tx_limit",
    "circuit_breaker_window",
    "max_active_reservations_base",
    "escrow_per_reservation_slot",
    "session_key_max_duration_blocks",
}


class LedgerIntegrityError(RuntimeError):
    """The durable evidence chain or state cannot be trusted."""


def ledger_dir() -> Path:
    return core.STATE / DIR_NAME


def _path(name: str) -> Path:
    return ledger_dir() / name


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _utc(value: datetime | None = None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("airdrop_ledger_timestamp_timezone_required")
    return current.astimezone(UTC).isoformat()


def _atomic_text_write(path: Path, text: str) -> None:
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
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    finally:
        if os.path.exists(handle.name):
            os.unlink(handle.name)


def _atomic_json_write(path: Path, value: dict) -> None:
    _atomic_text_write(path, json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")


def _read_json(path: Path, *, kind: str, default: dict | None = None) -> dict:
    if not path.exists():
        if default is None:
            raise LedgerIntegrityError(f"airdrop_ledger_missing_{kind}")
        return default
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LedgerIntegrityError(f"airdrop_ledger_corrupt_{kind}") from error
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise LedgerIntegrityError(f"airdrop_ledger_schema_mismatch_{kind}")
    return value


def _clean_excerpt(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return value[:MAX_EVIDENCE_EXCERPT]


def _sanitize_fact(row: object) -> dict | None:
    if not isinstance(row, dict) or not isinstance(row.get("key"), str):
        return None
    result = {
        key: row.get(key)
        for key in ("key", "value", "unit", "source", "tier", "authority", "status", "evidence_sha256")
        if key in row
    }
    excerpt = _clean_excerpt(row.get("evidence_excerpt"))
    if excerpt is not None:
        result["evidence_excerpt"] = excerpt
    return result


def _sanitize_deadline(row: object) -> dict | None:
    if not isinstance(row, dict):
        return None
    allowed = (
        "label",
        "timestamp",
        "date",
        "exact",
        "source",
        "tier",
        "evidence_sha256",
    )
    cleaned = {key: row.get(key) for key in allowed if key in row}
    return cleaned if cleaned.get("source") else None


def _sanitize_source(row: object) -> dict | None:
    if not isinstance(row, dict) or not isinstance(row.get("name"), str):
        return None
    result = {
        key: row.get(key)
        for key in (
            "name",
            "url",
            "final_url",
            "tier",
            "authority",
            "critical",
            "status",
            "attempts",
            "latency_ms",
            "content_sha256",
            "content_bytes",
            "error_type",
        )
        if key in row
    }
    meta = row.get("meta")
    if isinstance(meta, dict):
        result["meta"] = {
            key: meta.get(key)
            for key in ("version", "updated")
            if key in meta and isinstance(meta.get(key), (str, int, float, bool, type(None)))
        }
    links = row.get("interest_links")
    if isinstance(links, list):
        result["interest_links"] = [
            item[:1000] for item in links if isinstance(item, str)
        ][:200]
    facts = [_sanitize_fact(item) for item in row.get("facts", [])] if isinstance(row.get("facts"), list) else []
    result["facts"] = [item for item in facts if item is not None]
    deadlines = [_sanitize_deadline(item) for item in row.get("deadlines", [])] if isinstance(row.get("deadlines"), list) else []
    result["deadlines"] = [item for item in deadlines if item is not None]
    return result


def _sanitize_resolved_fact(row: object) -> dict | None:
    if not isinstance(row, dict):
        return None
    result = {
        key: row.get(key)
        for key in ("value", "unit", "source", "tier", "authority", "status", "conflict")
        if key in row
    }
    variants = row.get("variants")
    if isinstance(variants, list):
        cleaned = [_sanitize_fact(item) for item in variants]
        result["variants"] = [item for item in cleaned if item is not None]
    return result


def sanitize_snapshot(snapshot: dict) -> dict:
    """Persist only the Radar evidence model, never fetched bodies/headers/cookies."""
    normalized = airdrop_radar.normalize_previous_snapshot(snapshot)
    sources = [_sanitize_source(row) for row in normalized.get("sources", [])]
    resolved = {
        str(key): cleaned
        for key, row in normalized.get("resolved_facts", {}).items()
        if (cleaned := _sanitize_resolved_fact(row)) is not None
    }
    deadlines = [_sanitize_deadline(row) for row in normalized.get("deadlines", [])]
    result = {
        "schema_version": normalized["schema_version"],
        "read_only": True,
        "scanned_at": normalized.get("scanned_at"),
        "health": normalized.get("health"),
        "snapshot_id": normalized["snapshot_id"],
        "source_precedence": [
            str(item)[:500]
            for item in normalized.get("source_precedence", [])
            if isinstance(item, str)
        ],
        "sources": [row for row in sources if row is not None],
        "resolved_facts": resolved,
        "deadlines": [row for row in deadlines if row is not None],
        "summary": {
            "available_sources": normalized.get("summary", {}).get("available_sources"),
            "failed_sources": [
                str(item)[:120]
                for item in normalized.get("summary", {}).get("failed_sources", [])
                if isinstance(item, str)
            ],
            "conflicts": [
                str(item)[:200]
                for item in normalized.get("summary", {}).get("conflicts", [])
                if isinstance(item, str)
            ],
        },
    }
    return result


def _ledger_records() -> list[dict]:
    path = _path(LEDGER_NAME)
    if not path.exists():
        return []
    if path.stat().st_size > MAX_LEDGER_BYTES:
        raise LedgerIntegrityError("airdrop_ledger_size_limit")
    records: list[dict] = []
    try:
        for number, line in enumerate(path.read_text("utf-8").splitlines(), 1):
            if not line.strip():
                raise LedgerIntegrityError(f"airdrop_ledger_blank_line_{number}")
            row = json.loads(line)
            if not isinstance(row, dict):
                raise LedgerIntegrityError(f"airdrop_ledger_record_invalid_{number}")
            records.append(row)
    except json.JSONDecodeError as error:
        raise LedgerIntegrityError("airdrop_ledger_json_invalid") from error
    return records


def verify_ledger() -> dict:
    records = _ledger_records()
    previous = ""
    seen_sequences: set[int] = set()
    for expected_sequence, row in enumerate(records, 1):
        if row.get("schema_version") != SCHEMA_VERSION:
            raise LedgerIntegrityError("airdrop_ledger_record_schema_mismatch")
        sequence = row.get("sequence")
        if sequence != expected_sequence or sequence in seen_sequences:
            raise LedgerIntegrityError("airdrop_ledger_sequence_invalid")
        seen_sequences.add(sequence)
        if row.get("previous_hash") != previous:
            raise LedgerIntegrityError("airdrop_ledger_previous_hash_invalid")
        recorded_hash = row.get("hash")
        if not isinstance(recorded_hash, str) or len(recorded_hash) != 64:
            raise LedgerIntegrityError("airdrop_ledger_hash_invalid")
        event = row.get("event")
        if row.get("record_type") != "material_event" or not isinstance(event, dict):
            raise LedgerIntegrityError("airdrop_ledger_event_record_invalid")
        expected_event_id = hashlib.sha256(
            _canonical(
                {
                    "type": event.get("type"),
                    "key": event.get("key"),
                    "before": event.get("before"),
                    "after": event.get("after"),
                }
            ).encode("utf-8")
        ).hexdigest()[:24]
        if (
            row.get("event_id") != event.get("event_id")
            or row.get("event_id") != expected_event_id
        ):
            raise LedgerIntegrityError("airdrop_ledger_event_id_mismatch")
        for timestamp_key in ("first_seen", "last_seen", "observed_at"):
            raw_timestamp = row.get(timestamp_key)
            if not isinstance(raw_timestamp, str):
                raise LedgerIntegrityError("airdrop_ledger_timestamp_invalid")
            try:
                parsed = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
            except ValueError as error:
                raise LedgerIntegrityError("airdrop_ledger_timestamp_invalid") from error
            if parsed.tzinfo is None:
                raise LedgerIntegrityError("airdrop_ledger_timestamp_invalid")
        if not isinstance(row.get("source_evidence"), list):
            raise LedgerIntegrityError("airdrop_ledger_source_evidence_invalid")
        payload = {key: value for key, value in row.items() if key != "hash"}
        computed = _sha(payload)
        if computed != recorded_hash:
            raise LedgerIntegrityError("airdrop_ledger_hash_mismatch")
        previous = recorded_hash
    return {
        "valid": True,
        "count": len(records),
        "tip_hash": previous,
        "records": records,
    }


def _append_ledger_event(event: dict, observed_at: str, source_evidence: list[dict]) -> dict:
    verified = verify_ledger()
    records = verified["records"]
    record = {
        "schema_version": SCHEMA_VERSION,
        "sequence": len(records) + 1,
        "record_type": "material_event",
        "event_id": event["event_id"],
        "first_seen": observed_at,
        "last_seen": observed_at,
        "observed_at": observed_at,
        "previous_hash": verified["tip_hash"],
        "event": event,
        "source_evidence": source_evidence,
    }
    record["hash"] = _sha(record)
    line = json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
    existing = _path(LEDGER_NAME).read_text("utf-8") if _path(LEDGER_NAME).exists() else ""
    if len((existing + line).encode("utf-8")) > MAX_LEDGER_BYTES:
        raise LedgerIntegrityError("airdrop_ledger_size_limit")
    _atomic_text_write(_path(LEDGER_NAME), existing + line)
    return record


def _empty_index() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "ledger_count": 0,
        "ledger_tip_hash": "",
        "events": {},
    }


def _load_index() -> dict:
    return _read_json(_path(INDEX_NAME), kind="event_index", default=_empty_index())


def _reconcile_index(index: dict, verified: dict) -> tuple[dict, bool]:
    events = index.get("events")
    if not isinstance(events, dict):
        raise LedgerIntegrityError("airdrop_ledger_event_index_invalid")
    if (
        index.get("ledger_count") == verified["count"]
        and index.get("ledger_tip_hash") == verified["tip_hash"]
    ):
        return index, False

    old = events
    rebuilt = _empty_index()
    rebuilt["ledger_count"] = verified["count"]
    rebuilt["ledger_tip_hash"] = verified["tip_hash"]
    for row in verified["records"]:
        event = row.get("event", {})
        event_id = row.get("event_id")
        if not isinstance(event_id, str) or not isinstance(event, dict):
            raise LedgerIntegrityError("airdrop_ledger_event_record_invalid")
        prior = old.get(event_id, {}) if isinstance(old.get(event_id), dict) else {}
        rebuilt["events"][event_id] = {
            "event_id": event_id,
            "type": event.get("type"),
            "key": event.get("key"),
            "severity": event.get("severity"),
            "first_seen": row.get("first_seen"),
            "last_seen": prior.get("last_seen") or row.get("last_seen"),
            "observed_at": prior.get("observed_at") or row.get("observed_at"),
            "seen_count": max(1, int(prior.get("seen_count", 1) or 1)),
            "ledger_sequence": row.get("sequence"),
            "ledger_hash": row.get("hash"),
            "acknowledged_at": prior.get("acknowledged_at"),
        }
    return rebuilt, True


def _load_current() -> dict | None:
    path = _path(CURRENT_NAME)
    if not path.exists():
        return None
    wrapper = _read_json(path, kind="current_snapshot")
    snapshot = wrapper.get("snapshot")
    if not isinstance(snapshot, dict):
        raise LedgerIntegrityError("airdrop_ledger_current_snapshot_invalid")
    return airdrop_radar.normalize_previous_snapshot(snapshot)


def _empty_last_success() -> dict:
    return {"schema_version": SCHEMA_VERSION, "sources": {}}


def _load_last_success() -> dict:
    value = _read_json(
        _path(LAST_SUCCESS_NAME),
        kind="last_success",
        default=_empty_last_success(),
    )
    if not isinstance(value.get("sources"), dict):
        raise LedgerIntegrityError("airdrop_ledger_last_success_invalid")
    return value


def _empty_state() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "scan_count": 0,
        "current_snapshot_id": None,
        "last_recorded_at": None,
        "last_health": None,
    }


def _load_state() -> dict:
    return _read_json(_path(STATE_NAME), kind="state", default=_empty_state())


def _source_map(snapshot: dict | None) -> dict[str, dict]:
    if not snapshot:
        return {}
    return {
        str(row.get("name")): row
        for row in snapshot.get("sources", [])
        if isinstance(row, dict) and row.get("name")
    }


def _fact_map(source_row: dict) -> dict[str, dict]:
    return {
        str(row.get("key")): row
        for row in source_row.get("facts", [])
        if isinstance(row, dict) and row.get("key")
    }


def _event_sources(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        source = value.get("source")
        if isinstance(source, str):
            found.add(source)
        for item in value.values():
            found.update(_event_sources(item))
    elif isinstance(value, list):
        for item in value:
            found.update(_event_sources(item))
    return found


def _source_summary(row: dict, *, event_key: str | None = None) -> dict:
    summary = {
        key: row.get(key)
        for key in (
            "name",
            "url",
            "final_url",
            "tier",
            "authority",
            "critical",
            "status",
            "content_sha256",
        )
        if key in row
    }
    meta = row.get("meta")
    if isinstance(meta, dict):
        summary["version"] = meta.get("version")
        summary["updated"] = meta.get("updated")
    if event_key:
        facts = [
            fact
            for fact in row.get("facts", [])
            if isinstance(fact, dict) and fact.get("key") == event_key
        ]
        if facts:
            summary["facts"] = facts
    return summary


def _evidence_for_event(
    previous: dict | None,
    current: dict,
    event: dict,
    last_success: dict,
) -> list[dict]:
    names = _event_sources(event)
    key = event.get("key") if isinstance(event.get("key"), str) else None
    before = _source_map(previous)
    after = _source_map(current)
    cached = last_success.get("sources", {})
    if key and key.startswith("source:"):
        parts = key.split(":")
        if len(parts) >= 2:
            names.add(parts[1])
    evidence: list[dict] = []
    for name in sorted(names):
        for label, mapping in (
            ("previous", before),
            ("current", after),
            ("last_success", cached),
        ):
            row = mapping.get(name)
            if isinstance(row, dict):
                evidence.append(
                    {
                        "observation": label,
                        **_source_summary(row, event_key=key),
                    }
                )
    return evidence


def _recovered_source_events(
    previous: dict | None,
    current: dict,
    last_success: dict,
) -> list[dict]:
    if previous is None:
        return []
    before = _source_map(previous)
    after = _source_map(current)
    cached = last_success.get("sources", {})
    events: list[dict] = []

    for name, current_row in after.items():
        previous_row = before.get(name)
        cached_row = cached.get(name)
        if (
            not isinstance(previous_row, dict)
            or previous_row.get("status") == "ok"
            or current_row.get("status") != "ok"
            or not isinstance(cached_row, dict)
            or cached_row.get("status") != "ok"
        ):
            continue

        source_events_before = len(events)
        old_facts = _fact_map(cached_row)
        new_facts = _fact_map(current_row)
        for key in sorted(set(old_facts) | set(new_facts)):
            old = old_facts.get(key)
            new = new_facts.get(key)
            if old is None:
                event_type = "RECOVERED_SOURCE_FACT_NEW"
            elif new is None:
                event_type = "RECOVERED_SOURCE_FACT_REMOVED"
            elif _canonical(
                {
                    "value": old.get("value"),
                    "unit": old.get("unit"),
                    "status": old.get("status"),
                }
            ) != _canonical(
                {
                    "value": new.get("value"),
                    "unit": new.get("unit"),
                    "status": new.get("status"),
                }
            ):
                event_type = "RECOVERED_SOURCE_FACT_CHANGED"
            else:
                continue
            events.append(
                airdrop_radar._event(
                    event_type=event_type,
                    key=key,
                    before=old,
                    after=new,
                    severity=airdrop_radar._severity(
                        key,
                        new,
                        "CHANGED",
                    ),
                    extra={"recovered_source": name},
                )
            )

        old_version = cached_row.get("meta", {}).get("version")
        new_version = current_row.get("meta", {}).get("version")
        if old_version and new_version and old_version != new_version:
            events.append(
                airdrop_radar._event(
                    event_type="RECOVERED_SOURCE_VERSION_CHANGED",
                    key=f"source:{name}:version",
                    before=old_version,
                    after=new_version,
                    severity="HIGH" if name == "yellowpaper" else "MEDIUM",
                    extra={"recovered_source": name},
                )
            )

        old_target = cached_row.get("final_url")
        new_target = current_row.get("final_url")
        if old_target and new_target and old_target != new_target:
            events.append(
                airdrop_radar._event(
                    event_type="RECOVERED_SOURCE_TARGET_CHANGED",
                    key=f"source:{name}:target",
                    before=old_target,
                    after=new_target,
                    severity="HIGH" if name == "kol_application" else "MEDIUM",
                    extra={"recovered_source": name},
                )
            )

        old_links = set(cached_row.get("interest_links", []))
        new_links = set(current_row.get("interest_links", []))
        for url in sorted(new_links - old_links):
            events.append(
                airdrop_radar._event(
                    event_type="RECOVERED_OFFICIAL_LINK_DISCOVERED",
                    key=f"official_link:{url}",
                    before=None,
                    after={"url": url, "source": name},
                    severity="HIGH",
                    extra={"recovered_source": name},
                )
            )
        for url in sorted(old_links - new_links):
            events.append(
                airdrop_radar._event(
                    event_type="RECOVERED_OFFICIAL_LINK_REMOVED",
                    key=f"official_link:{url}",
                    before={"url": url, "source": name},
                    after=None,
                    severity="MEDIUM",
                    extra={"recovered_source": name},
                )
            )

        old_deadlines = {
            airdrop_radar._deadline_identity(row): row
            for row in cached_row.get("deadlines", [])
            if isinstance(row, dict)
        }
        new_deadlines = {
            airdrop_radar._deadline_identity(row): row
            for row in current_row.get("deadlines", [])
            if isinstance(row, dict)
        }
        for deadline_id, row in new_deadlines.items():
            if deadline_id in old_deadlines:
                continue
            severity = "HIGH"
            extra = {"recovered_source": name, "deadline": row}
            if row.get("exact") and isinstance(row.get("timestamp"), str):
                gate = airdrop_radar.deadline_gate(row["timestamp"])
                extra["deadline_gate"] = gate
                if 0 <= gate["seconds_remaining"] <= 86400:
                    severity = "ACTION_NOW"
            events.append(
                airdrop_radar._event(
                    event_type="RECOVERED_SOURCE_NEW_DEADLINE",
                    key=f"deadline:{row.get('label', 'unknown')}",
                    before=None,
                    after=row,
                    severity=severity,
                    extra=extra,
                )
            )

        if (
            cached_row.get("content_sha256")
            and current_row.get("content_sha256")
            and cached_row.get("content_sha256") != current_row.get("content_sha256")
            and len(events) == source_events_before
        ):
            events.append(
                airdrop_radar._event(
                    event_type="RECOVERED_SOURCE_CONTENT_CHANGED",
                    key=f"source:{name}",
                    before=cached_row.get("content_sha256"),
                    after=current_row.get("content_sha256"),
                    severity="HIGH" if current_row.get("critical") else "INFO",
                    extra={"recovered_source": name},
                )
            )
    return events


def _dedupe_events(events: Iterable[dict]) -> list[dict]:
    rows: dict[str, dict] = {}
    for event in events:
        event_id = event.get("event_id")
        if not isinstance(event_id, str):
            raise LedgerIntegrityError("airdrop_ledger_event_id_invalid")
        rows[event_id] = event
    return sorted(
        rows.values(),
        key=lambda row: (
            airdrop_radar.SEVERITY_ORDER.get(str(row.get("severity")), 99),
            str(row.get("key")),
            str(row.get("event_id")),
        ),
    )


def record_scan(snapshot: dict, *, now: datetime | None = None) -> dict:
    """Record one Radar snapshot and its material changes using local files only."""
    current = sanitize_snapshot(snapshot)
    observed_at = _utc(now)
    ledger_dir().mkdir(parents=True, exist_ok=True)

    verified = verify_ledger()
    state = _load_state()
    index, index_recovered = _reconcile_index(_load_index(), verified)
    previous = _load_current()
    last_success = _load_last_success()

    normal_diff = airdrop_radar.compare_snapshots(previous, current, now=now)
    recovery = _recovered_source_events(previous, current, last_success)
    events = _dedupe_events([*normal_diff.get("events", []), *recovery])

    new_events: list[dict] = []
    repeated_events: list[str] = []
    for event in events:
        event_id = event["event_id"]
        existing = index["events"].get(event_id)
        if isinstance(existing, dict):
            existing["last_seen"] = observed_at
            existing["observed_at"] = observed_at
            existing["seen_count"] = int(existing.get("seen_count", 1) or 1) + 1
            repeated_events.append(event_id)
            continue

        evidence = _evidence_for_event(previous, current, event, last_success)
        record = _append_ledger_event(event, observed_at, evidence)
        index["events"][event_id] = {
            "event_id": event_id,
            "type": event.get("type"),
            "key": event.get("key"),
            "severity": event.get("severity"),
            "first_seen": observed_at,
            "last_seen": observed_at,
            "observed_at": observed_at,
            "seen_count": 1,
            "ledger_sequence": record["sequence"],
            "ledger_hash": record["hash"],
            "acknowledged_at": None,
        }
        new_events.append(event)

    verified_after = verify_ledger()
    index["ledger_count"] = verified_after["count"]
    index["ledger_tip_hash"] = verified_after["tip_hash"]

    updated_last_success = {
        "schema_version": SCHEMA_VERSION,
        "sources": dict(last_success.get("sources", {})),
    }
    for row in current.get("sources", []):
        if row.get("status") == "ok":
            updated_last_success["sources"][row["name"]] = row

    updated_state = {
        "schema_version": SCHEMA_VERSION,
        "scan_count": int(state.get("scan_count", 0) or 0) + 1,
        "current_snapshot_id": current["snapshot_id"],
        "last_recorded_at": observed_at,
        "last_health": current.get("health"),
    }

    # Each file update is atomic. Ledger goes first; index reconciliation on the
    # next startup repairs a process interruption between these replacements.
    _atomic_json_write(_path(INDEX_NAME), index)
    _atomic_json_write(_path(LAST_SUCCESS_NAME), updated_last_success)
    _atomic_json_write(
        _path(CURRENT_NAME),
        {"schema_version": SCHEMA_VERSION, "snapshot": current},
    )
    _atomic_json_write(_path(STATE_NAME), updated_state)

    return {
        "schema_version": SCHEMA_VERSION,
        "recorded": True,
        "baseline": previous is None,
        "snapshot_id": current["snapshot_id"],
        "health": current.get("health"),
        "new_events": new_events,
        "repeated_event_ids": repeated_events,
        "index_recovered_after_interruption": index_recovered,
        "ledger": {
            "count": verified_after["count"],
            "tip_hash": verified_after["tip_hash"],
            "integrity_valid": True,
        },
    }


def status() -> dict:
    """Return local ledger health without any network access."""
    verified = verify_ledger()
    state = _load_state()
    index, recovered = _reconcile_index(_load_index(), verified)
    if recovered:
        _atomic_json_write(_path(INDEX_NAME), index)
    pending = [
        row
        for row in index.get("events", {}).values()
        if isinstance(row, dict) and row.get("acknowledged_at") is None
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "integrity_valid": True,
        "ledger_count": verified["count"],
        "ledger_tip_hash": verified["tip_hash"],
        "index_recovered_after_interruption": recovered,
        "current_snapshot_id": state.get("current_snapshot_id"),
        "last_recorded_at": state.get("last_recorded_at"),
        "last_health": state.get("last_health"),
        "scan_count": state.get("scan_count", 0),
        "unacknowledged_events": len(pending),
    }


def acknowledge_event(event_id: str, *, now: datetime | None = None) -> dict:
    """Local-only acknowledgement; corrupted evidence fails closed."""
    verified = verify_ledger()
    index, recovered = _reconcile_index(_load_index(), verified)
    if recovered:
        _atomic_json_write(_path(INDEX_NAME), index)
    item = index.get("events", {}).get(event_id)
    if not isinstance(item, dict):
        raise RuntimeError("airdrop_ledger_event_not_found")
    if item.get("acknowledged_at") is None:
        item["acknowledged_at"] = _utc(now)
        _atomic_json_write(_path(INDEX_NAME), index)
    return {
        "event_id": event_id,
        "acknowledged_at": item["acknowledged_at"],
        "integrity_valid": True,
    }


def export_bundle(*, now: datetime | None = None) -> dict:
    """Return a concise local evidence bundle suitable for operator review."""
    verified = verify_ledger()
    index, recovered = _reconcile_index(_load_index(), verified)
    if recovered:
        _atomic_json_write(_path(INDEX_NAME), index)
    current = _load_current()
    if current is None:
        raise RuntimeError("airdrop_ledger_no_snapshot")
    facts = {
        key: current.get("resolved_facts", {}).get(key)
        for key in sorted(ELIGIBILITY_KEYS)
        if key in current.get("resolved_facts", {})
    }
    ledger_by_event = {
        row["event_id"]: row
        for row in verified["records"]
        if isinstance(row.get("event_id"), str)
    }
    events = [
        row
        for row in index.get("events", {}).values()
        if isinstance(row, dict)
    ]
    events.sort(
        key=lambda row: (
            str(row.get("last_seen") or ""),
            str(row.get("event_id") or ""),
        ),
        reverse=True,
    )
    recent_events: list[dict] = []
    for item in events[:MAX_EXPORT_EVENTS]:
        durable = ledger_by_event.get(item.get("event_id"))
        if not isinstance(durable, dict):
            raise LedgerIntegrityError("airdrop_ledger_index_event_missing_from_chain")
        recent_events.append(
            {
                "event_id": item.get("event_id"),
                "type": item.get("type"),
                "key": item.get("key"),
                "severity": item.get("severity"),
                "first_seen": item.get("first_seen"),
                "last_seen": item.get("last_seen"),
                "observed_at": item.get("observed_at"),
                "seen_count": item.get("seen_count"),
                "acknowledged_at": item.get("acknowledged_at"),
                "ledger_sequence": item.get("ledger_sequence"),
                "ledger_hash": item.get("ledger_hash"),
                "event": durable.get("event"),
                "source_evidence": durable.get("source_evidence", []),
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _utc(now),
        "integrity": {
            "valid": True,
            "ledger_count": verified["count"],
            "ledger_tip_hash": verified["tip_hash"],
        },
        "current": {
            "snapshot_id": current.get("snapshot_id"),
            "scanned_at": current.get("scanned_at"),
            "health": current.get("health"),
            "facts": facts,
            "conflicts": current.get("summary", {}).get("conflicts", []),
            "deadlines": current.get("deadlines", []),
            "sources": [
                _source_summary(row)
                for row in current.get("sources", [])
                if isinstance(row, dict)
            ],
        },
        "recent_events": recent_events,
        "warnings": [
            "Evidence does not itself authorize registration, signing, spending, claiming, posting, or submission.",
            "Unratified/TBD FLOP rules remain provisional even when observed repeatedly.",
        ],
    }
