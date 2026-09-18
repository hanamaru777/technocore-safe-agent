"""Tamper-evident local evidence ledger for FLOP airdrop radar events.

This module writes only under FLOP_STATE_DIR/airdrop-radar or an explicit
test root. It performs no network I/O and never signs, posts, registers,
claims, spends, submits, or touches Observer/Signer state.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable

from . import airdrop_radar, core

LEDGER_SCHEMA_VERSION = 1
EVENT_SCHEMA_VERSION = 1
SNAPSHOT_WRAPPER_VERSION = 1
MAX_EVENT_BYTES = 262_144
MAX_SNAPSHOT_BYTES = 2_000_000
MAX_EXPORT_BYTES = 32_000_000
EVENT_FILE_RE = re.compile(r"^(\d{12})-([0-9a-f]{64})\.json$")
FORBIDDEN_PERSISTED_KEYS = {
    "body", "html", "cookie", "cookies", "authorization", "credentials",
    "password", "private_key", "sign_seed", "seed",
}


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise RuntimeError("airdrop_ledger_timestamp_invalid") from error
    if parsed.tzinfo is None:
        raise RuntimeError("airdrop_ledger_timestamp_timezone_required")
    return parsed.astimezone(UTC)


def _utc_iso(value: datetime | None = None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise RuntimeError("airdrop_ledger_timestamp_timezone_required")
    return current.astimezone(UTC).isoformat()


def ledger_dir(root: Path | str | None = None) -> Path:
    base = Path(root).resolve() if root is not None else core.STATE
    return base / "airdrop-radar"


def _events_dir(root: Path | str | None = None) -> Path:
    return ledger_dir(root) / "events"


def _state_path(root: Path | str | None = None) -> Path:
    return ledger_dir(root) / "state.json"


def _snapshot_path(root: Path | str | None = None) -> Path:
    return ledger_dir(root) / "current-snapshot.json"


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_json_write(path: Path, value: object, *, max_bytes: int) -> None:
    encoded = (_canonical(value) + "\n").encode("utf-8")
    if len(encoded) > max_bytes:
        raise RuntimeError("airdrop_ledger_record_too_large")
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "wb", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
    )
    temp_path = Path(handle.name)
    try:
        with handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        _fsync_directory(path.parent)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def _cleanup_orphan_temps(root: Path | str | None = None) -> int:
    removed = 0
    for directory in (ledger_dir(root), _events_dir(root)):
        if not directory.exists():
            continue
        for path in directory.iterdir():
            if path.is_file() and path.name.startswith(".") and path.name.endswith(".tmp"):
                path.unlink()
                removed += 1
    return removed


def _validate_no_forbidden_material(value: object, *, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            name = str(key).lower()
            if name in FORBIDDEN_PERSISTED_KEYS:
                raise RuntimeError(f"airdrop_ledger_forbidden_field:{path}.{key}")
            _validate_no_forbidden_material(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_no_forbidden_material(child, path=f"{path}[{index}]")


def _default_state(now: str | None = None) -> dict:
    stamp = now or _utc_iso()
    return {
        "schema_version": LEDGER_SCHEMA_VERSION,
        "created_at": stamp,
        "updated_at": stamp,
        "event_count": 0,
        "last_event_hash": "",
        "seen_events": {},
        "last_good_sources": {},
        "last_snapshot_id": None,
        "last_snapshot_event_count": 0,
        "last_scan_at": None,
        "last_health": None,
        "last_failed_sources": [],
    }


def _state_hash(state: dict) -> str:
    material = dict(state)
    material.pop("state_hash", None)
    return _digest(material)


def _write_state(state: dict, root: Path | str | None = None) -> None:
    material = json.loads(_canonical(state))
    material["schema_version"] = LEDGER_SCHEMA_VERSION
    material["state_hash"] = _state_hash(material)
    _atomic_json_write(_state_path(root), material, max_bytes=MAX_SNAPSHOT_BYTES)


def _read_state(root: Path | str | None = None) -> tuple[dict, bool]:
    path = _state_path(root)
    if not path.exists():
        return _default_state(), False
    try:
        state = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("airdrop_ledger_state_corrupt") from error
    if not isinstance(state, dict) or state.get("schema_version") != LEDGER_SCHEMA_VERSION:
        raise RuntimeError("airdrop_ledger_state_schema_mismatch")
    recorded = state.get("state_hash")
    if not isinstance(recorded, str):
        raise RuntimeError("airdrop_ledger_state_hash_missing")
    if recorded != _state_hash(state):
        raise RuntimeError("airdrop_ledger_state_hash_mismatch")
    state.pop("state_hash", None)
    if not isinstance(state.get("seen_events"), dict) or not isinstance(state.get("last_good_sources"), dict):
        raise RuntimeError("airdrop_ledger_state_shape_invalid")
    return state, True


def _event_file(sequence: int, event_hash: str, root: Path | str | None = None) -> Path:
    return _events_dir(root) / f"{sequence:012d}-{event_hash}.json"


def _event_material(record: dict) -> dict:
    material = dict(record)
    material.pop("hash", None)
    return material


def _scan_event_chain(root: Path | str | None = None) -> list[dict]:
    directory = _events_dir(root)
    if not directory.exists():
        return []
    files = sorted(path for path in directory.iterdir() if path.is_file() and not path.name.startswith("."))
    records: list[dict] = []
    previous_hash = ""
    seen_ids: set[str] = set()
    expected_sequence = 1
    for path in files:
        match = EVENT_FILE_RE.fullmatch(path.name)
        if not match:
            raise RuntimeError(f"airdrop_ledger_unexpected_event_file:{path.name}")
        sequence = int(match.group(1))
        filename_hash = match.group(2)
        if sequence != expected_sequence:
            raise RuntimeError("airdrop_ledger_event_sequence_gap")
        try:
            record = json.loads(path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError("airdrop_ledger_event_corrupt") from error
        if not isinstance(record, dict) or record.get("schema_version") != EVENT_SCHEMA_VERSION:
            raise RuntimeError("airdrop_ledger_event_schema_mismatch")
        if record.get("sequence") != sequence:
            raise RuntimeError("airdrop_ledger_event_sequence_mismatch")
        if record.get("previous_hash") != previous_hash:
            raise RuntimeError("airdrop_ledger_event_chain_mismatch")
        event_id = record.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            raise RuntimeError("airdrop_ledger_event_id_invalid")
        if event_id in seen_ids:
            raise RuntimeError("airdrop_ledger_duplicate_event_id")
        recorded_hash = record.get("hash")
        if not isinstance(recorded_hash, str):
            raise RuntimeError("airdrop_ledger_event_hash_missing")
        computed = _digest(_event_material(record))
        if recorded_hash != computed or recorded_hash != filename_hash:
            raise RuntimeError("airdrop_ledger_event_hash_mismatch")
        _parse_utc(str(record.get("first_seen")))
        _parse_utc(str(record.get("observed_at")))
        _validate_no_forbidden_material(record)
        seen_ids.add(event_id)
        records.append(record)
        previous_hash = recorded_hash
        expected_sequence += 1
    return records


def _rebuild_chain_cache(state: dict, records: list[dict]) -> tuple[dict, bool]:
    changed = False
    current_count = int(state.get("event_count", 0))
    if current_count < 0 or current_count > len(records):
        raise RuntimeError("airdrop_ledger_state_event_count_invalid")
    expected_prefix_hash = records[current_count - 1]["hash"] if current_count else ""
    if state.get("last_event_hash", "") != expected_prefix_hash:
        raise RuntimeError("airdrop_ledger_state_head_mismatch")
    if current_count < len(records):
        state["event_count"] = len(records)
        state["last_event_hash"] = records[-1]["hash"] if records else ""
        changed = True

    seen = state.setdefault("seen_events", {})
    record_ids = {record["event_id"] for record in records}
    if set(seen) - record_ids:
        raise RuntimeError("airdrop_ledger_state_seen_event_missing_from_chain")
    for record in records:
        event_id = record["event_id"]
        existing = seen.get(event_id)
        if existing is None:
            seen[event_id] = {
                "sequence": record["sequence"],
                "hash": record["hash"],
                "first_seen": record["first_seen"],
                "last_seen": record["first_seen"],
            }
            changed = True
        elif (
            existing.get("sequence") != record["sequence"]
            or existing.get("hash") != record["hash"]
            or existing.get("first_seen") != record["first_seen"]
        ):
            raise RuntimeError("airdrop_ledger_state_seen_event_mismatch")
        else:
            _parse_utc(str(existing.get("last_seen")))
    return state, changed


def _safe_source_cache(row: dict, observed_at: str) -> dict:
    if row.get("status") != "ok":
        raise RuntimeError("airdrop_ledger_last_good_requires_ok_source")
    allowed = {
        "name", "url", "final_url", "tier", "authority", "critical", "status",
        "attempts", "latency_ms", "content_sha256", "content_bytes", "meta",
        "facts", "deadlines", "interest_links",
    }
    cached = {key: row[key] for key in allowed if key in row}
    cached["last_success_at"] = observed_at
    _validate_no_forbidden_material(cached)
    if len(_canonical(cached).encode("utf-8")) > MAX_SNAPSHOT_BYTES:
        raise RuntimeError("airdrop_ledger_source_cache_too_large")
    return json.loads(_canonical(cached))


def _snapshot_wrapper(snapshot: dict, state: dict) -> dict:
    return {
        "schema_version": SNAPSHOT_WRAPPER_VERSION,
        "event_count": state["event_count"],
        "ledger_head": state["last_event_hash"],
        "snapshot": snapshot,
    }


def _validate_snapshot(snapshot: dict) -> None:
    airdrop_radar.normalize_previous_snapshot(snapshot)
    _parse_utc(str(snapshot.get("scanned_at")))
    _validate_no_forbidden_material(snapshot)
    if len(_canonical(snapshot).encode("utf-8")) > MAX_SNAPSHOT_BYTES:
        raise RuntimeError("airdrop_ledger_snapshot_too_large")


def _read_snapshot_wrapper(records: list[dict], root: Path | str | None = None) -> dict | None:
    path = _snapshot_path(root)
    if not path.exists():
        return None
    try:
        wrapper = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("airdrop_ledger_snapshot_corrupt") from error
    if not isinstance(wrapper, dict) or wrapper.get("schema_version") != SNAPSHOT_WRAPPER_VERSION:
        raise RuntimeError("airdrop_ledger_snapshot_schema_mismatch")
    count = wrapper.get("event_count")
    head = wrapper.get("ledger_head")
    if not isinstance(count, int) or count < 0 or count > len(records) or not isinstance(head, str):
        raise RuntimeError("airdrop_ledger_snapshot_head_invalid")
    expected = records[count - 1]["hash"] if count else ""
    if head != expected:
        raise RuntimeError("airdrop_ledger_snapshot_head_mismatch")
    snapshot = airdrop_radar.normalize_previous_snapshot(wrapper.get("snapshot"))
    _validate_snapshot(snapshot)
    return {
        "schema_version": SNAPSHOT_WRAPPER_VERSION,
        "event_count": count,
        "ledger_head": head,
        "snapshot": snapshot,
    }


def _reconcile_state_from_snapshot(state: dict, wrapper: dict | None) -> tuple[dict, bool]:
    if wrapper is None:
        return state, False
    snapshot = wrapper["snapshot"]
    if state.get("last_snapshot_id") == snapshot.get("snapshot_id"):
        return state, False
    previous_count = int(state.get("last_snapshot_event_count", 0))
    wrapper_count = int(wrapper["event_count"])
    if wrapper_count < previous_count:
        raise RuntimeError("airdrop_ledger_snapshot_state_regression")
    observed_at = str(snapshot["scanned_at"])
    for row in snapshot.get("sources", []):
        if isinstance(row, dict) and row.get("status") == "ok" and isinstance(row.get("name"), str):
            state["last_good_sources"][row["name"]] = _safe_source_cache(row, observed_at)
    state["last_snapshot_id"] = snapshot["snapshot_id"]
    state["last_snapshot_event_count"] = wrapper_count
    state["last_scan_at"] = observed_at
    state["last_health"] = snapshot.get("health")
    state["last_failed_sources"] = list(snapshot.get("summary", {}).get("failed_sources", []))
    state["updated_at"] = observed_at
    return state, True


def verify_ledger(root: Path | str | None = None, *, recover: bool = True) -> dict:
    """Verify immutable events and recover only crash-stale cache state."""
    base = ledger_dir(root)
    base.mkdir(parents=True, exist_ok=True)
    _events_dir(root).mkdir(parents=True, exist_ok=True)
    removed_temps = _cleanup_orphan_temps(root)
    state, state_exists = _read_state(root)
    records = _scan_event_chain(root)
    state, chain_recovered = _rebuild_chain_cache(state, records)
    wrapper = _read_snapshot_wrapper(records, root)
    state, snapshot_recovered = _reconcile_state_from_snapshot(state, wrapper)
    recovered = chain_recovered or snapshot_recovered or removed_temps > 0
    if (chain_recovered or snapshot_recovered) and not recover:
        raise RuntimeError("airdrop_ledger_recovery_required")
    if recover and (chain_recovered or snapshot_recovered or (not state_exists and records)):
        state["updated_at"] = _utc_iso()
        _write_state(state, root)
    return {
        "ok": True,
        "schema_version": LEDGER_SCHEMA_VERSION,
        "event_count": len(records),
        "last_event_hash": records[-1]["hash"] if records else "",
        "state_present": _state_path(root).exists(),
        "snapshot_present": wrapper is not None,
        "snapshot_id": wrapper["snapshot"]["snapshot_id"] if wrapper else None,
        "recovered": recovered,
        "orphan_temps_removed": removed_temps,
        "path": str(base),
    }


def _event_id(event_type: str, key: str, before: object, after: object, source: str | None = None) -> str:
    return hashlib.sha256(
        _canonical({"type": event_type, "key": key, "before": before, "after": after, "source": source}).encode("utf-8")
    ).hexdigest()[:24]


def _make_event(
    *, event_type: str, key: str, severity: str, before: object, after: object,
    source: str | None = None, extra: dict | None = None,
) -> dict:
    row = {
        "event_id": _event_id(event_type, key, before, after, source),
        "type": event_type,
        "key": key,
        "severity": severity,
        "before": before,
        "after": after,
    }
    if source:
        row["source"] = source
    if extra:
        row.update(extra)
    return row


def _source_rows(snapshot: dict | None) -> dict[str, dict]:
    if not snapshot:
        return {}
    return {
        str(row["name"]): row
        for row in snapshot.get("sources", [])
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    }


def _source_fact_map(source: dict) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for fact in source.get("facts", []):
        if isinstance(fact, dict) and isinstance(fact.get("key"), str):
            grouped.setdefault(fact["key"], []).append(fact)
    return {key: sorted(rows, key=_canonical) for key, rows in grouped.items()}


def _source_deadline_identity(row: dict) -> str:
    return _digest({
        "label": row.get("label"),
        "timestamp": row.get("timestamp"),
        "date": row.get("date"),
        "source": row.get("source"),
    })


def _recovery_source_events(*, last_good: dict, current: dict, observed_at: str) -> list[dict]:
    """Reveal semantic changes that happened while this source was unavailable."""
    source = str(current["name"])
    events: list[dict] = []
    before_facts = _source_fact_map(last_good)
    after_facts = _source_fact_map(current)
    semantic_change = False
    for key in sorted(set(before_facts) | set(after_facts)):
        before, after = before_facts.get(key), after_facts.get(key)
        if _canonical(before) == _canonical(after):
            continue
        semantic_change = True
        events.append(_make_event(
            event_type="RECOVERED_SOURCE_FACT_CHANGED",
            key=key,
            severity="HIGH" if key in airdrop_radar.HIGH_KEYS else "MEDIUM",
            before=before,
            after=after,
            source=source,
        ))

    before_version = last_good.get("meta", {}).get("version")
    after_version = current.get("meta", {}).get("version")
    if before_version and after_version and before_version != after_version:
        semantic_change = True
        events.append(_make_event(
            event_type="RECOVERED_SOURCE_VERSION_CHANGED",
            key=f"source:{source}:version",
            severity="HIGH" if source == "yellowpaper" else "MEDIUM",
            before=before_version,
            after=after_version,
            source=source,
        ))

    before_target, after_target = last_good.get("final_url"), current.get("final_url")
    if before_target and after_target and before_target != after_target:
        semantic_change = True
        events.append(_make_event(
            event_type="RECOVERED_SOURCE_TARGET_CHANGED",
            key=f"source:{source}:target",
            severity="HIGH" if source == "kol_application" else "MEDIUM",
            before=before_target,
            after=after_target,
            source=source,
        ))

    before_links = set(last_good.get("interest_links", []))
    after_links = set(current.get("interest_links", []))
    for url in sorted(after_links - before_links):
        semantic_change = True
        events.append(_make_event(
            event_type="RECOVERED_OFFICIAL_LINK_DISCOVERED",
            key=f"official_link:{url}",
            severity="HIGH",
            before=None,
            after={"url": url, "source": source},
            source=source,
        ))
    for url in sorted(before_links - after_links):
        semantic_change = True
        events.append(_make_event(
            event_type="RECOVERED_OFFICIAL_LINK_REMOVED",
            key=f"official_link:{url}",
            severity="MEDIUM",
            before={"url": url, "source": source},
            after=None,
            source=source,
        ))

    before_deadlines = {
        _source_deadline_identity(row): row
        for row in last_good.get("deadlines", []) if isinstance(row, dict)
    }
    after_deadlines = {
        _source_deadline_identity(row): row
        for row in current.get("deadlines", []) if isinstance(row, dict)
    }
    observed_dt = _parse_utc(observed_at)
    for deadline_id, row in after_deadlines.items():
        if deadline_id in before_deadlines:
            continue
        semantic_change = True
        extra = {"deadline": row}
        severity = "HIGH"
        if row.get("exact") and isinstance(row.get("timestamp"), str):
            gate = airdrop_radar.deadline_gate(row["timestamp"], now=observed_dt)
            extra["deadline_gate"] = gate
            if 0 <= gate["seconds_remaining"] <= 86_400:
                severity = "ACTION_NOW"
        events.append(_make_event(
            event_type="RECOVERED_SOURCE_DEADLINE_DISCOVERED",
            key=f"deadline:{row.get('label', 'unknown')}",
            severity=severity,
            before=None,
            after=row,
            source=source,
            extra=extra,
        ))

    if last_good.get("content_sha256") != current.get("content_sha256") and not semantic_change:
        events.append(_make_event(
            event_type="RECOVERED_SOURCE_CONTENT_CHANGED",
            key=f"source:{source}",
            severity="HIGH" if source == "yellowpaper" else "INFO",
            before=last_good.get("content_sha256"),
            after=current.get("content_sha256"),
            source=source,
        ))
    return events


def _recovery_events(previous: dict | None, current: dict, state: dict, observed_at: str) -> list[dict]:
    if previous is None:
        return []
    before_rows, after_rows = _source_rows(previous), _source_rows(current)
    events: list[dict] = []
    for name, current_row in after_rows.items():
        previous_row = before_rows.get(name)
        if (
            current_row.get("status") != "ok"
            or not previous_row
            or previous_row.get("status") == "ok"
        ):
            continue
        last_good = state.get("last_good_sources", {}).get(name)
        if isinstance(last_good, dict):
            events.extend(_recovery_source_events(
                last_good=last_good, current=current_row, observed_at=observed_at
            ))
    return events


def _collect_source_names(value: object, output: set[str]) -> None:
    if isinstance(value, dict):
        source = value.get("source")
        if isinstance(source, str):
            output.add(source)
        for child in value.values():
            _collect_source_names(child, output)
    elif isinstance(value, list):
        for child in value:
            _collect_source_names(child, output)


def _source_summary(row: dict) -> dict:
    allowed = {"name", "url", "final_url", "tier", "authority", "status", "content_sha256", "meta"}
    return {key: row[key] for key in allowed if key in row}


def _event_evidence(event: dict, previous: dict | None, current: dict) -> list[dict]:
    names: set[str] = set()
    _collect_source_names(event, names)
    key = str(event.get("key", ""))
    if key.startswith("source:"):
        pieces = key.split(":")
        if len(pieces) >= 2 and pieces[1]:
            names.add(pieces[1])
    before_rows, after_rows = _source_rows(previous), _source_rows(current)
    evidence = []
    for name in sorted(names):
        row: dict = {"name": name}
        if name in before_rows:
            row["previous"] = _source_summary(before_rows[name])
        if name in after_rows:
            row["current"] = _source_summary(after_rows[name])
        evidence.append(row)
    return evidence


def _normalize_event(event: dict, *, previous: dict | None, current: dict) -> dict:
    allowed = {
        "event_id", "type", "key", "severity", "before", "after", "source",
        "deadline", "deadline_gate",
    }
    normalized = {key: event[key] for key in allowed if key in event}
    if not isinstance(normalized.get("event_id"), str) or not normalized["event_id"]:
        normalized["event_id"] = _event_id(
            str(normalized.get("type", "UNKNOWN")),
            str(normalized.get("key", "unknown")),
            normalized.get("before"),
            normalized.get("after"),
            normalized.get("source") if isinstance(normalized.get("source"), str) else None,
        )
    normalized["evidence_sources"] = _event_evidence(normalized, previous, current)
    _validate_no_forbidden_material(normalized)
    if len(_canonical(normalized).encode("utf-8")) > MAX_EVENT_BYTES:
        raise RuntimeError("airdrop_ledger_event_too_large")
    return json.loads(_canonical(normalized))


def _write_event_record(
    event: dict, *, observed_at: str, state: dict, root: Path | str | None
) -> tuple[dict | None, bool]:
    event_id = event["event_id"]
    seen = state["seen_events"].get(event_id)
    if seen is not None:
        _parse_utc(str(seen["last_seen"]))
        seen["last_seen"] = observed_at
        return None, True

    sequence = int(state["event_count"]) + 1
    record = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "sequence": sequence,
        **event,
        "observed_at": observed_at,
        "first_seen": observed_at,
        "last_seen": observed_at,
        "previous_hash": state["last_event_hash"],
    }
    record["hash"] = _digest(_event_material(record))
    _validate_no_forbidden_material(record)
    if len((_canonical(record) + "\n").encode("utf-8")) > MAX_EVENT_BYTES:
        raise RuntimeError("airdrop_ledger_event_too_large")
    path = _event_file(sequence, record["hash"], root)
    if path.exists():
        try:
            existing = json.loads(path.read_text("utf-8"))
        except json.JSONDecodeError as error:
            raise RuntimeError("airdrop_ledger_event_collision_corrupt") from error
        if existing != record:
            raise RuntimeError("airdrop_ledger_event_collision")
    else:
        _atomic_json_write(path, record, max_bytes=MAX_EVENT_BYTES)
    state["event_count"] = sequence
    state["last_event_hash"] = record["hash"]
    state["seen_events"][event_id] = {
        "sequence": sequence,
        "hash": record["hash"],
        "first_seen": observed_at,
        "last_seen": observed_at,
    }
    return record, False


def _dedupe_event_list(events: Iterable[dict]) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    for event in events:
        event_id = str(event.get("event_id", ""))
        if event_id in seen:
            continue
        seen.add(event_id)
        rows.append(event)
    return rows


def record_snapshot(snapshot: dict, root: Path | str | None = None) -> dict:
    """Persist one Radar snapshot and its material changes as local evidence."""
    current = airdrop_radar.normalize_previous_snapshot(snapshot)
    _validate_snapshot(current)
    observed_at = _utc_iso(_parse_utc(str(current["scanned_at"])))

    verification = verify_ledger(root, recover=True)
    state, _ = _read_state(root)
    records = _scan_event_chain(root)
    previous_wrapper = _read_snapshot_wrapper(records, root)
    previous = previous_wrapper["snapshot"] if previous_wrapper else None

    diff = airdrop_radar.compare_snapshots(previous, current, now=_parse_utc(observed_at))
    recovery = _recovery_events(previous, current, state, observed_at)
    normalized_events = [
        _normalize_event(event, previous=previous, current=current)
        for event in _dedupe_event_list([*diff["events"], *recovery])
    ]

    written: list[dict] = []
    deduped = 0
    for event in normalized_events:
        record, was_duplicate = _write_event_record(
            event, observed_at=observed_at, state=state, root=root
        )
        if was_duplicate:
            deduped += 1
        elif record is not None:
            written.append(record)

    for row in current.get("sources", []):
        if isinstance(row, dict) and row.get("status") == "ok" and isinstance(row.get("name"), str):
            state["last_good_sources"][row["name"]] = _safe_source_cache(row, observed_at)

    state["last_snapshot_id"] = current["snapshot_id"]
    state["last_snapshot_event_count"] = state["event_count"]
    state["last_scan_at"] = observed_at
    state["last_health"] = current.get("health")
    state["last_failed_sources"] = list(current.get("summary", {}).get("failed_sources", []))
    state["updated_at"] = observed_at

    _atomic_json_write(
        _snapshot_path(root), _snapshot_wrapper(current, state), max_bytes=MAX_SNAPSHOT_BYTES
    )
    _write_state(state, root)
    return {
        "ok": True,
        "snapshot_id": current["snapshot_id"],
        "health": current.get("health"),
        "baseline": diff.get("baseline", False),
        "events_recorded": len(written),
        "events_deduped": deduped,
        "event_ids": [record["event_id"] for record in written],
        "recovery_events": [
            event["event_id"] for event in normalized_events
            if event["type"].startswith("RECOVERED_")
        ],
        "ledger": {
            **verification,
            "event_count": state["event_count"],
            "last_event_hash": state["last_event_hash"],
            "snapshot_id": current["snapshot_id"],
        },
    }


def ledger_status(root: Path | str | None = None) -> dict:
    verification = verify_ledger(root, recover=True)
    state, _ = _read_state(root)
    return {
        **verification,
        "last_scan_at": state.get("last_scan_at"),
        "last_health": state.get("last_health"),
        "last_failed_sources": state.get("last_failed_sources", []),
        "seen_event_count": len(state.get("seen_events", {})),
        "last_good_source_count": len(state.get("last_good_sources", {})),
    }


def _export_event(record: dict, state: dict) -> dict:
    row = dict(record)
    seen = state.get("seen_events", {}).get(record["event_id"], {})
    if isinstance(seen.get("last_seen"), str):
        row["last_seen"] = seen["last_seen"]
    return row


def export_bundle(output: Path | str, root: Path | str | None = None) -> dict:
    """Export one local proof bundle; this performs no network action."""
    status = verify_ledger(root, recover=True)
    state, _ = _read_state(root)
    records = _scan_event_chain(root)
    wrapper = _read_snapshot_wrapper(records, root)
    if wrapper is None:
        raise RuntimeError("airdrop_ledger_snapshot_missing")
    snapshot = wrapper["snapshot"]
    bundle = {
        "schema_version": 1,
        "exported_at": _utc_iso(),
        "ledger": {
            "event_count": status["event_count"],
            "last_event_hash": status["last_event_hash"],
            "snapshot_id": status["snapshot_id"],
        },
        "current": {
            "scanned_at": snapshot.get("scanned_at"),
            "health": snapshot.get("health"),
            "snapshot_id": snapshot.get("snapshot_id"),
            "resolved_facts": snapshot.get("resolved_facts", {}),
            "deadlines": snapshot.get("deadlines", []),
            "sources": [
                _source_summary(row) for row in snapshot.get("sources", [])
                if isinstance(row, dict)
            ],
        },
        "last_good_sources": state.get("last_good_sources", {}),
        "events": [_export_event(record, state) for record in records],
    }
    _validate_no_forbidden_material(bundle)
    destination = Path(output).expanduser().resolve()
    _atomic_json_write(destination, bundle, max_bytes=MAX_EXPORT_BYTES)
    return {
        "ok": True,
        "output": str(destination),
        "event_count": len(records),
        "last_event_hash": status["last_event_hash"],
        "snapshot_id": snapshot["snapshot_id"],
    }
