#!/usr/bin/env python3
"""Offline, fail-closed Flop recovery telemetry evaluator.

This program reads one bounded JSON proof supplied by an operator. It has no
Production connector, does not execute subprocesses and never authorizes
a restart. It is NOT a service activation carrier.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

EXPECTED_SOURCE = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
EXPECTED_TARGET = "a1b3517a1092fb4c7e4e730ac75d42d1f0075167"
EXPECTED_KIND = "startup_lobby_capture_protected_backlog_capacity"
EXPECTED_CORE = (143, 5_652_707)
EXPECTED_BRIDGE = (26, 569_552)
PROTECTED_UNITS = ("resident", "lobby-capture", "signer", "discord")
MAX_PROOF_BYTES = 65536
MIN_WINDOW_SECONDS = 60
MAX_SAMPLE_GAP_SECONDS = 12
MAX_SNAPSHOT_AGE_SECONDS = 120
MIN_MEM_AVAILABLE_KIB = 256 * 1024
MAX_MEMORY_PSI_FULL = 5.0
MAX_IO_PSI_FULL = 10.0


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("invalid_timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp_missing_timezone")
    return parsed.astimezone(timezone.utc)


def _integer(value: Any) -> bool:
    return type(value) is int and value >= 0


def _number(value: Any) -> bool:
    return type(value) in (int, float) and 0 <= value < float("inf")


def _units(value: Any) -> tuple:
    if not isinstance(value, dict) or set(value) != set(PROTECTED_UNITS):
        raise ValueError("protected_units_missing")
    fingerprint = []
    for name in PROTECTED_UNITS:
        unit = value[name]
        if not isinstance(unit, dict):
            raise ValueError("bad_unit")
        if unit.get("active_state") != "active":
            raise ValueError("unit_not_active")
        pid = unit.get("pid")
        if not _integer(pid) or pid == 0 or unit.get("n_restarts") != 0:
            raise ValueError("unit_identity_invalid")
        fingerprint.append((name, pid, 0))
    return tuple(fingerprint)


def _assert_counter(record: dict, key: str, expected: int) -> None:
    if not _integer(record.get(key)) or record[key] != expected:
        raise ValueError("counter_mismatch_" + key)


def assess(proof: Any) -> dict:
    """Evaluate an externally acquired read-only sample. Never return GO."""
    errors = []
    needs_review = False
    if not isinstance(proof, dict) or proof.get("schema_version") != 1:
        return {"decision": "NO_GO", "restart_authorized": False, "reasons": ["invalid_schema"]}
    if proof.get("source_head") != EXPECTED_SOURCE or proof.get("target_head") != EXPECTED_TARGET:
        errors.append("unexpected_head")
    if proof.get("worktree_clean") is not True:
        errors.append("dirty_or_unknown_worktree")

    samples = proof.get("samples")
    if not isinstance(samples, list) or len(samples) < 7 or len(samples) > 25:
        errors.append("insufficient_samples")
        samples = []
    previous_time = None
    start = end = None
    baseline_units = None
    for i, sample in enumerate(samples):
        try:
            if not isinstance(sample, dict):
                raise ValueError("bad_sample")
            stamp = _timestamp(sample.get("at"))
            if previous_time is not None:
                seconds = (stamp - previous_time).total_seconds()
                if seconds <= 0 or seconds > MAX_SAMPLE_GAP_SECONDS:
                    raise ValueError("sample_gap_or_order")
            previous_time = stamp
            if start is None:
                start = stamp
            end = stamp
            fingerprint = _units(sample.get("units"))
            if baseline_units is None:
                baseline_units = fingerprint
            elif fingerprint != baseline_units:
                raise ValueError("unit_changed")
            mem = sample.get("mem_available_kib")
            if not _integer(mem) or mem < MIN_MEM_AVAILABLE_KIB:
                raise ValueError("memory_window_failed")
            psi_m = sample.get("mem_psi_full_avg10")
            psi_io = sample.get("io_psi_full_avg10")
            if not _number(psi_m) or psi_m > MAX_MEMORY_PSI_FULL:
                raise ValueError("memory_psi_window_failed")
            if not _number(psi_io) or psi_io > MAX_IO_PSI_FULL:
                raise ValueError("io_psi_window_failed")
        except (ValueError, TypeError, OverflowError) as error:
            errors.append(f"sample_{i}_{error}")
    if start is None or end is None or (end - start).total_seconds() < MIN_WINDOW_SECONDS:
        errors.append("window_shorter_than_60_seconds")

    rich = proof.get("rich")
    safety = proof.get("safety")
    try:
        if not isinstance(rich, dict) or not isinstance(safety, dict):
            raise ValueError("missing_observer_or_safety")
        if end is None:
            raise ValueError("sample_window_missing")
        for name,record in (("rich", rich), ("safety", safety)):
            age = (end - _timestamp(record.get("at"))).total_seconds()
            if not 0 <= age <= MAX_SNAPSHOT_AGE_SECONDS:
                raise ValueError(name + "_not_fresh")
            _assert_counter(record, "core_gap_events", EXPECTED_CORE[0])
            _assert_counter(record, "core_gap_messages", EXPECTED_CORE[1])
        _assert_counter(rich, "bridge_gap_events", EXPECTED_BRIDGE[0])
        _assert_counter(rich, "bridge_gap_messages", EXPECTED_BRIDGE[1])
        if not _integer(rich.get("lobby_cursor")) or rich["lobby_cursor"] == 0:
            raise ValueError("rich_cursor_invalid")
        if rich.get("health") == safety.get("health") == "ok":
            if rich.get("error_rooms") != [] or rich.get("lobby_kind") is not None:
                raise ValueError("healthy_state_has_errors")
        elif rich.get("health") == safety.get("health") == "degraded":
            if rich.get("error_rooms") != ["lobby"] or rich.get("lobby_kind") != EXPECTED_KIND:
                raise ValueError("unknown_degraded_health")
            needs_review = True
        else:
            raise ValueError("unacceptable_health")
    except (ValueError, TypeError, OverflowError) as error:
        errors.append(str(error))

    if errors:
        return {"decision": "NO_GO", "restart_authorized": False, "reasons": sorted(set(errors))}
    if needs_review:
        return {"decision": "REVIEW_REQUIRED", "restart_authorized": False,
                "reasons": ["known_core_degraded_needs_independent_approval"]}
    return {"decision": "STRICT_GATE_PROOF_ONLY", "restart_authorized": False,
            "reasons": ["read_only_evidence_is_not_restart_authorization"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("proof", type=Path, help="already collected read-only JSON proof")
    args = parser.parse_args()
    try:
        if args.proof.stat().st_size > MAX_PROOF_BYTES:
            raise ValueError("oversized_proof")
        data = json.loads(args.proof.read_text(encoding="utf-8"))
        result = assess(data)
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        result = {"decision": "NO_GO", "restart_authorized": False,
                  "reasons": [type(error).__name__]}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["decision"] == "STRICT_GATE_PROOF_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
