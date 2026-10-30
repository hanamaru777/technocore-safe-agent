"""R1104 OFFLINE G1/G4 consistency gate, never a signed barrier or live fence.

Production source identifiers must be obtained from a future separately approved,
authenticated source witness. This script does not collect them. No host I/O.
All untrusted input remains insufficient for migration or source export.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import re


def _load_original_contract():
    path = Path(__file__).resolve().parents[1] / "archive" / "r1052_offline_writer_route_contract.py"
    spec = importlib.util.spec_from_file_location("r1104_offline_original_contract", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_SOURCE = _load_original_contract()  # pure source constants; no live OCI use
EXPECTED = frozenset(_SOURCE.ORIGINAL_TEMPLATE_GIT_BLOBS)
HISTORICAL_EXTRAS = frozenset(_SOURCE.UNEXPECTED_INSTALLED_NAMES_FROM_R1034)
CATEGORIES = frozenset({
    "capture", "resident", "discord", "signer", "tclk", "close1",
    "timers", "cron", "manual", "transient", "boot", "restart", "approval",
})
SOURCE_HEAD = _SOURCE.ORIGINAL_SOURCE_HEAD
HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_EXTRAS = 2048


class Stop(ValueError):
    pass


def need(value, reason):
    if not value:
        raise Stop(reason)


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys.split()), "SCHEMA_STOP")


def hexdigest(value):
    need(type(value) is str and HEX.fullmatch(value), "IDENTITY_STOP")


def number(value, lo=0, hi=2**63-1):
    need(type(value) is int and lo <= value <= hi, "NUMBER_STOP")


def true(value):
    need(value is True, "REVIEW_INCOMPLETE")


def zero(value):
    number(value)
    need(value == 0, "UNRESOLVED_OR_ACTIVE")


def _name_digest(name):
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


def _check_expected(values):
    need(type(values) is dict and set(values) == EXPECTED, "EXPECTED_27_STOP")
    absent = 0
    for name in sorted(EXPECTED):
        row = values[name]
        exact(row, "status config_digest effective_aliases_checked launch_edges_checked")
        need(row["status"] in ("audited_present", "audited_absent"), "EXPECTED_STATUS_STOP")
        hexdigest(row["config_digest"])
        true(row["effective_aliases_checked"])
        true(row["launch_edges_checked"])
        absent += row["status"] == "audited_absent"
    return absent


def _check_extras(values):
    need(type(values) is list and 11 <= len(values) <= MAX_EXTRAS, "EXTRA_11_STOP")
    observed = set()
    expected_hashes = {_name_digest(n) for n in EXPECTED}
    for row in values:
        exact(row, "name_digest config_digest effective_aliases_checked launch_edges_checked")
        hexdigest(row["name_digest"])
        hexdigest(row["config_digest"])
        true(row["effective_aliases_checked"])
        true(row["launch_edges_checked"])
        need(row["name_digest"] not in observed, "EXTRA_DUPLICATE_STOP")
        need(row["name_digest"] not in expected_hashes, "EXTRA_EXPECTED_COLLISION")
        observed.add(row["name_digest"])
    need({_name_digest(n) for n in HISTORICAL_EXTRAS} <= observed, "HISTORICAL_FOUR_MISSING")
    return len(observed)


def _check_launchers(value):
    need(type(value) is dict and set(value) == CATEGORIES, "LAUNCHER_COVERAGE_STOP")
    for name in sorted(CATEGORIES):
        row = value[name]
        exact(row, "census_digest scanned relaunch_denied unknown")
        hexdigest(row["census_digest"])
        true(row["scanned"])
        true(row["relaunch_denied"])
        zero(row["unknown"])


def assess(bundle, *, now):
    """False/forged assertions cannot become a runtime G4 authorization."""
    reason = "UNAUTHENTICATED_INPUT"
    counts = None
    try:
        number(now, 1)
        exact(bundle, "schema_version observed_at source_head host_digest baseline units launchers descriptors mounts")
        need(type(bundle["schema_version"]) is int and bundle["schema_version"] == 1, "SCHEMA_STOP")
        need(bundle["source_head"] == SOURCE_HEAD, "SOURCE_HEAD_STOP")
        hexdigest(bundle["host_digest"])
        number(bundle["observed_at"], 1)
        need(bundle["observed_at"] <= now and now - bundle["observed_at"] <= 30, "STALE_STOP")
        baseline = bundle["baseline"]
        exact(baseline, "expected installed missing extras loaded active writable_fds unknown_fds")
        need(baseline == {"expected": 27, "installed": 19, "missing": 8, "extras": 11,
                          "loaded": 22, "active": 13, "writable_fds": 4, "unknown_fds": 1}, "BASELINE_STOP")
        units = bundle["units"]
        exact(units, "expected extras unreadable_units unresolved_unit_types")
        absent = _check_expected(units["expected"])
        extras = _check_extras(units["extras"])
        zero(units["unreadable_units"])
        zero(units["unresolved_unit_types"])
        _check_launchers(bundle["launchers"])
        fds = bundle["descriptors"]
        exact(fds, "scan_complete active_writers writable_fds directory_fds unknown_fds")
        true(fds["scan_complete"])
        for key in ("active_writers", "writable_fds", "directory_fds", "unknown_fds"):
            zero(fds[key])
        mounts = bundle["mounts"]
        exact(mounts, "namespace_count all_namespaces_enumerated all_aliases_reviewed external_hardlinks unknown_aliases")
        number(mounts["namespace_count"], 1, 4096)
        true(mounts["all_namespaces_enumerated"])
        true(mounts["all_aliases_reviewed"])
        zero(mounts["external_hardlinks"])
        zero(mounts["unknown_aliases"])
        counts = {"expected_templates": len(EXPECTED), "missing_templates": absent,
                  "extra_unit_names": extras, "launcher_classes": len(CATEGORIES)}
        reason = "OFFLINE_CONSISTENCY_ONLY_INDEPENDENT_G4_NOT_PROVEN"
    except Stop as error:
        reason = str(error)
    except (KeyError, TypeError, OverflowError, RecursionError, UnicodeError):
        reason = "SCHEMA_STOP"
    return {"phase": "R1104", "result": "OFFLINE_G1_G4_NOT_PROVEN",
            "reason": reason, "counts": counts,
            "independent_runtime_authority": "NOT_ENROLLED",
            "global_writer_fence": "NOT_PROVEN", "five_routes_finality": "NOT_PROVEN",
            "source_archive": "NOT_AUTHORIZED", "cutover": "NO_GO",
            "oci_retirement": "STRICT_NO_GO"}
