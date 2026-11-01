"""Fake-only G1/G4 coverage. R1102 one-time observation is not a new live probe."""
import copy
import hashlib
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "packaging/migration/r1104_g1g4_coverage_consistency.py"
spec = importlib.util.spec_from_file_location("r1104", FILE)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
NOW = 2000000000


def h(value):
    return hashlib.sha256(value.encode()).hexdigest()


def fixture():
    expected = {name: {"status": "audited_absent" if i < 8 else "audited_present",
                       "config_digest": h(name), "effective_aliases_checked": True,
                       "launch_edges_checked": True} for i, name in enumerate(sorted(r.EXPECTED))}
    extras = sorted(r.HISTORICAL_EXTRAS) + [f"technocore-safe-agent-synthetic-{i}.service" for i in range(7)]
    return {"schema_version": 1, "observed_at": NOW, "source_head": r.SOURCE_HEAD,
            "host_digest": h("fake-original-host"),
            "baseline": {"expected": 27, "installed": 19, "missing": 8,
                         "extras": 11, "loaded": 22, "active": 13, "writable_fds": 4,
                         "unknown_fds": 1},
            "units": {"expected": expected, "extras": [
                {"name_digest": h(n), "config_digest": h("unit-" + n),
                 "effective_aliases_checked": True, "launch_edges_checked": True}
                for n in extras], "unreadable_units": 0, "unresolved_unit_types": 0},
            "launchers": {name: {"census_digest": h(name), "scanned": True,
                                  "relaunch_denied": True, "unknown": 0} for name in r.CATEGORIES},
            "descriptors": {"scan_complete": True, "active_writers": 0,
                            "writable_fds": 0, "directory_fds": 0, "unknown_fds": 0},
            "mounts": {"namespace_count": 1, "all_namespaces_enumerated": True,
                       "all_aliases_reviewed": True, "external_hardlinks": 0,
                       "unknown_aliases": 0}}


def test_complete_fake_manifest_never_proves_g4_or_archive():
    result = r.assess(fixture(), now=NOW)
    assert result["reason"] == "OFFLINE_CONSISTENCY_ONLY_INDEPENDENT_G4_NOT_PROVEN"
    assert result["counts"] == {"expected_templates": 27, "missing_templates": 8,
                                "extra_unit_names": 11, "launcher_classes": 13}
    assert result["global_writer_fence"] == "NOT_PROVEN"
    assert result["source_archive"] == "NOT_AUTHORIZED"
    assert result["oci_retirement"] == "STRICT_NO_GO"
    assert "technocore" not in str(result)


@pytest.mark.parametrize("case", [
    "missing_expected", "missing_extra", "missing_known_historical", "unknown_unit", "unreviewed_alias",
    "unreviewed_edge", "duplicate_extra", "bad_digest", "writer", "unknown_fd", "directory_fd",
    "unscanned", "relaunch", "unknown_launcher", "removed_manual", "mount_ns_unseen",
    "mount_alias_unknown", "external_hardlinks", "stale", "false_freshness", "wrong_head",
    "wrong_baseline", "bool_baseline", "expected_drift", "wrong_type", "r1102_only", "unreadable", "bad_count", "unknown_unit_type"
])
def test_incomplete_or_r1102_count_only_never_passes_precheck(case):
    a = fixture()
    if case == "missing_expected":
        del a["units"]["expected"][next(iter(a["units"]["expected"]))]
    elif case == "missing_extra":
        a["units"]["extras"].pop()
    elif case == "missing_known_historical":
        a["units"]["extras"].pop(0)
    elif case == "unknown_unit":
        a["units"]["unreadable_units"] = 1
    elif case == "unreviewed_alias":
        next(iter(a["units"]["expected"].values()))["effective_aliases_checked"] = False
    elif case == "unreviewed_edge":
        next(iter(a["units"]["extras"]))["launch_edges_checked"] = False
    elif case == "duplicate_extra":
        a["units"]["extras"][0] = copy.deepcopy(a["units"]["extras"][1])
    elif case == "bad_digest":
        a["units"]["extras"][0]["name_digest"] = "not-a-digest"
    elif case == "writer":
        a["descriptors"]["writable_fds"] = 4
    elif case == "unknown_fd":
        a["descriptors"]["unknown_fds"] = 1
    elif case == "directory_fd":
        a["descriptors"]["directory_fds"] = 1
    elif case == "unscanned":
        a["launchers"]["cron"]["scanned"] = False
    elif case == "relaunch":
        a["launchers"]["restart"]["relaunch_denied"] = False
    elif case == "unknown_launcher":
        a["launchers"]["manual"]["unknown"] = 1
    elif case == "removed_manual":
        del a["launchers"]["manual"]
    elif case == "mount_ns_unseen":
        a["mounts"]["all_namespaces_enumerated"] = False
    elif case == "mount_alias_unknown":
        a["mounts"]["unknown_aliases"] = 1
    elif case == "external_hardlinks":
        a["mounts"]["external_hardlinks"] = 1
    elif case == "stale":
        a["observed_at"] = NOW-31
    elif case == "false_freshness":
        a["observed_at"] = NOW+1
    elif case == "wrong_head":
        a["source_head"] = "a"*40
    elif case == "wrong_baseline":
        a["baseline"]["extras"] = 4
    elif case == "bool_baseline":
        a["baseline"]["unknown_fds"] = True
    elif case == "expected_drift":
        sorted_expected = sorted(a["units"]["expected"])
        a["units"]["expected"][sorted_expected[0]]["status"] = "audited_present"
    elif case == "wrong_type":
        a["descriptors"]["unknown_fds"] = False
    elif case == "r1102_only":
        a = {"schema_version": 1, "units": {"expected_source_templates": 27, "extra_installed_names": 11}}
    elif case == "unreadable":
        a["units"]["unreadable_units"] = 1
    elif case == "bad_count":
        a["units"]["expected"][next(iter(a["units"]["expected"]))]["status"] = "unverified"
    elif case == "unknown_unit_type":
        a["units"]["unresolved_unit_types"] = 1
    result = r.assess(a, now=NOW)
    assert result["reason"] != "OFFLINE_CONSISTENCY_ONLY_INDEPENDENT_G4_NOT_PROVEN"
    assert result["counts"] is None
    assert result["source_archive"] == "NOT_AUTHORIZED"
