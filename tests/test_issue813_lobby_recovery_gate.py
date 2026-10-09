from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


SCRIPT = Path(__file__).resolve().parents[1] / "packaging" / "oracle" / "issue813-lobby-recovery-gate.py"
spec = importlib.util.spec_from_file_location("issue813_gate", SCRIPT)
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def _iso(ts):
    return ts.isoformat()


def _units():
    return {
        name: {"pid": pid, "n_restarts": 0, "active_state": "active"}
        for name, pid in (
            ("resident", 3115930),
            ("lobby-capture", 3843527),
            ("signer", 3115839),
            ("discord", 3843574),
        )
    }


def _proof(*, healthy=False):
    end = datetime.now(timezone.utc) - timedelta(seconds=30)
    start = end - timedelta(seconds=60)
    common = {
        "at": _iso(end),
        "health": "ok" if healthy else "degraded",
        "core_gap_events": 143,
        "core_gap_messages": 5_652_707,
    }
    return {
        "schema_version": 1,
        "source_head": gate.EXPECTED_SOURCE,
        "target_head": gate.EXPECTED_TARGET,
        "worktree_clean": True,
        "samples": [
            {
                "at": _iso(start + timedelta(seconds=i * 10)),
                "mem_available_kib": 300 * 1024,
                "mem_psi_full_avg10": 2.0,
                "io_psi_full_avg10": 3.0,
                "units": _units(),
            }
            for i in range(7)
        ],
        "rich": {
            **common,
            "lobby_cursor": 71_155_086,
            "bridge_gap_events": 26,
            "bridge_gap_messages": 569_552,
            "error_rooms": [] if healthy else ["lobby"],
            "lobby_kind": None if healthy else gate.EXPECTED_KIND,
        },
        "safety": common.copy(),
    }


def test_known_capacity_degraded_is_never_autorestart_approval():
    result = gate.assess(_proof())
    assert result["decision"] == "REVIEW_REQUIRED"
    assert result["restart_authorized"] is False


def test_strict_healthy_pass_is_still_proof_only():
    result = gate.assess(_proof(healthy=True))
    assert result["decision"] == "STRICT_GATE_PROOF_ONLY"
    assert result["restart_authorized"] is False


def test_r809_pressure_sample_would_fail_gate():
    proof = _proof()
    proof["samples"][2]["mem_available_kib"] = 256232
    proof["samples"][2]["mem_psi_full_avg10"] = 7.94
    result = gate.assess(proof)
    assert result["decision"] == "NO_GO"
    assert any("memory_window_failed" in r for r in result["reasons"])

    proof = _proof()
    proof["samples"][2]["mem_psi_full_avg10"] = 7.94
    result = gate.assess(proof)
    assert result["decision"] == "NO_GO"
    assert any("memory_psi_window_failed" in r for r in result["reasons"])


def test_internally_consistent_old_window_cannot_pass():
    proof = _proof(healthy=True)
    old_time = timedelta(minutes=10)
    for sample in proof["samples"]:
        at = datetime.fromisoformat(sample["at"]) - old_time
        sample["at"] = at.isoformat()
    for key in ("rich", "safety"):
        proof[key]["at"] = (
            datetime.fromisoformat(proof[key]["at"]) - old_time
        ).isoformat()
    result = gate.assess(proof)
    assert result["decision"] == "NO_GO"
    assert "stale_or_future_sample_window" in result["reasons"]
    assert result["restart_authorized"] is False


def test_future_window_cannot_pass():
    proof = _proof(healthy=True)
    ahead = timedelta(minutes=5)
    for sample in proof["samples"]:
        sample["at"] = (
            datetime.fromisoformat(sample["at"]) + ahead
        ).isoformat()
    for key in ("rich", "safety"):
        proof[key]["at"] = (
            datetime.fromisoformat(proof[key]["at"]) + ahead
        ).isoformat()
    result = gate.assess(proof)
    assert result["decision"] == "NO_GO"
    assert "stale_or_future_sample_window" in result["reasons"]
    assert result["restart_authorized"] is False


def test_fresh_sample_window_but_stale_snapshot_cannot_pass():
    proof = _proof(healthy=True)
    proof["safety"]["at"] = (
        datetime.now(timezone.utc) - timedelta(minutes=10)
    ).isoformat()
    result = gate.assess(proof)
    assert result["decision"] == "NO_GO"
    assert "safety_not_fresh" in result["reasons"]


def test_missing_bridge_counters_fail_closed():
    proof = _proof()
    del proof["rich"]["bridge_gap_messages"]
    assert gate.assess(proof)["decision"] == "NO_GO"


def test_unexpected_degraded_error_fails_closed():
    proof = _proof()
    proof["rich"]["lobby_kind"] = "unexpected_lobby_error"
    assert gate.assess(proof)["decision"] == "NO_GO"


def test_stale_safety_snapshot_fails_closed():
    proof = _proof()
    proof["safety"]["at"] = "2026-10-08T23:55:00+00:00"
    assert gate.assess(proof)["decision"] == "NO_GO"


def test_short_or_gapped_sampling_window_fails():
    proof = _proof()
    proof["samples"] = proof["samples"][:-1]
    assert gate.assess(proof)["decision"] == "NO_GO"

    proof = _proof()
    proof["samples"][2]["at"] = proof["samples"][1]["at"]
    assert gate.assess(proof)["decision"] == "NO_GO"


def test_service_pid_or_restart_counter_drift_fails():
    proof = _proof()
    proof["samples"][4]["units"]["lobby-capture"]["pid"] += 1
    assert gate.assess(proof)["decision"] == "NO_GO"

    proof = _proof()
    proof["samples"][4]["units"]["signer"]["n_restarts"] = True
    assert gate.assess(proof)["decision"] == "NO_GO"


def test_bad_boolean_telemetry_fail_closed():
    proof = _proof()
    proof["samples"][0]["mem_available_kib"] = True
    assert gate.assess(proof)["decision"] == "NO_GO"

    proof = _proof()
    proof["samples"][0]["io_psi_full_avg10"] = float("nan")
    assert gate.assess(proof)["decision"] == "NO_GO"


def test_wrong_source_head_or_unknown_schema_fails_closed():
    proof = _proof()
    proof["source_head"] = "wrong"
    assert gate.assess(proof)["decision"] == "NO_GO"
    assert gate.assess({**_proof(), "schema_version": 2})["decision"] == "NO_GO"


def test_cli_reports_review_required_and_never_authorizes(tmp_path):
    source = tmp_path / "fixture.json"
    source.write_text(json.dumps(_proof()), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(source)],
        text=True, capture_output=True, check=False,
    )
    assert result.returncode == 2
    verdict = json.loads(result.stdout)
    assert verdict["decision"] == "REVIEW_REQUIRED"
    assert verdict["restart_authorized"] is False


def test_cli_oversized_proof_is_no_go(tmp_path):
    source = tmp_path / "large.json"
    source.write_bytes(b" " * (gate.MAX_PROOF_BYTES + 1))
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(source)],
        text=True, capture_output=True, check=False,
    )
    assert result.returncode == 2
    verdict = json.loads(result.stdout)
    assert verdict["decision"] == "NO_GO"
    assert verdict["restart_authorized"] is False
