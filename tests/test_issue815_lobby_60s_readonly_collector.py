from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "packaging" / "oracle" / "issue815-lobby-60s-readonly-collector.py"
POLICY = ROOT / "packaging" / "oracle" / "issue813-lobby-recovery-gate.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


collector = _load("issue815_collector", COLLECTOR)
gate = _load("issue813_gate_for_815", POLICY)


def _fake_proof(*, healthy=False):
    stamp = datetime.now(timezone.utc) - timedelta(seconds=15)
    health = "ok" if healthy else "degraded"
    return {
        "at": stamp.isoformat(),
        "health": health,
        "core_gap_events": 143,
        "core_gap_messages": 5_652_707,
    }


def _fake_rich(*, healthy=False):
    return {
        **_fake_proof(healthy=healthy),
        "lobby_cursor": 71_155_086,
        "bridge_gap_events": 26,
        "bridge_gap_messages": 569_552,
        "error_rooms": [] if healthy else ["lobby"],
        "lobby_kind": None if healthy else collector.EXPECTED_ERROR,
    }


def _fake_units():
    return {
        name: {"pid": i + 1, "n_restarts": 0, "active_state": "active"}
        for i, name in enumerate(collector.UNITS)
    }


def test_exact_seven_samples_are_policy_compatible_without_sleep(monkeypatch):
    stamp = datetime.now(timezone.utc) - timedelta(seconds=15)
    calls = []

    monkeypatch.setattr(collector.socket, "gethostname", lambda: "technocore-resident")
    monkeypatch.setattr(collector, "_repo_status", lambda: (collector.OLD_HEAD, True))
    monkeypatch.setattr(collector, "_rich", lambda: _fake_rich())
    monkeypatch.setattr(collector, "_safety", lambda: _fake_proof())
    monkeypatch.setattr(collector.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(collector.time, "sleep", lambda n: calls.append(n))
    index = iter(range(collector.SAMPLES))
    def sample():
        i = next(index)
        return {
            "at": (stamp - timedelta(seconds=60) + timedelta(seconds=i * 10)).isoformat(),
            "mem_available_kib": 300 * 1024,
            "mem_psi_full_avg10": 2.0,
            "io_psi_full_avg10": 3.0,
            "units": _fake_units(),
        }

    monkeypatch.setattr(collector, "_sample", sample)
    proof = collector.collect()

    assert proof["source_head"] == collector.OLD_HEAD
    assert proof["target_head"] == collector.TARGET_HEAD
    assert len(calls) == 6
    assert len(proof["samples"]) == 7
    assert gate.assess(proof)["decision"] == "REVIEW_REQUIRED"
    assert gate.assess(proof)["restart_authorized"] is False

    proof["rich"] = _fake_rich(healthy=True)
    proof["safety"] = _fake_proof(healthy=True)
    assert gate.assess(proof)["decision"] == "STRICT_GATE_PROOF_ONLY"
    assert gate.assess(proof)["restart_authorized"] is False


def test_wrong_host_fail_closed_before_samples(monkeypatch):
    monkeypatch.setattr(collector.socket, "gethostname", lambda: "other-bot")
    monkeypatch.setattr(
        collector, "_repo_status",
        lambda: (_ for _ in ()).throw(AssertionError("must never inspect wrong host")),
    )
    with pytest.raises(ValueError, match="unexpected_host"):
        collector.collect()


def test_pinned_git_commands_are_read_only(monkeypatch):
    commands = []
    def fake_run(args, *, timeout=4):
        commands.append(args)
        if args[-2:] == ["rev-parse", "HEAD"]:
            return collector.OLD_HEAD
        if args[-3:] == ["symbolic-ref", "--short", "HEAD"]:
            return "main"
        if args[-2:] == ["status", "--porcelain"]:
            return ""
        return ""
    monkeypatch.setattr(collector, "_run", fake_run)
    assert collector._repo_status() == (collector.OLD_HEAD, True)
    assert len(commands) == 3
    assert all("push" not in cmd and "checkout" not in cmd for cmd in commands)


def test_bad_repo_head_and_dirty_worktree_fail_closed(monkeypatch):
    monkeypatch.setattr(collector, "_run", lambda command, timeout=4: "wrong")
    with pytest.raises(ValueError, match="unexpected_production_head"):
        collector._repo_status()


def test_systemctl_only_reads_expected_flop_unit(monkeypatch):
    commands = []
    def fake_run(command, *, timeout=4):
        commands.append(command)
        return "MainPID=12345\nNRestarts=0\nActiveState=active\n"
    monkeypatch.setattr(collector, "_run", fake_run)
    data = collector._unit("lobby-capture")
    assert data == {"pid": 12345, "n_restarts": 0, "active_state": "active"}
    assert commands == [[
        "systemctl", "show", "technocore-safe-agent-lobby-capture.service",
        "-p", "MainPID", "-p", "NRestarts", "-p", "ActiveState", "--no-pager"
    ]]
    with pytest.raises(ValueError, match="unit_not_allowlisted"):
        collector._unit("aerodrome")


def test_systemctl_unexpected_output_fails_closed(monkeypatch):
    monkeypatch.setattr(collector, "_run", lambda command, timeout=4:
                        "MainPID=0\nNRestarts=0\nActiveState=active\n")
    with pytest.raises(ValueError, match="invalid_pid"):
        collector._unit("resident")


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq required on Linux production")
def test_rich_jq_stream_only_whitelisted_fields(tmp_path, monkeypatch):
    state = tmp_path / "observer-state.json"
    saved = {
        "updated_at": "2026-10-09T01:00:00+00:00",
        "cursors": {"lobby": 71_155_086},
        "health": {"current": "degraded", "rooms": {
            "lobby": {"status": "error", "kind": collector.EXPECTED_ERROR},
            "irrelevant": {"status": "ok"},
        }},
        "metrics": {
            "unrecoverable_core_gap_events": 143,
            "unrecoverable_core_gap_messages": 5_652_707,
            "lobby_startup_bridge_unrecoverable_events": 26,
            "lobby_startup_bridge_unrecoverable_messages": 569_552,
        },
        "agents": {"sensitive-do-not-emit": "fake-private-data"},
    }
    state.write_text(json.dumps(saved), encoding="utf-8")
    monkeypatch.setattr(collector, "OBSERVER", tmp_path)
    rich = collector._rich()
    assert rich == {
        "at": saved["updated_at"], "lobby_cursor": 71_155_086,
        "health": "degraded", "core_gap_events": 143,
        "core_gap_messages": 5_652_707, "bridge_gap_events": 26,
        "bridge_gap_messages": 569_552,
        "error_rooms": ["lobby"], "lobby_kind": collector.EXPECTED_ERROR,
    }
    assert "fake-private-data" not in json.dumps(rich)
    saved["health"]["rooms"]["other-secret-room"] = {
        "status": "error", "kind": "sensitive-kind"
    }
    saved["health"]["rooms"]["lobby"]["kind"] = "untrusted-kind"
    state.write_text(json.dumps(saved), encoding="utf-8")
    redacted = collector._rich()
    assert redacted["error_rooms"] == ["lobby", "other"]
    assert redacted["lobby_kind"] == "OTHER"
    assert "other-secret-room" not in json.dumps(redacted)


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq required on Linux production")
def test_missing_bridge_in_stream_fails_closed(tmp_path, monkeypatch):
    (tmp_path / "observer-state.json").write_text(
        json.dumps({"updated_at": "2026-10-09T01:00:00+00:00", "cursors": {"lobby": 1}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(collector, "OBSERVER", tmp_path)
    with pytest.raises(ValueError, match="missing_rich_fields"):
        collector._rich()


def test_safety_reads_tiny_whitelist_only(tmp_path, monkeypatch):
    (tmp_path / "observer-safety.json").write_text(json.dumps({
        "schema_version": 1, "updated_at": "2026-10-09T01:00:00+00:00",
        "health": "degraded",
        "unrecoverable_core_gap_events": 143,
        "unrecoverable_core_gap_messages": 5_652_707,
        "untrusted": "private",
    }), encoding="utf-8")
    monkeypatch.setattr(collector, "ROOT", tmp_path)
    safety = collector._safety()
    assert safety["at"] == "2026-10-09T01:00:00+00:00"
    assert safety["core_gap_events"] == 143
    assert "private" not in json.dumps(safety)


def test_no_go_cli_never_echoes_exception_details(monkeypatch, capsys):
    monkeypatch.setattr(
        collector, "collect",
        lambda: (_ for _ in ()).throw(ValueError("fake-private-data")),
    )
    assert collector.main() == 2
    text = capsys.readouterr().out
    assert "fake-private-data" not in text
    result = json.loads(text)
    assert result["decision"] == "NO_GO"
    assert result["restart_authorized"] is False


def test_fail_closed_stage_categorizes_known_repo_error_without_six_minute_retry(
    monkeypatch, capsys
):
    monkeypatch.setattr(collector.socket, "gethostname", lambda: "technocore-resident")
    monkeypatch.setattr(
        collector, "_repo_status",
        lambda: (_ for _ in ()).throw(ValueError("unexpected_branch")),
    )
    monkeypatch.setattr(
        collector, "_sample",
        lambda: (_ for _ in ()).throw(AssertionError("no_60sec_probe")),
    )
    assert collector.main() == 2
    verdict = json.loads(capsys.readouterr().out)
    assert verdict == {
        "decision": "NO_GO", "restart_authorized": False,
        "stage": "REPO", "samples_taken": 0, "reasons": ["unexpected_branch"]
    }


def test_samples_fail_stage_and_count_after_two_samples(monkeypatch, capsys):
    monkeypatch.setattr(collector.socket, "gethostname", lambda: "technocore-resident")
    monkeypatch.setattr(collector, "_repo_status", lambda: (collector.OLD_HEAD, True))
    monkeypatch.setattr(collector.time, "monotonic", lambda: 0)
    monkeypatch.setattr(collector.time, "sleep", lambda n: None)
    call_count = [0]

    def sample():
        call_count[0] += 1
        if call_count[0] > 2:
            raise ValueError("missing_full_psi")
        return {"at": "synthetic"}

    monkeypatch.setattr(collector, "_sample", sample)
    assert collector.main() == 2
    verdict = json.loads(capsys.readouterr().out)
    assert verdict["stage"] == "SAMPLES"
    assert verdict["samples_taken"] == 2
    assert verdict["reasons"] == ["missing_full_psi"]
    assert verdict["restart_authorized"] is False


def test_rich_failure_identifies_phase_without_raw_error(monkeypatch, capsys):
    monkeypatch.setattr(collector.socket, "gethostname", lambda: "technocore-resident")
    monkeypatch.setattr(collector, "_repo_status", lambda: (collector.OLD_HEAD, True))
    monkeypatch.setattr(collector, "SAMPLES", 1)
    monkeypatch.setattr(collector.time, "monotonic", lambda: 0)
    monkeypatch.setattr(collector, "_sample", lambda: {"at": "fake"})
    monkeypatch.setattr(
        collector, "_rich",
        lambda: (_ for _ in ()).throw(ValueError("missing_rich_fields")),
    )
    assert collector.main() == 2
    verdict = json.loads(capsys.readouterr().out)
    assert verdict["stage"] == "RICH"
    assert verdict["samples_taken"] == 1
    assert verdict["reasons"] == ["missing_rich_fields"]


def test_sensitive_unexpected_exception_is_redacted(monkeypatch, capsys):
    monkeypatch.setattr(collector.socket, "gethostname", lambda: "technocore-resident")
    monkeypatch.setattr(
        collector, "_repo_status",
        lambda: (_ for _ in ()).throw(ValueError("secret-operator-path")),
    )
    assert collector.main() == 2
    out = capsys.readouterr().out
    assert "secret-operator-path" not in out
    verdict = json.loads(out)
    assert verdict["stage"] == "REPO"
    assert verdict["reasons"] == ["unclassified_failure"]
    assert verdict["restart_authorized"] is False


def test_run_command_does_not_use_shell_and_discards_errors(monkeypatch):
    commands = []
    def fake_subprocess_run(args, **kwargs):
        commands.append((args, kwargs))
        return subprocess.CompletedProcess(args, 1, "", "sensitive stderr")
    monkeypatch.setattr(collector.subprocess, "run", fake_subprocess_run)
    with pytest.raises(ValueError, match="read_only_command_failed"):
        collector._run(["git", "status"])
    assert commands[0][1]["env"]["GIT_OPTIONAL_LOCKS"] == "0"
    assert "shell" not in commands[0][1]
