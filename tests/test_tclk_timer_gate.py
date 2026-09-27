import json
import sys
from pathlib import Path

import pytest

from flop_agent import core, tclk_timer_gate


NOW = 2_000_000_000_000
STAGE_ID = "1" * 32


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def test_gate_module_is_stdlib_only():
    source = (core.ROOT / "src" / "flop_agent" / "tclk_timer_gate.py").read_text("utf-8")
    assert "from . import" not in source
    assert "import httpx" not in source
    assert "import requests" not in source
    assert "subprocess" not in source


def test_stager_skips_missing_or_expired_review_evidence_and_runs_live(tmp_path):
    assert tclk_timer_gate.should_run("stager", root=tmp_path, now_ms=NOW) is False
    path = tmp_path / "resident" / "tclk-review-evidence.json"
    _write(
        path,
        {
            "schema_version": 1,
            "records": [{"expires_ms": NOW + 299_999, "accepted": False}],
        },
    )
    assert tclk_timer_gate.should_run("stager", root=tmp_path, now_ms=NOW) is False
    _write(
        path,
        {
            "schema_version": 1,
            "records": [{"expires_ms": NOW + 300_000, "accepted": False}],
        },
    )
    assert tclk_timer_gate.should_run("stager", root=tmp_path, now_ms=NOW) is True


def test_preparer_skips_no_or_expired_stage_and_runs_any_live_stage(tmp_path):
    assert tclk_timer_gate.should_run("preparer", root=tmp_path, now_ms=NOW) is False
    stage = tmp_path / "autopilot" / "tclk-pilot" / "stages" / f"{STAGE_ID}.json"
    _write(stage, {"expires_ms": NOW + 119_999})
    assert tclk_timer_gate.should_run("preparer", root=tmp_path, now_ms=NOW) is False
    _write(stage, {"expires_ms": NOW + 120_000})
    assert tclk_timer_gate.should_run("preparer", root=tmp_path, now_ms=NOW) is True


@pytest.mark.parametrize(
    ("mode", "relative"),
    [
        ("lock", ("autopilot", "tclk-pilot", "previews")),
        ("work", ("autopilot", "tclk-pilot", "locks")),
        ("reveal", ("autopilot", "tclk-pilot", "work")),
    ],
)
def test_downstream_gate_only_skips_when_prerequisite_directory_is_empty(tmp_path, mode, relative):
    assert tclk_timer_gate.should_run(mode, root=tmp_path, now_ms=NOW) is False
    prereq = tmp_path.joinpath(*relative) / f"{STAGE_ID}.json"
    _write(prereq, {"intentionally": "not-validated-by-light-gate"})
    assert tclk_timer_gate.should_run(mode, root=tmp_path, now_ms=NOW) is True


@pytest.mark.parametrize("mode", ["stager", "preparer"])
def test_malformed_json_fails_open_in_cli(monkeypatch, tmp_path, mode):
    if mode == "stager":
        path = tmp_path / "resident" / "tclk-review-evidence.json"
    else:
        path = tmp_path / "autopilot" / "tclk-pilot" / "stages" / f"{STAGE_ID}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{broken", encoding="utf-8")
    monkeypatch.setenv("FLOP_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["tclk_timer_gate", mode])
    with pytest.raises(SystemExit) as error:
        tclk_timer_gate.main()
    assert error.value.code == 0


def test_unexpected_prerequisite_filename_fails_open(monkeypatch, tmp_path):
    path = tmp_path / "autopilot" / "tclk-pilot" / "previews" / "unexpected.json"
    _write(path, {"anything": True})
    monkeypatch.setenv("FLOP_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["tclk_timer_gate", "lock"])
    with pytest.raises(SystemExit) as error:
        tclk_timer_gate.main()
    assert error.value.code == 0


@pytest.mark.parametrize(
    ("unit", "mode"),
    [
        ("technocore-safe-agent-tclk-stager.service", "stager"),
        ("technocore-safe-agent-tclk-preparer.service", "preparer"),
        ("technocore-safe-agent-tclk-lock-watcher.service", "lock"),
        ("technocore-safe-agent-tclk-work-watcher.service", "work"),
        ("technocore-safe-agent-tclk-reveal-preparer.service", "reveal"),
    ],
)
def test_tclk_periodic_services_have_lightweight_exec_condition(unit, mode):
    source = (core.ROOT / "packaging" / "oracle" / unit).read_text("utf-8")
    expected = (
        "ExecCondition=/opt/technocore-safe-agent/.venv/bin/python "
        f"-m flop_agent.tclk_timer_gate {mode}"
    )
    assert expected in source
    assert source.index("ExecCondition=") < source.index("ExecStart=")
