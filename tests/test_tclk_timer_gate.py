import json
import sys
from pathlib import Path

import pytest

from flop_agent import core, tclk_timer_gate


NOW = 2_000_000_000_000
STAGE_ID = "1" * 32
OFFER_ID = "0x" + "2" * 64
FRAME = "3" * 64
ACCEPT_LINE = 'tclk1 {"type":"accept"}'


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def _stage(*, expires_ms=NOW + 900_000):
    return {
        "stage_id": STAGE_ID,
        "offer_id": OFFER_ID,
        "frame_sha256": FRAME,
        "expires_ms": expires_ms,
    }


def _review(*, expires_ms=NOW + 900_000):
    return {
        "offer_id": OFFER_ID,
        "frame_sha256": FRAME,
        "expires_ms": expires_ms,
        "accepted": False,
    }


def test_gate_module_is_stdlib_only():
    source = (core.ROOT / "src" / "flop_agent" / "tclk_timer_gate.py").read_text("utf-8")
    assert "from . import" not in source
    assert "import httpx" not in source
    assert "import requests" not in source
    assert "subprocess" not in source


def test_stager_skips_without_live_review_evidence_and_runs_for_new_live_evidence(tmp_path):
    assert tclk_timer_gate.should_run("stager", root=tmp_path, now_ms=NOW) is False

    evidence = tmp_path / "resident" / "tclk-review-evidence.json"
    _write(evidence, {"schema_version": 1, "records": [_review(expires_ms=NOW + 299_999)]})
    assert tclk_timer_gate.should_run("stager", root=tmp_path, now_ms=NOW) is False

    _write(evidence, {"schema_version": 1, "records": [_review()]})
    assert tclk_timer_gate.should_run("stager", root=tmp_path, now_ms=NOW) is True

    _write(tmp_path / "autopilot" / "tclk-pilot" / "stages" / f"{STAGE_ID}.json", _stage())
    assert tclk_timer_gate.should_run("stager", root=tmp_path, now_ms=NOW) is True


def test_preparer_runs_only_for_live_unprepared_or_incomplete_stage(tmp_path):
    stage_path = tmp_path / "autopilot" / "tclk-pilot" / "stages" / f"{STAGE_ID}.json"
    _write(stage_path, _stage())
    assert tclk_timer_gate.should_run("preparer", root=tmp_path, now_ms=NOW) is True

    preview = tmp_path / "autopilot" / "tclk-pilot" / "previews" / f"{STAGE_ID}.json"
    material_file = tmp_path / "signer" / "tclk-pilot-secrets" / f"{STAGE_ID}.json"
    _write(preview, {"ok": True})
    assert tclk_timer_gate.should_run("preparer", root=tmp_path, now_ms=NOW) is True

    _write(material_file, {"opaque": "not-inspected-by-gate"})
    assert tclk_timer_gate.should_run("preparer", root=tmp_path, now_ms=NOW) is False

    _write(stage_path, _stage(expires_ms=NOW + 119_999))
    preview.unlink()
    material_file.unlink()
    assert tclk_timer_gate.should_run("preparer", root=tmp_path, now_ms=NOW) is False


def test_lock_runs_only_after_matching_posted_accept_activity(tmp_path):
    preview = tmp_path / "autopilot" / "tclk-pilot" / "previews" / f"{STAGE_ID}.json"
    _write(preview, {"accept_line": ACCEPT_LINE})
    assert tclk_timer_gate.should_run("lock", root=tmp_path, now_ms=NOW) is False

    activities = tmp_path / "activities.jsonl"
    activities.write_text(
        json.dumps({"action": "something_else", "text": ACCEPT_LINE}) + "\n",
        encoding="utf-8",
    )
    assert tclk_timer_gate.should_run("lock", root=tmp_path, now_ms=NOW) is False

    activities.write_text(
        json.dumps({"action": "tclk_first_pilot_accept", "text": ACCEPT_LINE}) + "\n",
        encoding="utf-8",
    )
    assert tclk_timer_gate.should_run("lock", root=tmp_path, now_ms=NOW) is True

    _write(tmp_path / "autopilot" / "tclk-pilot" / "locks" / f"{STAGE_ID}.json", {"status": "lock_verified"})
    assert tclk_timer_gate.should_run("lock", root=tmp_path, now_ms=NOW) is False


def test_work_gate_uses_lock_then_work_file_existence(tmp_path):
    lock = tmp_path / "autopilot" / "tclk-pilot" / "locks" / f"{STAGE_ID}.json"
    _write(lock, {"status": "lock_verified"})
    assert tclk_timer_gate.should_run("work", root=tmp_path, now_ms=NOW) is True

    _write(tmp_path / "autopilot" / "tclk-pilot" / "work" / f"{STAGE_ID}.json", {"status": "work_ready"})
    assert tclk_timer_gate.should_run("work", root=tmp_path, now_ms=NOW) is False


def test_reveal_runs_only_for_work_ready_without_public_preview(tmp_path):
    work = tmp_path / "autopilot" / "tclk-pilot" / "work" / f"{STAGE_ID}.json"
    _write(work, {"status": "work_failed"})
    assert tclk_timer_gate.should_run("reveal", root=tmp_path, now_ms=NOW) is False

    _write(work, {"status": "work_ready"})
    assert tclk_timer_gate.should_run("reveal", root=tmp_path, now_ms=NOW) is True

    _write(tmp_path / "autopilot" / "tclk-pilot" / "reveal-previews" / f"{STAGE_ID}.json", {"status": "prepared"})
    assert tclk_timer_gate.should_run("reveal", root=tmp_path, now_ms=NOW) is True

    private = tmp_path / "signer" / "tclk-pilot-reveals" / f"{STAGE_ID}.json"
    _write(private, {"private": "opaque"})
    private.chmod(0o600)
    assert tclk_timer_gate.should_run("reveal", root=tmp_path, now_ms=NOW) is False


def test_malformed_state_fails_open_in_cli(monkeypatch, tmp_path):
    evidence = tmp_path / "resident" / "tclk-review-evidence.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("{broken", encoding="utf-8")
    monkeypatch.setenv("FLOP_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["tclk_timer_gate", "stager"])
    with pytest.raises(SystemExit) as error:
        tclk_timer_gate.main()
    assert error.value.code == 0


def test_large_activity_history_fails_open_instead_of_missing_old_accept(monkeypatch, tmp_path):
    preview = tmp_path / "autopilot" / "tclk-pilot" / "previews" / f"{STAGE_ID}.json"
    _write(preview, {"accept_line": ACCEPT_LINE})
    activities = tmp_path / "activities.jsonl"
    activities.write_bytes(b"x" * (tclk_timer_gate.MAX_ACTIVITY_TAIL_BYTES + 1))
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


def test_existing_corrupt_completion_state_fails_open(monkeypatch, tmp_path):
    lock = tmp_path / "autopilot" / "tclk-pilot" / "locks" / f"{STAGE_ID}.json"
    _write(lock, {"status": "wrong"})
    monkeypatch.setenv("FLOP_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["tclk_timer_gate", "work"])
    with pytest.raises(SystemExit) as error:
        tclk_timer_gate.main()
    assert error.value.code == 0
