import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from flop_agent import airdrop_ledger, precontest_supervisor as supervisor


ROOT = Path(__file__).resolve().parents[1]


def _spec(challenge_id: str, *, opening: datetime | None, deadline: datetime) -> dict:
    return {
        "schema_version": 1,
        "challenge_id": challenge_id,
        "opening": opening.isoformat() if opening else None,
        "deadline": deadline.isoformat(),
        "prize": None,
        "eligibility": {},
        "submission": {},
        "collaboration_required": False,
        "registration_required": False,
        "source": {
            "rules_url": "https://flop.finance/teaser/",
            "authority_type": "flop_site",
            "authority_id": None,
            "pinned_commit": None,
            "source_sha256": None,
        },
        "required_artifacts": [],
        "notes": [],
    }


def _write_spec(root: Path, value: dict) -> None:
    directory = root / "challenges" / value["challenge_id"]
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "spec.json").write_text(json.dumps(value), encoding="utf-8")


def _plan(challenge_id: str, *, ready: bool, deadline: datetime) -> dict:
    return {
        "challenge_id": challenge_id,
        "deadline": deadline.isoformat(),
        "ready_for_execution_path": ready,
        "critical_path": [] if ready else ["precontest_readiness_no_go", "CONTROL_PATH_REDUNDANCY_GATE"],
        "precontest_readiness": {"status": "GO" if ready else "NO_GO"},
    }


def test_upcoming_within_72h_requires_action(tmp_path, monkeypatch):
    now = datetime(2026, 10, 5, 3, 0, tzinfo=UTC)
    opening = now + timedelta(hours=24)
    deadline = opening + timedelta(hours=6)
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)
    _write_spec(tmp_path, _spec("next-contest", opening=opening, deadline=deadline))
    monkeypatch.setattr(
        supervisor.precontest_challenge,
        "build_plan",
        lambda challenge_id, now=None: _plan(challenge_id, ready=False, deadline=deadline),
    )

    result = supervisor.build_status(now=now)

    assert result["status"] == "ACTION_REQUIRED"
    assert result["challenge_count"] == 1
    row = result["challenges"][0]
    assert row["phase"] == "UPCOMING"
    assert row["status"] == "ACTION_REQUIRED"
    assert row["ready"] is False
    assert row["seconds_to_open"] == 24 * 3600
    assert "CONTROL_PATH_REDUNDANCY_GATE" in row["blockers"]


def test_upcoming_more_than_72h_is_prep_required(tmp_path, monkeypatch):
    now = datetime(2026, 10, 5, 3, 0, tzinfo=UTC)
    opening = now + timedelta(days=5)
    deadline = opening + timedelta(hours=6)
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)
    _write_spec(tmp_path, _spec("future-contest", opening=opening, deadline=deadline))
    monkeypatch.setattr(
        supervisor.precontest_challenge,
        "build_plan",
        lambda challenge_id, now=None: _plan(challenge_id, ready=False, deadline=deadline),
    )

    result = supervisor.build_status(now=now)

    assert result["status"] == "PREP_REQUIRED"
    assert result["challenges"][0]["status"] == "PREP_REQUIRED"


def test_open_no_go_is_blocked_live(tmp_path, monkeypatch):
    now = datetime(2026, 10, 5, 3, 0, tzinfo=UTC)
    deadline = now + timedelta(hours=3)
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)
    _write_spec(tmp_path, _spec("live-contest", opening=now - timedelta(hours=1), deadline=deadline))
    monkeypatch.setattr(
        supervisor.precontest_challenge,
        "build_plan",
        lambda challenge_id, now=None: _plan(challenge_id, ready=False, deadline=deadline),
    )

    result = supervisor.build_status(now=now)

    assert result["status"] == "BLOCKED_LIVE"
    row = result["challenges"][0]
    assert row["phase"] == "OPEN"
    assert row["status"] == "BLOCKED_LIVE"


def test_ready_future_challenge_is_ready(tmp_path, monkeypatch):
    now = datetime(2026, 10, 5, 3, 0, tzinfo=UTC)
    opening = now + timedelta(hours=12)
    deadline = opening + timedelta(hours=6)
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)
    _write_spec(tmp_path, _spec("ready-contest", opening=opening, deadline=deadline))
    monkeypatch.setattr(
        supervisor.precontest_challenge,
        "build_plan",
        lambda challenge_id, now=None: _plan(challenge_id, ready=True, deadline=deadline),
    )

    result = supervisor.build_status(now=now)

    assert result["status"] == "READY"
    assert result["challenges"][0]["ready"] is True
    assert result["challenges"][0]["blockers"] == []


def test_closed_challenge_is_silent_closed_without_planner(tmp_path, monkeypatch):
    now = datetime(2026, 10, 5, 3, 0, tzinfo=UTC)
    deadline = now - timedelta(seconds=1)
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)
    _write_spec(tmp_path, _spec("closed-contest", opening=now - timedelta(hours=3), deadline=deadline))

    def should_not_run(*_args, **_kwargs):
        raise AssertionError("planner should not run for closed challenge")

    monkeypatch.setattr(supervisor.precontest_challenge, "build_plan", should_not_run)

    result = supervisor.build_status(now=now)

    assert result["status"] == "IDLE"
    assert result["challenges"][0]["status"] == "CLOSED"
    assert result["challenges"][0]["blockers"] == []


def test_missing_opening_is_conservatively_open(tmp_path, monkeypatch):
    now = datetime(2026, 10, 5, 3, 0, tzinfo=UTC)
    deadline = now + timedelta(days=1)
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)
    _write_spec(tmp_path, _spec("unknown-opening", opening=None, deadline=deadline))
    monkeypatch.setattr(
        supervisor.precontest_challenge,
        "build_plan",
        lambda challenge_id, now=None: _plan(challenge_id, ready=False, deadline=deadline),
    )

    result = supervisor.build_status(now=now)

    assert result["status"] == "BLOCKED_LIVE"
    assert result["challenges"][0]["phase"] == "OPEN"


def test_run_once_persists_durable_local_state(tmp_path, monkeypatch):
    now = datetime(2026, 10, 5, 3, 0, tzinfo=UTC)
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)

    result = supervisor.run_once(now=now)

    saved = json.loads((tmp_path / "precontest-supervisor.json").read_text("utf-8"))
    assert saved == result
    assert saved["non_binding"] is True
    assert saved["status"] == "IDLE"


def test_packaging_is_low_pressure_and_nonprivileged():
    service = (
        ROOT / "packaging/oracle/technocore-safe-agent-precontest-supervisor.service"
    ).read_text("utf-8")
    timer = (
        ROOT / "packaging/oracle/technocore-safe-agent-precontest-supervisor.timer"
    ).read_text("utf-8")

    assert "User=technocore" in service
    assert "Group=technocore-autopilot" in service
    assert "precontest_supervisor" in service
    assert "NoNewPrivileges=true" in service
    assert "MemoryMax=128M" in service
    assert "ReadWritePaths=/var/lib/technocore-safe-agent/airdrop-radar" in service
    assert "signer.env" not in service
    assert "technocore-signer" not in service
    assert "vault" not in service.lower()
    assert "OnUnitActiveSec=10min" in timer
    assert "RandomizedDelaySec=30s" in timer
    assert "Persistent=true" in timer
