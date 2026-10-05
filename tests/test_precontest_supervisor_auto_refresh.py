import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from flop_agent import airdrop_ledger
from flop_agent import precontest_supervisor as supervisor


NOW = datetime(2026, 10, 5, 6, 0, tzinfo=UTC)
CHALLENGE = "auto-refresh-test"


def _profile(configured_at=NOW - timedelta(minutes=1)):
    return {
        "schema_version": 1,
        "challenge_id": CHALLENGE,
        "runtime_profile": "close1_short_liquidity",
        "configured_at": configured_at.isoformat(),
        "profile_sha256": "a" * 64,
    }


def _fresh_rehearsal(evaluated_at=NOW):
    return {
        "evaluated_at": evaluated_at.isoformat(),
        "capture_to_rehearsal_ms": 1000,
    }


def test_missing_profile_does_not_call_any_proof_or_collector(monkeypatch):
    monkeypatch.setattr(supervisor.precontest_runtime_profile, "load", lambda challenge_id: None)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("proof automation must not run without explicit profile")

    monkeypatch.setattr(supervisor.precontest_deadline_proof, "save_proof", forbidden)
    monkeypatch.setattr(supervisor.precontest_active_learning_proof, "save_proof", forbidden)
    monkeypatch.setattr(supervisor.precontest_reconciliation_proof, "save_proof", forbidden)
    monkeypatch.setattr(supervisor.precontest_batch_rehearsal_proof, "save_proof", forbidden)
    monkeypatch.setattr(supervisor.precontest_machine_evidence, "collect", forbidden)

    assert supervisor._refresh_safe_proofs(CHALLENGE, now=NOW) == []


def test_explicit_profile_refreshes_all_safe_proofs_then_collector(monkeypatch):
    calls = []
    monkeypatch.setattr(supervisor.precontest_runtime_profile, "load", lambda challenge_id: _profile())
    monkeypatch.setattr(
        supervisor.precontest_machine_evidence,
        "_fresh_rehearsal",
        lambda now: _fresh_rehearsal(),
    )

    def proof(label):
        def run(challenge_id, now=None):
            calls.append(label)
            return {"status": "PASS"}
        return run

    monkeypatch.setattr(supervisor.precontest_deadline_proof, "save_proof", proof("deadline"))
    monkeypatch.setattr(supervisor.precontest_active_learning_proof, "save_proof", proof("active"))
    monkeypatch.setattr(supervisor.precontest_reconciliation_proof, "save_proof", proof("reconciliation"))
    monkeypatch.setattr(supervisor.precontest_batch_rehearsal_proof, "save_proof", proof("batch"))

    def collect(challenge_id, now=None):
        calls.append("collector")
        return {"status": "COLLECTED_NO_GO"}

    monkeypatch.setattr(supervisor.precontest_machine_evidence, "collect", collect)

    blockers = supervisor._refresh_safe_proofs(CHALLENGE, now=NOW)

    assert blockers == []
    assert calls == ["deadline", "active", "reconciliation", "batch", "collector"]


def test_rehearsal_predating_profile_never_runs_collector(monkeypatch):
    calls = []
    monkeypatch.setattr(supervisor.precontest_runtime_profile, "load", lambda challenge_id: _profile(configured_at=NOW))
    monkeypatch.setattr(
        supervisor.precontest_machine_evidence,
        "_fresh_rehearsal",
        lambda now: _fresh_rehearsal(evaluated_at=NOW - timedelta(seconds=1)),
    )

    def proof(challenge_id, now=None):
        calls.append("proof")
        return {"status": "PASS"}

    monkeypatch.setattr(supervisor.precontest_deadline_proof, "save_proof", proof)
    monkeypatch.setattr(supervisor.precontest_active_learning_proof, "save_proof", proof)
    monkeypatch.setattr(supervisor.precontest_reconciliation_proof, "save_proof", proof)
    monkeypatch.setattr(supervisor.precontest_batch_rehearsal_proof, "save_proof", proof)

    def forbidden_collect(*_args, **_kwargs):
        raise AssertionError("old single rehearsal must not be collected for new profile")

    monkeypatch.setattr(supervisor.precontest_machine_evidence, "collect", forbidden_collect)

    blockers = supervisor._refresh_safe_proofs(CHALLENGE, now=NOW)

    assert blockers == ["precontest_auto_single_rehearsal_predates_profile"]
    assert len(calls) == 4


def test_individual_proof_and_collector_failures_become_fixed_blockers(monkeypatch):
    monkeypatch.setattr(supervisor.precontest_runtime_profile, "load", lambda challenge_id: _profile())
    monkeypatch.setattr(
        supervisor.precontest_machine_evidence,
        "_fresh_rehearsal",
        lambda now: _fresh_rehearsal(),
    )
    monkeypatch.setattr(
        supervisor.precontest_deadline_proof,
        "save_proof",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("upstream detail")),
    )
    monkeypatch.setattr(supervisor.precontest_active_learning_proof, "save_proof", lambda *a, **k: {})
    monkeypatch.setattr(supervisor.precontest_reconciliation_proof, "save_proof", lambda *a, **k: {})
    monkeypatch.setattr(supervisor.precontest_batch_rehearsal_proof, "save_proof", lambda *a, **k: {})
    monkeypatch.setattr(
        supervisor.precontest_machine_evidence,
        "collect",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("private collector detail")),
    )

    blockers = supervisor._refresh_safe_proofs(CHALLENGE, now=NOW)

    assert blockers == [
        "precontest_auto_deadline_proof_blocked",
        "precontest_auto_machine_evidence_blocked",
    ]
    assert all("detail" not in blocker for blocker in blockers)


def _spec(challenge_id: str, *, deadline: datetime) -> dict:
    return {
        "schema_version": 1,
        "challenge_id": challenge_id,
        "opening": (deadline - timedelta(hours=2)).isoformat(),
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


def test_closed_challenge_never_refreshes_proofs(tmp_path, monkeypatch):
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)
    _write_spec(tmp_path, _spec(CHALLENGE, deadline=NOW - timedelta(seconds=1)))

    def forbidden(*_args, **_kwargs):
        raise AssertionError("closed challenge must not refresh proof artifacts")

    monkeypatch.setattr(supervisor, "_refresh_safe_proofs", forbidden)
    monkeypatch.setattr(supervisor.precontest_challenge, "build_plan", forbidden)

    result = supervisor.build_status(now=NOW)

    assert result["status"] == "IDLE"
    assert result["challenges"][0]["status"] == "CLOSED"


def test_refresh_blocker_prevents_false_ready(tmp_path, monkeypatch):
    deadline = NOW + timedelta(hours=1)
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)
    _write_spec(tmp_path, _spec(CHALLENGE, deadline=deadline))
    monkeypatch.setattr(
        supervisor,
        "_refresh_safe_proofs",
        lambda challenge_id, now: ["precontest_auto_deadline_proof_blocked"],
    )
    monkeypatch.setattr(
        supervisor.precontest_challenge,
        "build_plan",
        lambda challenge_id, now=None: {
            "ready_for_execution_path": True,
            "critical_path": [],
            "precontest_readiness": {"status": "GO"},
        },
    )

    result = supervisor.build_status(now=NOW)

    row = result["challenges"][0]
    assert row["ready"] is False
    assert row["status"] == "BLOCKED_LIVE"
    assert row["blockers"] == ["precontest_auto_deadline_proof_blocked"]
