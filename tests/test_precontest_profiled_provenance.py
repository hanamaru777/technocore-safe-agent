from datetime import UTC, datetime, timedelta

from flop_agent import precontest_challenge
from flop_agent import precontest_machine_provenance
from flop_agent import precontest_runtime_profile


NOW = datetime(2026, 10, 5, 6, 50, tzinfo=UTC)
DEADLINE = NOW + timedelta(days=1)
EVIDENCE_SHA = "1" * 64


def _legacy():
    return {
        "challenge_id": "proof",
        "deadline": DEADLINE.isoformat(),
        "critical_path": [],
        "estimated_remaining_steps": 0,
        "ready_for_execution_path": True,
        "warnings": [],
    }


def _readiness(*, go=True):
    return {
        "schema_version": 1,
        "challenge_id": "proof",
        "non_binding": True,
        "status": "GO" if go else "NO_GO",
        "go": go,
        "evaluated_at": NOW.isoformat(),
        "evidence_sha256": EVIDENCE_SHA,
        "gates": {},
        "blockers": [] if go else ["HUMAN_INDEPENDENCE_GATE"],
        "warning": "proof",
    }


def _profile(monkeypatch):
    monkeypatch.setattr(
        precontest_challenge.precontest_runtime_profile,
        "load",
        lambda challenge_id: {
            "schema_version": 1,
            "challenge_id": challenge_id,
            "runtime_profile": "close1_short_liquidity",
            "configured_at": NOW.isoformat(),
            "profile_sha256": "2" * 64,
        },
    )
    monkeypatch.setattr(
        precontest_challenge.precontest_plumbing_apply,
        "apply_if_present",
        lambda challenge_id, now=None: {"status": "APPLIED"},
    )
    monkeypatch.setattr(
        precontest_challenge.airdrop_challenge,
        "build_plan",
        lambda challenge_id, now=None: _legacy(),
    )


def test_profiled_missing_machine_provenance_is_no_go(monkeypatch):
    _profile(monkeypatch)
    monkeypatch.setattr(
        precontest_challenge.precontest_readiness,
        "evaluate_saved",
        lambda *args, **kwargs: _readiness(),
    )

    def missing(*args, **kwargs):
        raise precontest_machine_provenance.MachineProvenanceError(
            "precontest_machine_provenance_missing"
        )

    monkeypatch.setattr(
        precontest_challenge.precontest_machine_provenance,
        "load_validated",
        missing,
    )

    result = precontest_challenge.build_plan("proof", now=NOW)

    assert result["ready_for_execution_path"] is False
    assert result["machine_provenance_required"] is True
    assert result["machine_provenance_valid"] is False
    assert "precontest_machine_provenance_invalid" in result["critical_path"]
    assert "precontest_machine_provenance_missing" in result["critical_path"]


def test_profiled_fresh_matching_provenance_can_preserve_go(monkeypatch):
    _profile(monkeypatch)
    monkeypatch.setattr(
        precontest_challenge.precontest_readiness,
        "evaluate_saved",
        lambda *args, **kwargs: _readiness(),
    )
    calls = []

    def valid(challenge_id, *, readiness_evidence_sha256, now, require_no_unsupported):
        calls.append((challenge_id, readiness_evidence_sha256, now, require_no_unsupported))
        return {"unsupported_gates_forced_no_go": []}

    monkeypatch.setattr(
        precontest_challenge.precontest_machine_provenance,
        "load_validated",
        valid,
    )

    result = precontest_challenge.build_plan("proof", now=NOW)

    assert calls == [("proof", EVIDENCE_SHA, NOW, True)]
    assert result["ready_for_execution_path"] is True
    assert result["machine_provenance_required"] is True
    assert result["machine_provenance_valid"] is True


def test_profiled_no_go_provenance_may_explain_remaining_unsupported_gates(monkeypatch):
    _profile(monkeypatch)
    monkeypatch.setattr(
        precontest_challenge.precontest_readiness,
        "evaluate_saved",
        lambda *args, **kwargs: _readiness(go=False),
    )
    required_flags = []

    def valid(challenge_id, *, readiness_evidence_sha256, now, require_no_unsupported):
        required_flags.append(require_no_unsupported)
        return {"unsupported_gates_forced_no_go": ["HUMAN_INDEPENDENCE_GATE"]}

    monkeypatch.setattr(
        precontest_challenge.precontest_machine_provenance,
        "load_validated",
        valid,
    )

    result = precontest_challenge.build_plan("proof", now=NOW)

    assert required_flags == [False]
    assert result["ready_for_execution_path"] is False
    assert result["machine_provenance_valid"] is True
    assert "HUMAN_INDEPENDENCE_GATE" in result["critical_path"]


def test_invalid_runtime_profile_fails_closed_without_plumbing_or_provenance(monkeypatch):
    monkeypatch.setattr(
        precontest_challenge.airdrop_challenge,
        "build_plan",
        lambda challenge_id, now=None: _legacy(),
    )

    def invalid_profile(challenge_id):
        raise precontest_runtime_profile.RuntimeProfileError(
            "precontest_runtime_profile_integrity_invalid"
        )

    monkeypatch.setattr(
        precontest_challenge.precontest_runtime_profile,
        "load",
        invalid_profile,
    )
    monkeypatch.setattr(
        precontest_challenge.precontest_plumbing_apply,
        "apply_if_present",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("invalid profile must fail before plumbing")
        ),
    )

    result = precontest_challenge.build_plan("proof", now=NOW)

    assert result["ready_for_execution_path"] is False
    assert result["machine_provenance_required"] is True
    assert result["machine_provenance_valid"] is False
    assert "precontest_runtime_profile_invalid" in result["critical_path"]
