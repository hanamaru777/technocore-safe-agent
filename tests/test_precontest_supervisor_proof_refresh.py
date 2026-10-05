from datetime import UTC, datetime, timedelta

from flop_agent import precontest_supervisor as supervisor


NOW = datetime(2026, 10, 5, 8, 35, tzinfo=UTC)
CHALLENGE = "supervisor-proof-refresh-test"


def _profile(configured_at):
    return {
        "schema_version": 1,
        "challenge_id": CHALLENGE,
        "runtime_profile": supervisor.CLOSE1_PROFILE,
        "configured_at": configured_at.isoformat(),
        "profile_sha256": "1" * 64,
    }


def _install_builders(monkeypatch, calls, *, failing=None):
    builders = [
        ("deadline", supervisor.precontest_deadline_proof),
        ("active_learning", supervisor.precontest_active_learning_proof),
        ("reconciliation", supervisor.precontest_reconciliation_proof),
        ("batch", supervisor.precontest_batch_rehearsal_proof),
        ("control_path", supervisor.precontest_control_path_proof),
        ("human_independence", supervisor.precontest_human_independence_proof),
    ]
    for label, module in builders:
        def save(challenge_id, now=None, *, _label=label):
            calls.append((_label, challenge_id, now))
            if _label == failing:
                raise RuntimeError("proof failed")
            # NO_GO is a valid proof result for missing real-world receipts.
            return {"status": "NO_GO" if _label in {"control_path", "human_independence"} else "PASS"}
        monkeypatch.setattr(module, "save_proof", save)


def test_profiled_fresh_rehearsal_refreshes_all_proofs_and_collector(monkeypatch):
    calls = []
    configured = NOW - timedelta(minutes=5)
    monkeypatch.setattr(supervisor.precontest_runtime_profile, "load", lambda challenge_id: _profile(configured))
    monkeypatch.setattr(
        supervisor.precontest_machine_evidence,
        "_fresh_rehearsal",
        lambda now: {"evaluated_at": (NOW - timedelta(seconds=1)).isoformat()},
    )
    _install_builders(monkeypatch, calls)
    collected = []
    monkeypatch.setattr(
        supervisor.precontest_machine_evidence,
        "collect",
        lambda challenge_id, now=None: collected.append((challenge_id, now)) or {"status": "COLLECTED_NO_GO"},
    )

    blockers = supervisor._refresh_safe_proofs(CHALLENGE, now=NOW)

    assert blockers == []
    assert [row[0] for row in calls] == [
        "deadline",
        "active_learning",
        "reconciliation",
        "batch",
        "control_path",
        "human_independence",
    ]
    assert collected == [(CHALLENGE, NOW)]


def test_missing_receipt_no_go_proofs_are_not_refresh_failures(monkeypatch):
    calls = []
    monkeypatch.setattr(
        supervisor.precontest_runtime_profile,
        "load",
        lambda challenge_id: _profile(NOW - timedelta(minutes=10)),
    )
    monkeypatch.setattr(
        supervisor.precontest_machine_evidence,
        "_fresh_rehearsal",
        lambda now: {"evaluated_at": NOW.isoformat()},
    )
    _install_builders(monkeypatch, calls)
    monkeypatch.setattr(
        supervisor.precontest_machine_evidence,
        "collect",
        lambda challenge_id, now=None: {"status": "COLLECTED_NO_GO"},
    )

    blockers = supervisor._refresh_safe_proofs(CHALLENGE, now=NOW)

    assert blockers == []
    assert ("control_path", CHALLENGE, NOW) in calls
    assert ("human_independence", CHALLENGE, NOW) in calls


def test_builder_failure_is_named_blocker_and_never_silent(monkeypatch):
    calls = []
    monkeypatch.setattr(
        supervisor.precontest_runtime_profile,
        "load",
        lambda challenge_id: _profile(NOW - timedelta(minutes=10)),
    )
    monkeypatch.setattr(
        supervisor.precontest_machine_evidence,
        "_fresh_rehearsal",
        lambda now: {"evaluated_at": NOW.isoformat()},
    )
    _install_builders(monkeypatch, calls, failing="human_independence")
    monkeypatch.setattr(
        supervisor.precontest_machine_evidence,
        "collect",
        lambda challenge_id, now=None: {"status": "COLLECTED_NO_GO"},
    )

    blockers = supervisor._refresh_safe_proofs(CHALLENGE, now=NOW)

    assert "precontest_auto_human_independence_proof_blocked" in blockers


def test_profile_predating_rehearsal_prevents_collector_but_still_refreshes_safe_proofs(monkeypatch):
    calls = []
    monkeypatch.setattr(
        supervisor.precontest_runtime_profile,
        "load",
        lambda challenge_id: _profile(NOW - timedelta(minutes=1)),
    )
    monkeypatch.setattr(
        supervisor.precontest_machine_evidence,
        "_fresh_rehearsal",
        lambda now: {"evaluated_at": (NOW - timedelta(minutes=2)).isoformat()},
    )
    _install_builders(monkeypatch, calls)

    def should_not_collect(*_args, **_kwargs):
        raise AssertionError("collector must not use a rehearsal older than profile configuration")

    monkeypatch.setattr(supervisor.precontest_machine_evidence, "collect", should_not_collect)

    blockers = supervisor._refresh_safe_proofs(CHALLENGE, now=NOW)

    assert "precontest_auto_single_rehearsal_predates_profile" in blockers
    assert [row[0] for row in calls][-2:] == ["control_path", "human_independence"]


def test_missing_profile_remains_explicit_noop(monkeypatch):
    monkeypatch.setattr(supervisor.precontest_runtime_profile, "load", lambda challenge_id: None)

    assert supervisor._refresh_safe_proofs(CHALLENGE, now=NOW) == []
