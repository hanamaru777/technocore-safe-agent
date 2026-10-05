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
            return {"status": "NO_GO" if _label in {"control_path", "human_independence"} else "PASS"}
        monkeypatch.setattr(module, "save_proof", save)


def _stub_plumbing(monkeypatch, calls=None, *, fail=False):
    def save(challenge_id, now=None):
        if calls is not None:
            calls.append(("plumbing", challenge_id, now))
        if fail:
            raise RuntimeError("plumbing unavailable")
        return {"status": "PASS", "non_binding": True}
    monkeypatch.setattr(supervisor.precontest_plumbing_receipt, "save_receipt", save)


def test_profiled_fresh_rehearsal_refreshes_all_proofs_collector_then_plumbing(monkeypatch):
    calls = []
    configured = NOW - timedelta(minutes=5)
    monkeypatch.setattr(supervisor.precontest_runtime_profile, "load", lambda challenge_id: _profile(configured))
    monkeypatch.setattr(
        supervisor.precontest_machine_evidence,
        "_fresh_rehearsal",
        lambda now: {"evaluated_at": (NOW - timedelta(seconds=1)).isoformat()},
    )
    _install_builders(monkeypatch, calls)
    monkeypatch.setattr(
        supervisor.precontest_machine_evidence,
        "collect",
        lambda challenge_id, now=None: calls.append(("collector", challenge_id, now)) or {"status": "COLLECTED_NO_GO"},
    )
    _stub_plumbing(monkeypatch, calls)

    blockers = supervisor._refresh_safe_proofs(CHALLENGE, now=NOW)

    assert blockers == []
    assert [row[0] for row in calls] == [
        "deadline",
        "active_learning",
        "reconciliation",
        "batch",
        "control_path",
        "human_independence",
        "collector",
        "plumbing",
    ]


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
    _stub_plumbing(monkeypatch)

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
    _stub_plumbing(monkeypatch)

    blockers = supervisor._refresh_safe_proofs(CHALLENGE, now=NOW)

    assert "precontest_auto_human_independence_proof_blocked" in blockers


def test_collector_failure_skips_plumbing_and_is_named_blocker(monkeypatch):
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

    def fail_collect(challenge_id, now=None):
        calls.append(("collector", challenge_id, now))
        raise RuntimeError("collector failed")

    monkeypatch.setattr(supervisor.precontest_machine_evidence, "collect", fail_collect)

    def forbidden_plumbing(*_args, **_kwargs):
        raise AssertionError("plumbing receipt must not run after collector failure")

    monkeypatch.setattr(supervisor.precontest_plumbing_receipt, "save_receipt", forbidden_plumbing)

    blockers = supervisor._refresh_safe_proofs(CHALLENGE, now=NOW)

    assert "precontest_auto_machine_evidence_blocked" in blockers


def test_plumbing_failure_after_collector_is_named_blocker(monkeypatch):
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
        lambda challenge_id, now=None: calls.append(("collector", challenge_id, now)) or {"status": "COLLECTED_NO_GO"},
    )
    _stub_plumbing(monkeypatch, calls, fail=True)

    blockers = supervisor._refresh_safe_proofs(CHALLENGE, now=NOW)

    assert calls[-2][0] == "collector"
    assert calls[-1][0] == "plumbing"
    assert "precontest_auto_plumbing_receipt_blocked" in blockers


def test_profile_predating_rehearsal_prevents_collector_and_plumbing(monkeypatch):
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
    monkeypatch.setattr(
        supervisor.precontest_plumbing_receipt,
        "save_receipt",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("plumbing must not run without collector")),
    )

    blockers = supervisor._refresh_safe_proofs(CHALLENGE, now=NOW)

    assert "precontest_auto_single_rehearsal_predates_profile" in blockers
    assert [row[0] for row in calls][-2:] == ["control_path", "human_independence"]


def test_valid_plumbing_receipt_does_not_override_other_plan_blockers(monkeypatch):
    monkeypatch.setattr(supervisor, "_refresh_safe_proofs", lambda challenge_id, now: [])
    monkeypatch.setattr(
        supervisor.precontest_challenge,
        "build_plan",
        lambda challenge_id, now=None: {
            "ready_for_execution_path": False,
            "critical_path": ["HUMAN_INDEPENDENCE_GATE"],
            "precontest_readiness": {"status": "NO_GO"},
        },
    )
    spec = {
        "challenge_id": CHALLENGE,
        "deadline": (NOW + timedelta(hours=2)).isoformat(),
        "opening": (NOW + timedelta(hours=1)).isoformat(),
    }

    row = supervisor._challenge_row(spec, now=NOW)

    assert row["ready"] is False
    assert row["status"] == "ACTION_REQUIRED"
    assert "HUMAN_INDEPENDENCE_GATE" in row["blockers"]


def test_missing_profile_remains_explicit_noop(monkeypatch):
    monkeypatch.setattr(supervisor.precontest_runtime_profile, "load", lambda challenge_id: None)

    assert supervisor._refresh_safe_proofs(CHALLENGE, now=NOW) == []
