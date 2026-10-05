import json
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import airdrop_challenge
from flop_agent import airdrop_ledger
from flop_agent import close_call
from flop_agent import precontest_challenge
from flop_agent import precontest_runtime_compatibility as compatibility
from flop_agent import precontest_runtime_profile
from flop_agent import precontest_supervisor


NOW = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)
CHALLENGE = "runtime-compat-test"


def _spec(*, commit=compatibility.FROZEN_REFEREE_COMMIT, deadline=None, authority="flop_labs_github"):
    deadline = deadline or close_call.LOCK
    return {
        "schema_version": 1,
        "challenge_id": CHALLENGE,
        "opening": close_call.OPENING.isoformat(),
        "deadline": deadline.isoformat(),
        "prize": None,
        "eligibility": {},
        "submission": {},
        "collaboration_required": False,
        "registration_required": False,
        "source": {
            "rules_url": (
                "https://raw.githubusercontent.com/flop-labs/"
                f"technocore-close-call-challenge/{commit}/rules.md"
            ),
            "authority_type": authority,
            "authority_id": None,
            "pinned_commit": commit,
            "source_sha256": None,
        },
        "required_artifacts": [],
        "notes": [],
    }


def _setup(tmp_path, monkeypatch, *, spec=None):
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)
    airdrop_challenge.create_challenge(spec or _spec(), now=NOW)
    precontest_runtime_profile.save(CHALLENGE, compatibility.PROFILE, now=NOW)


def test_exact_frozen_close1_adapter_is_compatible(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)

    proof = compatibility.save_proof(CHALLENGE, now=NOW)
    valid = compatibility.load_validated(CHALLENGE, now=NOW)

    assert proof["status"] == "PASS"
    assert proof["reason"] == "compatible"
    assert valid == proof
    assert proof["runtime_profile"] == compatibility.PROFILE
    assert proof["campaign_deadline"] == close_call.LOCK.isoformat()
    assert proof["spec_pinned_commit"] == compatibility.FROZEN_REFEREE_COMMIT
    assert proof["rules_url_commit"] == compatibility.FROZEN_REFEREE_COMMIT
    assert proof["adapter_bindings"]["runtime_lock"] == close_call.LOCK.isoformat()
    assert proof["adapter_bindings"]["frozen_rules_repo"] == "flop-labs/technocore-close-call-challenge"
    assert proof["adapter_bindings"]["frozen_rules_commit"] == compatibility.FROZEN_REFEREE_COMMIT
    assert len(proof["proof_sha256"]) == 64


def test_different_rules_commit_is_explicit_no_go(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch, spec=_spec(commit="1" * 40))

    proof = compatibility.save_proof(CHALLENGE, now=NOW)
    valid = compatibility.load_validated(CHALLENGE, now=NOW)

    assert proof["status"] == "NO_GO"
    assert proof["reason"] == "pinned_commit_mismatch"
    assert valid["status"] == "NO_GO"


def test_launch_authority_commit_cannot_substitute_for_frozen_rules_commit(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch, spec=_spec(commit=close_call.OFFICIAL_REPO_COMMIT))

    proof = compatibility.build_proof(CHALLENGE, now=NOW)

    assert proof["status"] == "NO_GO"
    assert proof["reason"] == "pinned_commit_mismatch"
    assert proof["adapter_bindings"]["launch_repo_commit"] == close_call.OFFICIAL_REPO_COMMIT
    assert proof["adapter_bindings"]["frozen_rules_commit"] == compatibility.FROZEN_REFEREE_COMMIT


def test_different_deadline_is_explicit_no_go(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch, spec=_spec(deadline=close_call.LOCK + timedelta(days=7)))

    proof = compatibility.build_proof(CHALLENGE, now=NOW)

    assert proof["status"] == "NO_GO"
    assert proof["reason"] == "deadline_mismatch"


def test_tamper_and_source_drift_fail_closed(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    proof = compatibility.build_proof(CHALLENGE, now=NOW)

    tampered = json.loads(json.dumps(proof))
    tampered["status"] = "NO_GO"
    with pytest.raises(compatibility.RuntimeCompatibilityError, match="proof_integrity_invalid"):
        compatibility.validate_proof(tampered, challenge_id=CHALLENGE, now=NOW)

    original_bindings = compatibility._bindings()
    changed = dict(original_bindings)
    changed["resident_cycle_sha256"] = "0" * 64
    monkeypatch.setattr(compatibility, "_bindings", lambda: changed)
    with pytest.raises(compatibility.RuntimeCompatibilityError, match="source_changed"):
        compatibility.validate_proof(proof, challenge_id=CHALLENGE, now=NOW)


def test_stale_proof_fails_closed(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    old = NOW - timedelta(hours=25)
    proof = compatibility.build_proof(CHALLENGE, now=old)

    with pytest.raises(compatibility.RuntimeCompatibilityError, match="proof_stale"):
        compatibility.validate_proof(proof, challenge_id=CHALLENGE, now=NOW)


def test_supervisor_incompatible_adapter_stops_all_downstream_refresh(monkeypatch):
    profile = {
        "runtime_profile": precontest_supervisor.CLOSE1_PROFILE,
        "configured_at": NOW.isoformat(),
    }
    monkeypatch.setattr(precontest_supervisor.precontest_runtime_profile, "load", lambda challenge_id: profile)
    monkeypatch.setattr(
        precontest_supervisor.precontest_runtime_compatibility,
        "save_proof",
        lambda challenge_id, now=None: {"status": "NO_GO", "reason": "deadline_mismatch"},
    )

    called = []
    for module, name in (
        (precontest_supervisor.precontest_deadline_proof, "deadline"),
        (precontest_supervisor.precontest_active_learning_proof, "active"),
        (precontest_supervisor.precontest_reconciliation_proof, "reconciliation"),
        (precontest_supervisor.precontest_batch_rehearsal_proof, "batch"),
        (precontest_supervisor.precontest_control_path_proof, "control"),
        (precontest_supervisor.precontest_human_independence_proof, "human"),
    ):
        monkeypatch.setattr(module, "save_proof", lambda *args, _name=name, **kwargs: called.append(_name))
    monkeypatch.setattr(
        precontest_supervisor.precontest_machine_evidence,
        "collect",
        lambda *args, **kwargs: called.append("collector"),
    )
    monkeypatch.setattr(
        precontest_supervisor.precontest_plumbing_receipt,
        "save_receipt",
        lambda *args, **kwargs: called.append("plumbing"),
    )

    blockers = precontest_supervisor._refresh_safe_proofs(CHALLENGE, now=NOW)

    assert blockers == ["precontest_runtime_adapter_incompatible"]
    assert called == []


def test_strict_planner_independently_blocks_incompatible_adapter(monkeypatch):
    legacy = {
        "challenge_id": CHALLENGE,
        "deadline": (NOW + timedelta(days=1)).isoformat(),
        "critical_path": [],
        "warnings": [],
        "ready_for_execution_path": True,
    }
    monkeypatch.setattr(precontest_challenge.airdrop_challenge, "build_plan", lambda challenge_id, now=None: legacy)
    monkeypatch.setattr(
        precontest_challenge,
        "_runtime_profile_status",
        lambda challenge_id: (True, {"runtime_profile": compatibility.PROFILE}, None),
    )
    monkeypatch.setattr(
        precontest_challenge,
        "_runtime_compatibility_status",
        lambda challenge_id, now: (False, "precontest_runtime_adapter_incompatible"),
    )

    plumbing_calls = []
    monkeypatch.setattr(
        precontest_challenge.precontest_plumbing_apply,
        "apply_if_present",
        lambda *args, **kwargs: plumbing_calls.append(True),
    )

    result = precontest_challenge.build_plan(CHALLENGE, now=NOW)

    assert result["ready_for_execution_path"] is False
    assert result["precontest_readiness"]["go"] is False
    assert "precontest_runtime_adapter_incompatible" in result["critical_path"]
    assert plumbing_calls == []
