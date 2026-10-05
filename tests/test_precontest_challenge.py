from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import (
    airdrop_challenge,
    core,
    precontest_challenge,
    precontest_readiness,
)


NOW = datetime(2026, 10, 1, 0, 0, tzinfo=UTC)
DEADLINE = NOW + timedelta(days=7)
COMMIT = "1" * 40


@pytest.fixture
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    # These legacy strict-planner tests focus on readiness semantics other than
    # the new plumbing receipt.  Model an already-validated receipt overlay so
    # the original assertions remain scoped; dedicated plumbing tests cover
    # missing/invalid receipts separately.
    monkeypatch.setattr(
        precontest_challenge.precontest_plumbing_apply,
        "apply_if_present",
        lambda challenge_id, now=None: {"status": "APPLIED"},
    )
    return tmp_path


def create_legacy_ready_challenge():
    airdrop_challenge.create_challenge(
        {
            "challenge_id": "future-challenge",
            "opening": NOW.isoformat(),
            "deadline": DEADLINE.isoformat(),
            "prize": {"amount": 1, "unit": "FLOP"},
            "eligibility": {"status": "known"},
            "submission": {"path": "official"},
            "collaboration_required": False,
            "registration_required": False,
            "source": {
                "rules_url": (
                    "https://raw.githubusercontent.com/flop-labs/example-challenge/"
                    f"{COMMIT}/rules.md"
                ),
                "authority_type": "flop_labs_github",
                "authority_id": "authority",
                "pinned_commit": COMMIT,
                "source_sha256": "2" * 64,
            },
            "required_artifacts": [],
            "notes": [],
        },
        now=NOW,
    )
    airdrop_challenge.update_progress(
        "future-challenge",
        {"rules_authority_pinned": True},
        now=NOW,
    )


def evidence(**patch):
    value = {
        "schema_version": 1,
        "challenge_id": "future-challenge",
        "measured_at": NOW.isoformat(),
        "campaign_deadline": DEADLINE.isoformat(),
        "capture_to_executor_ms": 2_000,
        "requires_chat_relay": False,
        "requires_user_terminal": False,
        "control_paths": [
            {
                "id": "primary",
                "authenticated": True,
                "ready": True,
                "quota_independent": False,
                "verified_at": NOW.isoformat(),
            },
            {
                "id": "backup",
                "authenticated": True,
                "ready": True,
                "quota_independent": True,
                "verified_at": NOW.isoformat(),
            },
        ],
        "execution_modes_required": ["single"],
        "execution_modes_rehearsed": ["single"],
        "reconciliation_cases_rehearsed": [
            "settled", "void", "ambiguous", "redacted"
        ],
        "runtime_deadline_guard": True,
        "post_deadline_fail_closed": True,
        "first_leg_policy_predefined": True,
        "first_leg_risk_bounded": True,
        "zero_trade_deadlock_prevented": True,
        "execution_plumbing_complete": True,
        "production_rehearsal_passed": True,
        "live_plumbing_changes_required": False,
    }
    value.update(patch)
    return value


def test_missing_readiness_is_no_go_but_legacy_planner_stays_compatible(isolated_state):
    create_legacy_ready_challenge()
    legacy = airdrop_challenge.build_plan("future-challenge", now=NOW)
    strict = precontest_challenge.build_plan("future-challenge", now=NOW)
    assert legacy["ready_for_execution_path"] is True
    assert strict["ready_for_execution_path"] is False
    assert strict["precontest_gate_enforced"] is True
    assert strict["precontest_readiness"]["status"] == "NO_GO"
    assert "PRECONTEST_READINESS_EVIDENCE_MISSING" in strict["critical_path"]


def test_go_evidence_allows_legacy_ready_plan(isolated_state):
    create_legacy_ready_challenge()
    precontest_readiness.save_evidence("future-challenge", evidence())
    strict = precontest_challenge.build_plan("future-challenge", now=NOW)
    assert strict["precontest_readiness"]["status"] == "GO"
    assert strict["ready_for_execution_path"] is True
    assert "precontest_readiness_no_go" not in strict["critical_path"]


def test_no_go_evidence_overrides_legacy_ready_plan(isolated_state):
    create_legacy_ready_challenge()
    precontest_readiness.save_evidence(
        "future-challenge",
        evidence(requires_chat_relay=True),
    )
    strict = precontest_challenge.build_plan("future-challenge", now=NOW)
    assert strict["ready_for_execution_path"] is False
    assert strict["precontest_readiness"]["gates"]["HUMAN_INDEPENDENCE_GATE"] is False
    assert "precontest_readiness_no_go" in strict["critical_path"]
    assert "HUMAN_INDEPENDENCE_GATE" in strict["critical_path"]


def test_tampered_readiness_fails_closed_in_strict_plan(isolated_state):
    create_legacy_ready_challenge()
    precontest_readiness.save_evidence("future-challenge", evidence())
    path = precontest_readiness._path("future-challenge")
    raw = json.loads(path.read_text("utf-8"))
    raw["capture_to_executor_ms"] = 1
    path.write_text(json.dumps(raw), encoding="utf-8")

    strict = precontest_challenge.build_plan("future-challenge", now=NOW)
    assert strict["ready_for_execution_path"] is False
    assert strict["precontest_readiness"]["status"] == "NO_GO"
    assert "precontest_readiness_integrity_invalid" in strict["critical_path"]


def test_strict_go_never_removes_legacy_blocker(isolated_state):
    create_legacy_ready_challenge()
    airdrop_challenge.update_progress(
        "future-challenge",
        {"rules_authority_pinned": False},
        now=NOW,
    )
    precontest_readiness.save_evidence("future-challenge", evidence())
    strict = precontest_challenge.build_plan("future-challenge", now=NOW)
    assert strict["precontest_readiness"]["status"] == "GO"
    assert strict["ready_for_execution_path"] is False
    assert "rules_authority_pinned" in strict["critical_path"]
