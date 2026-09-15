from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import sonnet_nonbinding_policy as policy


def snapshot(*, health="ok", age=10, core=(117, 5_083_155)):
    return {
        "schema_version": 1,
        "updated_at": (datetime.now(UTC) - timedelta(seconds=age)).isoformat(),
        "health": health,
        "unrecoverable_core_gap_events": core[0],
        "unrecoverable_core_gap_messages": core[1],
    }


def test_nonbinding_allows_fresh_degraded_state(monkeypatch):
    monkeypatch.setattr(
        policy.registration,
        "load_safety_snapshot",
        lambda: snapshot(health="degraded", age=30),
    )
    result = policy.require_nonbinding_safety()
    assert result["health"] == "degraded"
    assert result["protected_core_gap_events"] == 117
    assert result["protected_core_gap_messages"] == 5_083_155


def test_nonbinding_allows_fresh_ok_state(monkeypatch):
    monkeypatch.setattr(
        policy.registration,
        "load_safety_snapshot",
        lambda: snapshot(health="ok", age=30),
    )
    assert policy.require_nonbinding_safety()["health"] == "ok"


def test_nonbinding_rejects_core_change(monkeypatch):
    monkeypatch.setattr(
        policy.registration,
        "load_safety_snapshot",
        lambda: snapshot(core=(118, 5_083_155)),
    )
    with pytest.raises(policy.NonBindingPolicyError, match="protected_core_baseline_changed"):
        policy.require_nonbinding_safety()


def test_nonbinding_rejects_stale_snapshot(monkeypatch):
    monkeypatch.setattr(
        policy.registration,
        "load_safety_snapshot",
        lambda: snapshot(age=policy.MAX_SAFETY_AGE_SECONDS + 1),
    )
    with pytest.raises(policy.NonBindingPolicyError, match="nonbinding_safety_stale"):
        policy.require_nonbinding_safety()


def test_nonbinding_rejects_unknown_health(monkeypatch):
    monkeypatch.setattr(
        policy.registration,
        "load_safety_snapshot",
        lambda: snapshot(health="unknown"),
    )
    with pytest.raises(policy.NonBindingPolicyError, match="nonbinding_safety_invalid_health"):
        policy.require_nonbinding_safety()


def test_binding_policy_stays_strict(monkeypatch):
    calls = []
    monkeypatch.setattr(policy.registration, "require_health", lambda: calls.append("strict"))
    policy.require_binding_safety()
    assert calls == ["strict"]
