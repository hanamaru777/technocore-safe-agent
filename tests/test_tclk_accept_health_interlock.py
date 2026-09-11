import pytest

from flop_agent import tclk_pilot_accept


STAGE_ID = "1" * 32
NOW = 2_000_000_000_000


def observer_state(*, health="ok", events=117, messages=5_083_155):
    return {
        "health": {"current": health},
        "metrics": {
            "unrecoverable_core_gap_events": events,
            "unrecoverable_core_gap_messages": messages,
        },
    }


def test_interlock_rejects_degraded_and_protected_core_mismatch(monkeypatch):
    monkeypatch.setattr(
        tclk_pilot_accept.observer,
        "load_state",
        lambda: observer_state(health="degraded"),
    )
    with pytest.raises(tclk_pilot_accept.AcceptError, match="observer_health_not_ok"):
        tclk_pilot_accept._require_write_interlock()

    monkeypatch.setattr(
        tclk_pilot_accept.observer,
        "load_state",
        lambda: observer_state(events=118),
    )
    with pytest.raises(tclk_pilot_accept.AcceptError, match="protected_core_baseline_changed"):
        tclk_pilot_accept._require_write_interlock()

    monkeypatch.setattr(
        tclk_pilot_accept.observer,
        "load_state",
        lambda: observer_state(messages=5_083_156),
    )
    with pytest.raises(tclk_pilot_accept.AcceptError, match="protected_core_baseline_changed"):
        tclk_pilot_accept._require_write_interlock()


def test_degraded_state_blocks_before_any_new_accept_preparation(monkeypatch):
    monkeypatch.setattr(tclk_pilot_accept, "_load_state", lambda _stage_id: None)
    monkeypatch.setattr(
        tclk_pilot_accept.observer,
        "load_state",
        lambda: observer_state(health="degraded"),
    )
    monkeypatch.setattr(
        tclk_pilot_accept,
        "_exact_prepared",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not revalidate or sign")),
    )
    monkeypatch.setattr(
        tclk_pilot_accept,
        "_post_once",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not post")),
    )

    with pytest.raises(tclk_pilot_accept.AcceptError, match="observer_health_not_ok"):
        tclk_pilot_accept.accept_stage(STAGE_ID, now_ms=NOW)


def test_second_interlock_blocks_post_if_health_changes_after_signature_preparation(monkeypatch):
    states = iter([observer_state(), observer_state(health="degraded")])
    monkeypatch.setattr(tclk_pilot_accept.observer, "load_state", lambda: next(states))
    monkeypatch.setattr(tclk_pilot_accept, "_load_state", lambda _stage_id: None)

    stage = {"expires_ms": NOW + 600_000}
    preview = {"accept_line": "tclk1 {\"type\":\"accept\"}"}
    approval = {"approval_digest": "a" * 64}
    monkeypatch.setattr(
        tclk_pilot_accept,
        "_exact_prepared",
        lambda *_a, **_k: (stage, preview, approval, {}),
    )

    prepared_calls = []
    prepared = {"state": "prepared", "accept_line": preview["accept_line"]}
    monkeypatch.setattr(
        tclk_pilot_accept,
        "_new_prepared_state",
        lambda *_a, **_k: prepared_calls.append(1) or prepared,
    )
    monkeypatch.setattr(tclk_pilot_accept, "_save_state", lambda *_a, **_k: None)
    post_calls = []
    monkeypatch.setattr(
        tclk_pilot_accept,
        "_post_once",
        lambda *_a, **_k: post_calls.append(1),
    )

    with pytest.raises(tclk_pilot_accept.AcceptError, match="observer_health_not_ok"):
        tclk_pilot_accept.accept_stage(STAGE_ID, now_ms=NOW)

    assert prepared_calls == [1]
    assert post_calls == []
    assert prepared["state"] == "prepared"


def test_healthy_exact_baseline_preserves_one_shot_mocked_post_flow(monkeypatch):
    monkeypatch.setattr(tclk_pilot_accept.observer, "load_state", lambda: observer_state())
    monkeypatch.setattr(tclk_pilot_accept, "_load_state", lambda _stage_id: None)

    stage = {"expires_ms": NOW + 600_000}
    preview = {"accept_line": "tclk1 {\"type\":\"accept\"}"}
    approval = {"approval_digest": "a" * 64}
    monkeypatch.setattr(
        tclk_pilot_accept,
        "_exact_prepared",
        lambda *_a, **_k: (stage, preview, approval, {}),
    )
    prepared = {"state": "prepared", "accept_line": preview["accept_line"]}
    monkeypatch.setattr(tclk_pilot_accept, "_new_prepared_state", lambda *_a, **_k: prepared)
    monkeypatch.setattr(tclk_pilot_accept, "_save_state", lambda *_a, **_k: None)

    post_calls = []
    response = object()
    monkeypatch.setattr(
        tclk_pilot_accept,
        "_post_once",
        lambda *_a, **_k: post_calls.append(1) or response,
    )
    matched = {"seq": 7, "ts": "2033-05-18T03:33:22Z"}
    monkeypatch.setattr(tclk_pilot_accept, "_validate_transport_response", lambda *_a, **_k: matched)

    def mark_posted(value, _line, _matched):
        value["state"] = "posted"
        return value

    monkeypatch.setattr(tclk_pilot_accept, "_mark_posted", mark_posted)
    result = tclk_pilot_accept.accept_stage(STAGE_ID, now_ms=NOW)

    assert result["action"] == "posted"
    assert result["state"]["state"] == "posted"
    assert post_calls == [1]


def test_ambiguous_reconciliation_and_posted_idempotency_bypass_new_write_gate(monkeypatch):
    ambiguous = {"state": "ambiguous", "accept_line": "tclk1 {}"}
    monkeypatch.setattr(tclk_pilot_accept, "_load_state", lambda _stage_id: ambiguous)
    monkeypatch.setattr(
        tclk_pilot_accept.observer,
        "load_state",
        lambda: (_ for _ in ()).throw(AssertionError("reconciliation must remain read-only available")),
    )
    monkeypatch.setattr(
        tclk_pilot_accept,
        "_reconcile",
        lambda value, _line: {"action": "ambiguous", "state": value},
    )
    assert tclk_pilot_accept.accept_stage(STAGE_ID, now_ms=NOW)["action"] == "ambiguous"

    posted = {"state": "posted"}
    monkeypatch.setattr(tclk_pilot_accept, "_load_state", lambda _stage_id: posted)
    assert tclk_pilot_accept.accept_stage(STAGE_ID, now_ms=NOW)["action"] == "already_posted"
