from __future__ import annotations

from flop_agent import airdrop_notifier as base
from flop_agent import airdrop_notifier_compact as compact


def _payload(**overrides) -> dict:
    value = {
        "event_id": "event-1234567890",
        "severity": "HIGH",
        "key": "registration_status",
        "source": "yellowpaper",
        "source_url": "https://flop.finance/intro/yellowpaper/",
        "authority": "normative",
        "tier": 1,
        "before": "closed",
        "after": "open",
        "deadline": None,
        "safe_next_step": "Review the official evidence; do not take binding action without approval.",
    }
    value.update(overrides)
    return value


def _item(event_id: str, *, key: str = "registration_status") -> dict:
    return {
        "payload": _payload(
            event_id=event_id,
            severity="MEDIUM",
            key=key,
            source_url=None,
        )
    }


def _assert_compact(text: str) -> list[str]:
    lines = text.splitlines()
    assert len(lines) <= 6
    assert sum(line.startswith("次:") for line in lines) == 1
    assert any(line.startswith("影響:") for line in lines)
    assert any(line.startswith("状態:") for line in lines)
    assert len(text) <= base.MAX_CONTENT
    return lines


def test_immediate_alert_is_action_first_and_keeps_safe_next_step():
    text = compact.render_alert(_payload())
    lines = _assert_compact(text)
    assert lines[0].startswith("🟠 FLOP Airdrop:")
    assert '"closed" → "open"' in text
    assert "yellowpaper / Tier 1 / normative" in text
    assert "次: Review the official evidence" in text
    assert "公式: https://flop.finance/intro/yellowpaper/" in text


def test_medium_alert_is_warning_and_mentions_are_neutralized():
    text = compact.render_alert(
        _payload(
            severity="MEDIUM",
            key="@everyone registration",
            before="@here",
            after="<@123456789>",
        )
    )
    lines = _assert_compact(text)
    assert lines[0].startswith("⚠️ ")
    assert "@everyone" not in text
    assert "@here" not in text
    assert "<@123456789>" not in text
    assert "＠everyone" in text


def test_digest_preserves_original_selected_event_ids_exactly():
    items = [
        _item("medium-a", key="github_interest_repo_names"),
        _item("medium-b", key="registration_status"),
    ]
    _legacy_text, legacy_selected = compact._ORIGINAL_RENDER_DIGEST(items)
    text, selected = compact.render_digest(items)
    _assert_compact(text)
    assert selected == legacy_selected
    assert selected == ["medium-a", "medium-b"]
    assert "MEDIUM更新 2件" in text


def test_health_problem_and_recovery_are_compact_and_non_binding():
    status = {
        "outcome": "scan_failed",
        "last_completed_at": "2026-10-04T23:00:00+00:00",
        "heartbeat_stale": False,
        "staging_outcome": "ok",
    }
    problem = compact.render_health_problem(status)
    _assert_compact(problem)
    assert problem.startswith("⚠️ FLOP Airdrop Radar監視異常")
    assert "次: FLOPへの操作はせず、自動回復を待つ" in problem

    recovery = compact.render_health_recovery(status)
    _assert_compact(recovery)
    assert recovery.startswith("✅ FLOP Airdrop Radar監視復旧")
    assert "次: 対応不要" in recovery


def test_readiness_ready_transition_is_action_but_not_authorization():
    previous = {
        "overall": "BLOCKED",
        "actions": {
            "faucet": {"state": "BLOCKED", "blockers": ["canonical_open_event_missing"]},
            "registration": {"state": "BLOCKED", "blockers": ["missing_fact:registration_status"]},
            "claim": {"state": "BLOCKED", "blockers": ["claim_path_unresolved"]},
        },
    }
    current = {
        "overall": "BLOCKED",
        "actions": {
            "faucet": {"state": "IMPLEMENTATION_READY", "blockers": []},
            "registration": {"state": "BLOCKED", "blockers": ["missing_fact:registration_status"]},
            "claim": {"state": "BLOCKED", "blockers": ["claim_path_unresolved"]},
        },
    }
    text = compact.render_readiness_change(previous, current)
    _assert_compact(text)
    assert text.startswith("🟠 FLOP Adapter Readiness: IMPLEMENTATION_READY")
    assert "IMPLEMENTATION_READYは実行許可ではありません" in text
    assert "次: 実行せず、別監査と承認を待つ" in text
    assert "外部writeは別の監査と承認が必要" in text


def test_readiness_blocker_only_change_is_warning_and_no_action():
    previous = {
        "overall": "BLOCKED",
        "actions": {
            "faucet": {"state": "BLOCKED", "blockers": ["a", "b"]},
            "registration": {"state": "BLOCKED", "blockers": ["c"]},
            "claim": {"state": "BLOCKED", "blockers": ["d"]},
        },
    }
    current = {
        "overall": "BLOCKED",
        "actions": {
            "faucet": {"state": "BLOCKED", "blockers": ["b"]},
            "registration": {"state": "BLOCKED", "blockers": ["c"]},
            "claim": {"state": "BLOCKED", "blockers": ["d"]},
        },
    }
    text = compact.render_readiness_change(previous, current)
    _assert_compact(text)
    assert text.startswith("⚠️ FLOP Adapter Readiness 更新")
    assert "解消: a" in text
    assert "次: 対応不要。公式条件の更新を待つ" in text


def test_install_changes_only_render_hooks_and_preserves_run_once(monkeypatch):
    original_run_once = base.run_once
    original = {
        "render_alert": base.render_alert,
        "render_digest": base.render_digest,
        "health_problem": base._render_health_problem,
        "health_recovery": base._render_health_recovery,
        "readiness": base._render_readiness_change,
    }
    old_installed = compact._INSTALLED
    monkeypatch.setattr(compact, "_INSTALLED", False)
    try:
        compact.install()
        assert base.run_once is original_run_once
        assert base.render_alert is compact.render_alert
        assert base.render_digest is compact.render_digest
        assert base._render_health_problem is compact.render_health_problem
        assert base._render_health_recovery is compact.render_health_recovery
        assert base._render_readiness_change is compact.render_readiness_change
    finally:
        base.render_alert = original["render_alert"]
        base.render_digest = original["render_digest"]
        base._render_health_problem = original["health_problem"]
        base._render_health_recovery = original["health_recovery"]
        base._render_readiness_change = original["readiness"]
        compact._INSTALLED = old_installed
