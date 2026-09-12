from datetime import UTC, datetime, timedelta

from flop_agent import core, discord_health_coalescing as coalescing


RED_DEGRADED = (
    "🔴 FLOP Agent 異常\n\n"
    "監視状態 degraded が5分以上継続しています。\n"
    "最終正常監視の確認: 1分前\n\n"
    "次にやること: /status"
)
RED_STALE = (
    "🔴 FLOP Agent 異常\n\n"
    "最終監視 3分前\n"
    "最終正常監視の確認: 3分前\n\n"
    "次にやること: /status"
)
GREEN = (
    "🟢 FLOP Agent 監視復旧\n\n"
    "Observer監視状態が正常へ戻りました。\n"
    "結論: 対応不要。そのまま稼働中。"
)


def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setattr(coalescing, "_ORIGINAL_SYSTEM_NOTICES", lambda _control: [])
    monkeypatch.setattr(coalescing, "_healthy_now", lambda: False)


def raw(monkeypatch, notices):
    monkeypatch.setattr(
        coalescing,
        "_ORIGINAL_SYSTEM_NOTICES",
        lambda _control: list(notices),
    )


def test_repeated_same_red_is_coalesced(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    raw(monkeypatch, [RED_DEGRADED])
    assert coalescing._coalesced_system_notices(object()) == [RED_DEGRADED]
    assert coalescing._coalesced_system_notices(object()) == []
    state = coalescing._load_state()
    assert state["incident_open"] is True
    assert state["seen_red_signatures"] == ["監視状態 degraded が5分以上継続しています。"]


def test_new_failure_class_is_not_hidden_inside_open_incident(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    raw(monkeypatch, [RED_DEGRADED])
    coalescing._coalesced_system_notices(object())
    raw(monkeypatch, [RED_STALE])
    assert coalescing._coalesced_system_notices(object()) == [RED_STALE]
    assert len(coalescing._load_state()["seen_red_signatures"]) == 2


def test_first_green_is_suppressed_until_five_minutes_stable(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    raw(monkeypatch, [RED_DEGRADED])
    coalescing._coalesced_system_notices(object())

    monkeypatch.setattr(coalescing, "_healthy_now", lambda: True)
    raw(monkeypatch, [GREEN])
    assert coalescing._coalesced_system_notices(object()) == []
    state = coalescing._load_state()
    assert state["incident_open"] is True
    assert state["recovery_since"] is not None

    state["recovery_since"] = (
        datetime.now(UTC) - coalescing.RECOVERY_GRACE - timedelta(seconds=1)
    ).isoformat()
    coalescing._save_state(state)
    raw(monkeypatch, [])
    notices = coalescing._coalesced_system_notices(object())
    assert len(notices) == 1
    assert notices[0].startswith("🟢 FLOP Agent 復旧")
    assert "5分間安定" in notices[0]
    assert coalescing._load_state()["incident_open"] is False


def test_redegrade_during_recovery_grace_keeps_one_incident_open(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    raw(monkeypatch, [RED_DEGRADED])
    coalescing._coalesced_system_notices(object())

    monkeypatch.setattr(coalescing, "_healthy_now", lambda: True)
    raw(monkeypatch, [GREEN])
    assert coalescing._coalesced_system_notices(object()) == []
    assert coalescing._load_state()["recovery_since"] is not None

    monkeypatch.setattr(coalescing, "_healthy_now", lambda: False)
    raw(monkeypatch, [RED_DEGRADED])
    assert coalescing._coalesced_system_notices(object()) == []
    state = coalescing._load_state()
    assert state["incident_open"] is True
    assert state["recovery_since"] is None


def test_non_health_notice_passes_through_unchanged(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    notice = "🟡 FLOP Agent 通信欠落を複数検出\n未通知gap: +3"
    raw(monkeypatch, [notice])
    assert coalescing._coalesced_system_notices(object()) == [notice]


def test_service_entrypoint_uses_health_coalescing_wrapper():
    text = (core.ROOT / "packaging" / "oracle" / "discord.service").read_text("utf-8")
    assert "-m flop_agent.discord_health_coalescing" in text
    assert "discord_tclk_approval" not in text
