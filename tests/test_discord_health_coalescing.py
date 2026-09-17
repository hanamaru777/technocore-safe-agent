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
RED_AUTOPILOT_OFF = (
    "🔴 FLOP Agent 異常\n\n"
    "Autopilot OFF\n"
    "最終正常監視の確認: 2分前\n\n"
    "次にやること: /status"
)
GREEN = (
    "🟢 FLOP Agent 監視復旧\n\n"
    "Observer監視状態が正常へ戻りました。\n"
    "結論: 対応不要。そのまま稼働中。"
)
YELLOW_GAP = (
    "🟡 FLOP Agent 通信欠落を複数検出\n\n"
    "未通知gap: +3\n"
    "最終監視: 1分前\n"
    "単発gapは6時間レポートへ集約し、連続時だけ通知しています。\n"
    "次にやること: /status"
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


def test_repeated_same_red_is_coalesced_and_humanized(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    raw(monkeypatch, [RED_DEGRADED])
    notices = coalescing._coalesced_system_notices(object())
    assert len(notices) == 1
    assert notices[0].startswith("🔴 監視が不安定")
    assert "今やること: 基本は待機" in notices[0]
    assert "監視データが5分以上、不安定" in notices[0]
    assert "必要なら: `/status` で詳細確認" in notices[0]
    assert "degraded" not in notices[0]
    assert coalescing._coalesced_system_notices(object()) == []
    state = coalescing._load_state()
    assert state["incident_open"] is True
    assert state["seen_red_signatures"] == ["監視状態 degraded が5分以上継続しています。"]


def test_new_failure_class_is_not_hidden_inside_open_incident(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    raw(monkeypatch, [RED_DEGRADED])
    coalescing._coalesced_system_notices(object())
    raw(monkeypatch, [RED_STALE])
    notices = coalescing._coalesced_system_notices(object())
    assert len(notices) == 1
    assert notices[0].startswith("🔴 監視更新が遅れています")
    assert "今やること: `/status` で状態確認" in notices[0]
    assert len(coalescing._load_state()["seen_red_signatures"]) == 2


def test_critical_autopilot_state_keeps_stronger_action(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    raw(monkeypatch, [RED_AUTOPILOT_OFF])
    notices = coalescing._coalesced_system_notices(object())
    assert len(notices) == 1
    assert notices[0].startswith("🔴 自動対応が停止")
    assert "今やること: `/status` で状態確認" in notices[0]
    assert "自動対応機能がOFF" in notices[0]
    assert "Autopilot" not in notices[0]


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
    assert notices[0].startswith("🟢 監視復旧")
    assert "今やること: なし" in notices[0]
    assert "監視と自動対応が5分間安定" in notices[0]
    assert "Autopilot" not in notices[0]
    assert coalescing._load_state()["incident_open"] is False


def test_green_without_wrapper_incident_state_is_still_humanized(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    raw(monkeypatch, [GREEN])
    notices = coalescing._coalesced_system_notices(object())
    assert len(notices) == 1
    assert notices[0].startswith("🟢 監視復旧")
    assert "今やること: なし" in notices[0]
    assert "通常状態に戻りました" in notices[0]
    assert "Observer" not in notices[0]


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


def test_gap_notice_is_humanized_without_changing_gap_logic(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    raw(monkeypatch, [YELLOW_GAP])
    notices = coalescing._coalesced_system_notices(object())
    assert len(notices) == 1
    assert notices[0].startswith("🟡 通信抜けを複数検出")
    assert "今やること: 基本は待機" in notices[0]
    assert "今回 3件" in notices[0]
    assert "最終監視 1分前" in notices[0]
    assert "必要なら: `/status` で詳細確認" in notices[0]
    assert "gap" not in notices[0]


def test_unrelated_notice_passes_through_unchanged(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    notice = "ℹ️ 別カテゴリの通知"
    raw(monkeypatch, [notice])
    assert coalescing._coalesced_system_notices(object()) == [notice]


def test_retained_tclk_approval_entrypoint_installs_health_coalescer():
    service = (core.ROOT / "packaging" / "oracle" / "discord.service").read_text("utf-8")
    approval = (core.ROOT / "src" / "flop_agent" / "discord_tclk_approval.py").read_text("utf-8")
    assert "-m flop_agent.discord_tclk_approval" in service
    assert "discord_health_coalescing.install()" in approval
