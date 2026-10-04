from flop_agent import (
    discord_control,
    discord_mission_compact as compact,
    discord_outcome_scorecard as outcome,
)


def activity(*, problems=None, direct=0, queued=0):
    return {
        "snapshot": {
            "problems": problems or [],
            "health": "ok",
            "critical": 0,
            "direct": direct,
            "resident": {"approved": 0},
            "last_refresh_age": "10秒前",
            "auto": {"enabled": True, "paused": False, "queued": queued},
        },
        "posts": 0,
        "eligible": 0,
        "ignored": 0,
        "blocked": 0,
        "reasons": {},
        "zero_reason": "none",
        "received": [],
        "sent": [],
        "counterparts": 1,
        "interactions": [
            {
                "direction": "受信",
                "at": "2026-09-14T00:12:00+00:00",
                "fingerprint": "abcdef123456",
                "display_label": "Useful Agent",
                "summary": "Can you explain nonce safety?",
                "room": "lobby",
                "seq": 8,
            }
        ],
        "latest_post": None,
        "trusted": [],
        "trust_candidates": [],
        "bootstrap_pending": [],
        "oldest_unresolved_direct": None,
        "signed_direct_requests": 0,
        "acked_replies": 0,
        "active_trusted": 0,
        "collaboration_active": 0,
        "collaboration_completed": 0,
        "public_artifacts": 0,
    }


def test_mission_is_six_line_action_first_summary(monkeypatch):
    row = activity()
    monkeypatch.setattr(compact, "_collaboration_rows", lambda **_kwargs: [])

    message = compact.mission_message(row)
    lines = message.splitlines()

    assert len(lines) == 6
    assert lines[0] == "🎯 FLOP AGENT MISSION CONTROL"
    assert lines[1].startswith("状態:")
    assert lines[2].startswith("目標:")
    assert sum(line.startswith("次:") for line in lines) == 1
    assert lines[4].startswith("阻害:")
    assert "Useful Agent → MARU Agent: Can you explain nonce safety?" in lines[5]


def test_mission_selects_one_exact_pending_action(monkeypatch):
    row = activity()
    row["bootstrap_pending"] = [{"candidate_id": "candidate-1"}]
    monkeypatch.setattr(compact, "_collaboration_rows", lambda **_kwargs: [])

    message = compact.mission_message(row)

    assert "次: /reply-approved candidate-1 SEND を確認して実行" in message
    assert sum(line.startswith("次:") for line in message.splitlines()) == 1


def test_normal_status_is_mission_first_without_telemetry_dump(monkeypatch):
    row = activity()
    monkeypatch.setattr(outcome, "_activity_snapshot", lambda **kwargs: dict(row))
    monkeypatch.setattr(discord_control, "populate_status_trust", lambda value: value)
    monkeypatch.setattr(compact, "_collaboration_rows", lambda **_kwargs: [])

    message = compact.status_message()
    lines = message.splitlines()

    assert lines[0] == "🎯 FLOP AGENT MISSION CONTROL"
    assert sum(line.startswith("次:") for line in lines) == 1
    assert lines[-1].startswith("詳細: 監視:正常 / 自動対応:ON / queue:0 / 緊急:0")
    assert "/activity" in lines[-1] and "/history" in lines[-1]
    assert "関係24h:" not in message
    assert "自動投稿:" not in message
    assert "主な非アクション理由:" not in message


def test_safety_problem_status_is_short_human_warning(monkeypatch):
    row = activity(problems=["Autopilot OFF"])
    monkeypatch.setattr(outcome, "_activity_snapshot", lambda **kwargs: dict(row))
    monkeypatch.setattr(discord_control, "populate_status_trust", lambda value: value)

    message = compact.status_message()
    lines = message.splitlines()

    assert len(lines) <= 6
    assert lines[0] == "⚠️ FLOP Agent 異常"
    assert "状態: 自動対応が停止" in message
    assert "Autopilot OFF" not in message
    assert "次: 安全状態が戻るまで不可逆操作を進めない" in message
    assert sum(line.startswith("次:") for line in lines) == 1


def test_status_preserves_fast_path_flag(monkeypatch):
    captured = {}
    row = activity()

    def fake_snapshot(**kwargs):
        captured.update(kwargs)
        return dict(row)

    monkeypatch.setattr(outcome, "_activity_snapshot", fake_snapshot)
    monkeypatch.setattr(discord_control, "populate_status_trust", lambda value: value)
    monkeypatch.setattr(compact, "_collaboration_rows", lambda **_kwargs: [])

    compact.status_message()

    assert captured == {
        "sync_timeline": False,
        "include_trust": False,
        "status_fast": True,
    }


def test_install_replaces_only_presentation_functions(monkeypatch):
    old_mission = discord_control.mission_message
    old_status = discord_control.status_message
    old_installed = compact._INSTALLED
    monkeypatch.setattr(compact, "_INSTALLED", False)

    try:
        compact.install()
        assert discord_control.mission_message is compact.mission_message
        assert discord_control.status_message is compact.status_message
        assert discord_control.mission_message is not old_mission
        assert discord_control.status_message is not old_status
    finally:
        discord_control.mission_message = old_mission
        discord_control.status_message = old_status
        compact._INSTALLED = old_installed
