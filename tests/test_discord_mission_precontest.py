import json

from flop_agent import discord_mission_compact as compact


def _activity():
    return {
        "snapshot": {
            "problems": [],
            "health": "ok",
            "critical": 0,
            "direct": 0,
            "resident": {"approved": 0},
            "auto": {"enabled": True, "paused": False, "queued": 0},
        },
        "interactions": [],
        "trusted": [],
        "trust_candidates": [],
        "bootstrap_pending": [],
        "oldest_unresolved_direct": None,
    }


def _write(path, status):
    path.write_text(
        json.dumps({
            "schema_version": 1,
            "non_binding": True,
            "status": status,
            "evaluated_at": "2026-10-05T03:00:00+00:00",
            "action_window_seconds": 259200,
            "challenge_count": 1,
            "challenges": [],
        }),
        encoding="utf-8",
    )


def test_action_required_replaces_only_blocker_line(tmp_path, monkeypatch):
    path = tmp_path / "precontest-supervisor.json"
    _write(path, "ACTION_REQUIRED")
    monkeypatch.setattr(compact.precontest_supervisor, "state_path", lambda: path)
    monkeypatch.setattr(compact, "_collaboration_rows", lambda **_kwargs: [])

    message = compact.mission_message(_activity())
    lines = message.splitlines()

    assert len(lines) == 6
    assert "阻害: 72時間以内に開始するキャンペーンの準備が未完了" in message
    assert sum(line.startswith("次:") for line in lines) == 1


def test_blocked_live_is_visible_without_raw_telemetry(tmp_path, monkeypatch):
    path = tmp_path / "precontest-supervisor.json"
    _write(path, "BLOCKED_LIVE")
    monkeypatch.setattr(compact.precontest_supervisor, "state_path", lambda: path)
    monkeypatch.setattr(compact, "_collaboration_rows", lambda **_kwargs: [])

    message = compact.mission_message(_activity())

    assert "阻害: 開始済みキャンペーンの実行準備が未完了" in message
    assert "CONTROL_PATH" not in message
    assert "sha256" not in message


def test_ready_and_idle_preserve_existing_blocker(tmp_path, monkeypatch):
    path = tmp_path / "precontest-supervisor.json"
    monkeypatch.setattr(compact.precontest_supervisor, "state_path", lambda: path)
    monkeypatch.setattr(compact, "_collaboration_rows", lambda **_kwargs: [])
    monkeypatch.setattr(compact.base, "_mission_blocker", lambda _activity: "従来阻害")

    for status in ("READY", "IDLE"):
        _write(path, status)
        assert "阻害: 従来阻害" in compact.mission_message(_activity())


def test_missing_state_preserves_existing_blocker(tmp_path, monkeypatch):
    path = tmp_path / "missing.json"
    monkeypatch.setattr(compact.precontest_supervisor, "state_path", lambda: path)
    monkeypatch.setattr(compact, "_collaboration_rows", lambda **_kwargs: [])
    monkeypatch.setattr(compact.base, "_mission_blocker", lambda _activity: "従来阻害")

    assert "阻害: 従来阻害" in compact.mission_message(_activity())


def test_corrupt_existing_state_fails_visible_not_silent(tmp_path, monkeypatch):
    path = tmp_path / "precontest-supervisor.json"
    path.write_text("{bad", encoding="utf-8")
    monkeypatch.setattr(compact.precontest_supervisor, "state_path", lambda: path)
    monkeypatch.setattr(compact, "_collaboration_rows", lambda **_kwargs: [])

    assert "阻害: 次回キャンペーン準備状態を確認できません" in compact.mission_message(_activity())
