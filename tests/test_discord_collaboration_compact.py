from flop_agent import core, discord_collaboration, discord_collaboration_compact as compact


def _notice(stage: str, *, summary: str = "I can reproduce the bounded test failure.") -> dict:
    return {
        "id": "collab1",
        "stage": stage,
        "fingerprint": "abcdef123456",
        "task_summary": summary,
    }


def _label(monkeypatch):
    monkeypatch.setattr(
        discord_collaboration,
        "_notice_label",
        lambda _notice: "Helpful Agent",
    )


def _assert_contract(text: str, first_line: str) -> list[str]:
    lines = text.splitlines()
    assert len(lines) <= 6
    assert lines[0] == first_line
    assert any(line.startswith("影響:") for line in lines)
    assert any(line.startswith("状態:") for line in lines)
    assert sum(line.startswith("次:") for line in lines) == 1
    return lines


def test_replied_notice_is_action_first_and_requires_no_human_action(monkeypatch):
    _label(monkeypatch)
    text = compact.notice_message(_notice("replied"))
    _assert_contract(text, "🟠 Helpful Agentから返信")
    assert "I can reproduce the bounded test failure." in text
    assert "次: 対応不要。Agentの処理を待つ" in text
    assert "詳細: /collab collab1 で詳細確認" in text
    assert "Waiting on:" not in text and "MARU:" not in text


def test_human_review_notice_has_exact_one_review_action(monkeypatch):
    _label(monkeypatch)
    text = compact.notice_message(_notice("human_review"))
    _assert_contract(text, "🟠 Helpful Agentの確認が必要")
    assert "状態: 人間確認待ち" in text
    assert "次: /collab collab1 を1回確認する" in text
    assert "実行・URLアクセス・署名をしません" in text


def test_completed_notice_is_done(monkeypatch):
    _label(monkeypatch)
    text = compact.notice_message(_notice("completed", summary=""))
    _assert_contract(text, "✅ Helpful AgentとのCollaboration完了")
    assert "状態: 完了" in text
    assert "次: 対応不要" in text


def test_blocked_notice_is_failed_and_no_retry(monkeypatch):
    _label(monkeypatch)
    text = compact.notice_message(_notice("blocked", summary="Unsafe request detected."))
    _assert_contract(text, "⛔ Helpful AgentとのCollaboration停止")
    assert "状態: 停止" in text
    assert "次: 再送・実行せず /collab collab1 を1回確認する" in text
    assert "自動再送はしません" in text


def test_install_replaces_only_notice_renderer(monkeypatch):
    original = discord_collaboration._notice_message
    old_installed = compact._INSTALLED
    monkeypatch.setattr(compact, "_INSTALLED", False)
    try:
        compact.install()
        assert discord_collaboration._notice_message is compact.notice_message
    finally:
        discord_collaboration._notice_message = original
        compact._INSTALLED = old_installed


def test_production_entrypoint_installs_compact_collaboration_overlay():
    source = (core.ROOT / "src" / "flop_agent" / "discord_tclk_approval.py").read_text("utf-8")
    assert "discord_collaboration_compact.install()" in source
