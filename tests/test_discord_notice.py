import pytest

from flop_agent import discord_notice


def test_action_notice_is_compact_and_has_one_next_action():
    text = discord_notice.render(
        "ACTION",
        "承認が必要",
        impact="未承認なら外部実行はありません。",
        state="候補はfreshです。",
        next_action="詳細を確認して承認する",
        deadline="10分",
        detail="内部telemetryは省略",
    )
    lines = text.splitlines()
    assert len(lines) == 6
    assert lines[0] == "🟠 承認が必要"
    assert sum(line.startswith("次:") for line in lines) == 1
    assert lines[4] == "期限: 10分"


def test_formatter_rejects_multiline_or_oversized_fields():
    with pytest.raises(discord_notice.NoticeFormatError, match="title_invalid"):
        discord_notice.render(
            "ACTION",
            "x" * 73,
            impact="impact",
            state="state",
            next_action="next",
        )


def test_unknown_kind_fails_closed():
    with pytest.raises(discord_notice.NoticeFormatError, match="kind_invalid"):
        discord_notice.render(
            "INFO",
            "title",
            impact="impact",
            state="state",
            next_action="next",
        )
