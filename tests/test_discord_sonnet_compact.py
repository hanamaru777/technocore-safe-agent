from flop_agent import discord_sonnet_compact


def test_official_sonnet_notice_becomes_action_first_and_keeps_caution():
    source = "\n".join(
        [
            "🟣 Sonnet-2: MARU official disposition update",
            "何が起きた: accepted writer disposition",
            "重要性: writer/team の公式判断に関係する更新です。",
            "MARU: 公式・署名済みの根拠を確認",
            "注意: activity・返信・招待はroster consentを自動では意味しません。このwatcherは署名・投稿を行っていません。",
        ]
    )

    rendered = discord_sonnet_compact.compact(source)
    lines = rendered.splitlines()

    assert len(lines) <= 6
    assert lines[0] == "🟠 Sonnet-2: MARU official disposition update"
    assert "writer/team の公式判断" in rendered
    assert "accepted writer disposition" in rendered
    assert "roster consentを自動では意味しません" in rendered
    assert sum(line.startswith("次:") for line in lines) == 1


def test_sonnet_gap_notice_becomes_warning_with_one_next_action():
    source = "\n".join(
        [
            "🔴 Sonnet-2: 監視ギャップを検出",
            "何が起きた: mb-sonnet-2-discovery の seq 10..12 はexport保持範囲にも残っていません。",
            "重要性: この区間にMARU関連のactivity・setup証拠があった可能性を自動では否定できません。",
            "MARU: 公式状態を手動再確認するまで不可逆操作を進めない",
            "注意: 自動送信・再招待・roster consent は行っていません。",
        ]
    )

    rendered = discord_sonnet_compact.compact(source)
    lines = rendered.splitlines()

    assert len(lines) <= 6
    assert lines[0] == "⚠️ Sonnet-2監視ギャップ"
    assert "seq 10..12" in rendered
    assert "不可逆操作を進めません" in rendered
    assert sum(line.startswith("次:") for line in lines) == 1


def test_unknown_notice_shape_passes_through_unchanged():
    source = "legacy or unrelated notice\nkeep me exactly"
    assert discord_sonnet_compact.compact(source) == source


def test_compact_batch_preserves_count_and_order():
    first = "🟣 Sonnet-2: update\n何が起きた: one\n重要性: two\n注意: three"
    second = "unrelated"
    rendered = discord_sonnet_compact.compact_batch([first, second])
    assert len(rendered) == 2
    assert rendered[0].startswith("🟠 Sonnet-2: update")
    assert rendered[1] == second
