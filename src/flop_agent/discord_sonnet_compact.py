"""Presentation-only compaction for existing Sonnet-2 unsolicited notices.

The authoritative polling/evidence/dedupe logic stays in discord_sonnet_alerts.
This module only converts its already-decided notices into the shared compact
Discord UX. Unknown shapes pass through unchanged rather than being reclassified.
"""
from __future__ import annotations

from . import discord_notice


def _value(lines: list[str], prefix: str) -> str | None:
    for line in lines:
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return None


def compact(value: str) -> str:
    if not isinstance(value, str):
        return value
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if not lines:
        return value

    if lines[0].startswith("🟣 Sonnet-2:"):
        headline = lines[0].split(":", 1)[1].strip()
        event = _value(lines, "何が起きた:") or "公式・署名済み更新を検出"
        importance = _value(lines, "重要性:") or "MARU関連の更新です。"
        caution = _value(lines, "注意:") or "activityだけでは参加意思を断定しません。"
        return discord_notice.render(
            "ACTION",
            f"Sonnet-2: {headline}",
            impact=importance,
            state=event,
            next_action="新しい公式内容を確認し、必要な対応だけ行う",
            detail=caution,
        )

    if lines[0].startswith("🔴 Sonnet-2: 監視ギャップを検出"):
        event = _value(lines, "何が起きた:") or "監視履歴に復元できない区間があります。"
        importance = _value(lines, "重要性:") or "MARU関連証拠の欠落を自動では否定できません。"
        return discord_notice.render(
            "WARNING",
            "Sonnet-2監視ギャップ",
            impact=importance,
            state=event,
            next_action="公式Sonnet状態と /status を1回確認する",
            detail="確認完了までは不可逆操作を進めません。",
        )

    return value


def compact_batch(values: list[str]) -> list[str]:
    return [compact(value) for value in values]
