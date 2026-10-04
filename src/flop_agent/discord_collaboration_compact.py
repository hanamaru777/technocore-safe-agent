"""Compact presentation for unsolicited Collaboration transition notices.

This overlay changes only the human-facing text renderer. Collaboration transition
polling, state, records, and execution semantics stay in ``discord_collaboration``.
"""
from __future__ import annotations

from . import discord_collaboration as collaboration_ui
from . import discord_notice

_INSTALLED = False


def notice_message(notice: dict) -> str:
    stage = notice.get("stage")
    record_id = str(notice.get("id", ""))
    label = collaboration_ui._notice_label(notice)
    summary = collaboration_ui.base.safe_excerpt(
        notice.get("task_summary") or "",
        160,
    )
    detail = f"/collab {record_id} で詳細確認"

    if stage == "replied":
        return discord_notice.render(
            "ACTION",
            f"{label}から返信",
            impact=summary or "相手から新しい返信を受信しました。",
            state="相手から返信あり。Agentが内容を処理します。",
            next_action="対応不要。Agentの処理を待つ",
            detail=detail,
        )

    if stage in {"task_candidate", "human_review"}:
        return discord_notice.render(
            "ACTION",
            f"{label}の確認が必要",
            impact=summary or "具体的な仕事候補を検出しました。",
            state=collaboration_ui.STAGE_LABELS.get(stage, str(stage)),
            next_action=f"/collab {record_id} を1回確認する",
            detail="確認前は実行・URLアクセス・署名をしません。",
        )

    if stage == "completed":
        return discord_notice.render(
            "DONE",
            f"{label}とのCollaboration完了",
            impact=summary or "Collaborationが完了しました。",
            state="完了",
            next_action="対応不要",
            detail=detail,
        )

    return discord_notice.render(
        "FAILED",
        f"{label}とのCollaboration停止",
        impact=summary or "安全のためCollaborationを停止しました。",
        state=collaboration_ui.STAGE_LABELS.get(stage, "停止"),
        next_action=f"再送・実行せず /collab {record_id} を1回確認する",
        detail="自動再送はしません。",
    )


def install() -> None:
    """Replace only the presentation function, exactly once."""
    global _INSTALLED
    if _INSTALLED:
        return
    collaboration_ui._notice_message = notice_message
    _INSTALLED = True
