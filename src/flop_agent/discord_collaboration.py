"""Discord collaboration UX overlay.

The existing Discord control implementation remains untouched. Production starts
this wrapper, which adds local/read-only collaboration commands and notifications
then delegates every existing command to ``discord_control``.
"""
from __future__ import annotations

from . import collaboration
from . import discord_control as base

STAGE_LABELS = {
    "discovered": "発見",
    "contacted": "初回接触済み",
    "replied": "返信あり",
    "task_candidate": "仕事候補",
    "human_review": "人間確認待ち",
    "active": "進行中",
    "completed": "完了",
    "blocked": "停止",
}


def _next_text(record: dict) -> str:
    action = record.get("next_action")
    record_id = str(record.get("id", ""))
    if action == "wait_for_reply":
        return "対応不要。BOTが相手の返信を監視します。"
    if action == "no_action_required":
        return "対応不要。既存の安全なAutopilotに任せます。"
    if action == "watch_reply":
        return "対応不要。追加の具体的な依頼が来るまで監視します。"
    if action == "review_task":
        return f"/collab {record_id} を確認。実行・URLアクセス・署名はまだしない。"
    if action == "review_tclk":
        offer_id = record.get("related_tclk_offer_id")
        return f"/tclk {offer_id} を確認し、acceptせず内容をChatGPTへ送る。" if offer_id else f"/collab {record_id} を確認。tclkはacceptしない。"
    if action == "security_hold":
        return f"何も実行・再送しない。/collab {record_id} の内容をChatGPTへ送る。"
    if action == "agent_may_contact":
        return "対応不要。Safe First Contactの判定に任せます。"
    return f"/collab {record_id} を確認。"


def _list_message() -> str:
    rows = collaboration.records(include_tclk=False)
    metrics = collaboration.metrics()
    lines = [
        "🤝 FLOP Collaboration Pipeline",
        (
            "contacted {contacted} / replied {replied} / task {task} / "
            "active {active} / completed {completed}"
        ).format(
            contacted=metrics["contacted"],
            replied=metrics["replied"],
            task=metrics["task_candidate"] + metrics["human_review"],
            active=metrics["active"],
            completed=metrics["completed"],
        ),
    ]
    if not rows:
        lines.extend(["", "現在のcollaboration候補はありません。", "結論: 対応不要。監視を継続します。"])
        return "\n".join(lines)
    for record in rows[:5]:
        summary = base.safe_excerpt(record.get("task_summary") or "", 100)
        lines.extend([
            "",
            f"{record.get('id')} | {STAGE_LABELS.get(record.get('stage'), record.get('stage'))} | {base.short_fingerprint(record.get('fingerprint'))}",
            f"最終変化: {base.human_age(record.get('last_activity_at'))}",
        ])
        if summary:
            lines.append(f"要点: {summary}")
        lines.append("next: " + _next_text(record))
    if len(rows) > 5:
        lines.append(f"\n他 {len(rows) - 5}件。詳細は /collab <id>")
    return "\n".join(lines)


def _detail_message(record_id: str) -> str:
    record = collaboration.get(record_id, include_tclk=True)
    if record is None:
        return "🤝 Collaboration\nそのcollaboration IDは見つかりません。/collab で一覧を確認してください。"
    lines = [
        "🤝 FLOP Collaboration",
        f"ID: {record.get('id')}",
        f"stage: {STAGE_LABELS.get(record.get('stage'), record.get('stage'))}",
        f"相手: {base.short_fingerprint(record.get('fingerprint'))}",
        f"origin: {record.get('room', '?')} #{record.get('source_seq', '?')}",
        f"初回candidate: {record.get('source_candidate_id') or '-'}",
        f"初回intent: {record.get('first_contact_intent_id') or '-'}",
        f"last: {base.human_age(record.get('last_activity_at'))}",
    ]
    if record.get("task_topic"):
        lines.append(f"topic: {record.get('task_topic')}")
    if record.get("task_summary"):
        lines.append("context: " + base.safe_excerpt(record.get("task_summary"), 280))
    if record.get("related_tclk_offer_id"):
        lines.append(f"tclk: {record.get('related_tclk_offer_id')}（read-only / 未accept）")
    refs = list(record.get("evidence_refs", []))[-5:]
    if refs:
        lines.append("evidence: " + ", ".join(base.safe_excerpt(item, 80) for item in refs))
    history = list(record.get("history", []))[-6:]
    if history:
        lines.append("stage history:")
        for item in history:
            lines.append(
                f"・{STAGE_LABELS.get(item.get('stage'), item.get('stage'))} / "
                f"{base.human_time(item.get('at'))} / {base.safe_excerpt(item.get('reason'), 80)}"
            )
    lines.extend(["", "next: " + _next_text(record)])
    return "\n".join(lines)


def _notice_message(notice: dict) -> str:
    stage = notice.get("stage")
    record_id = str(notice.get("id", ""))
    fingerprint = base.short_fingerprint(notice.get("fingerprint"))
    summary = base.safe_excerpt(notice.get("task_summary") or "", 160)
    if stage == "replied":
        lines = ["🔵 FLOP Agent 相手から返信", f"相手: {fingerprint}", f"collab: {record_id}"]
        if summary:
            lines.append("要点: " + summary)
        lines.append("結論: 対応不要。BOTが安全条件内で継続します。")
        return "\n".join(lines)
    if stage in {"task_candidate", "human_review"}:
        lines = ["🟡 FLOP Agent 仕事候補", f"相手: {fingerprint}", f"collab: {record_id}"]
        if summary:
            lines.append("要点: " + summary)
        lines.append(f"次にやること: /collab {record_id}")
        return "\n".join(lines)
    if stage == "completed":
        return f"🟢 FLOP Agent Collaboration完了\n相手: {fingerprint}\ncollab: {record_id}\n証拠を /collab {record_id} で確認できます。"
    return f"🔴 FLOP Agent Collaboration停止\n相手: {fingerprint}\ncollab: {record_id}\n再送・実行せず /collab {record_id} を確認してください。"


class Control(base.Control):
    def command(self, user_id: str, text: str, channel_id: str | None = None) -> dict:
        parts = text.strip().split()
        if parts and parts[0] == "/collab":
            if channel_id is not None and channel_id != self.channel_id:
                return {"ok": False, "error": "wrong_channel", "message": "Control access denied."}
            if user_id not in self.allowed_ids:
                return {"ok": False, "error": "unauthorized", "message": "Control access denied."}
            if len(parts) == 1:
                return {"ok": True, "data": {}, "message": _list_message()}
            if len(parts) == 2:
                return {"ok": True, "data": {}, "message": _detail_message(parts[1])}
            return {"ok": False, "error": "invalid_args", "message": "Usage: /collab [id]"}

        result = super().command(user_id, text, channel_id)
        if result.get("ok") and parts and parts[0] == "/activity" and len(parts) == 1:
            metrics = collaboration.metrics()
            result["message"] += (
                "\nCollaboration: contacted {contacted} / replies {replies} / "
                "task {tasks} / active {active} / completed {completed}"
            ).format(
                contacted=metrics["contacted"],
                replies=metrics["replies_from_contacted"],
                tasks=metrics["task_candidate"] + metrics["human_review"],
                active=metrics["active"],
                completed=metrics["completed"],
            )
        if result.get("ok") and parts and parts[0] == "/help" and len(parts) == 1:
            result["message"] += " | collaboration: /collab [id]"
        return result

    def ensure_baseline(self) -> None:
        super().ensure_baseline()
        collaboration.ensure_notification_baseline()

    def system_notices(self) -> list[str]:
        notices = super().system_notices()
        notices.extend(_notice_message(item) for item in collaboration.transition_notices())
        return notices


def main() -> None:
    # discord_control.main resolves its module-global Control at runtime.
    base.Control = Control
    base.main()


if __name__ == "__main__":
    main()
