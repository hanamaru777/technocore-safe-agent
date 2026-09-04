"""Discord overlay for versioned source-backed onboarding knowledge."""
from __future__ import annotations

import time

from . import discord_collaboration as base
from . import knowledge, knowledge_guard, resident

knowledge_guard.install()

AUDIT_SYNC_SECONDS = 60
_LAST_AUDIT_SYNC = 0.0


def _summary_message() -> str:
    try:
        info = knowledge.summary()
    except RuntimeError:
        return "📚 FLOP Knowledge\nregistry: ERROR\n結論: source-backed回答は停止。ChatGPTへ連絡してください。"
    lines = [
        "📚 FLOP Knowledge",
        f"registry: {info['registry_id']}",
        f"verified {info['verified']}/{info['topics']} | signed-ready {info['signable']}",
        f"checked: {base.base.human_time(info['checked_at'])}",
    ]
    if info["stale"]:
        lines.append("stale: " + ", ".join(info["stale"]))
    lines.append("")
    for row in info["rows"]:
        mode = "signed" if row.get("signable") else "read-only"
        state = "OK" if row.get("verified") else "STALE"
        lines.append(f"・{row['topic']} | {state} | {mode} | sources {len(row.get('source_ids', []))}")
    lines.extend(["", "詳細: /knowledge <topic>"])
    return "\n".join(lines)


def _detail_message(topic: str) -> str:
    try:
        status = knowledge.topic_status(topic)
    except RuntimeError:
        return "📚 FLOP Knowledge\nregistryを検証できません。source-backed回答は停止しています。"
    if not status.get("known"):
        return f"📚 FLOP Knowledge\ntopic `{base.base.safe_excerpt(topic, 48)}` は未登録です。/knowledge で一覧を確認してください。"
    lines = [
        "📚 FLOP Knowledge",
        f"topic: {topic}",
        f"state: {'verified' if status['verified'] else 'STALE / FAIL-CLOSED'}",
        f"freshness: {status['freshness']}",
        f"checked: {base.base.human_time(status['checked_at'])}",
        f"mode: {'signed fixed renderer' if status.get('signable') else 'read-only'}",
        "sources:",
    ]
    for source in status.get("sources", []):
        lines.append(
            f"・{source['source_id']} | {source['authority']} | "
            f"{source['repo']}@{source['commit'][:8]}:{source['path']}"
        )
    if not status["verified"]:
        lines.extend(["", "answer: BLOCKED。time-sensitive sourceを再確認するまで回答しません。"])
        return "\n".join(lines)
    try:
        answer = knowledge.preview(topic)
    except RuntimeError:
        lines.extend(["", "answer: BLOCKED。renderer/source整合性を確認できません。"])
        return "\n".join(lines)
    lines.extend(["", "exact answer preview:", answer])
    if not status.get("signable"):
        lines.append("注意: このtopicはSigner経路へ入りません。read-only確認専用です。")
    return "\n".join(lines)


def _candidate_suffix(candidate_id: str) -> str:
    try:
        item = resident.candidate(candidate_id)
    except RuntimeError:
        return ""
    if not isinstance(item, dict):
        return ""
    # resident.candidate may return a wrapper in some compatibility paths.
    candidate = item.get("candidate") if isinstance(item.get("candidate"), dict) else item
    try:
        info = knowledge.candidate_knowledge(candidate)
    except RuntimeError:
        return "\nKnowledge: registry ERROR → source-backed自動回答はfail-closed"
    if not info.get("topic"):
        return f"\nKnowledge: なし ({info.get('reason', 'unresolved')})"
    state = "verified" if info.get("verified") else "BLOCKED"
    mode = "signed-ready" if info.get("signable") else "read-only"
    sources = ", ".join(info.get("source_ids", [])) or "-"
    return f"\nKnowledge: {info['topic']} | {state} | {mode}\nSources: {sources}"


class Control(base.Control):
    def command(self, user_id: str, text: str, channel_id: str | None = None) -> dict:
        parts = text.strip().split()
        if parts and parts[0] == "/knowledge":
            if channel_id is not None and channel_id != self.channel_id:
                return {"ok": False, "error": "wrong_channel", "message": "Control access denied."}
            if user_id not in self.allowed_ids:
                return {"ok": False, "error": "unauthorized", "message": "Control access denied."}
            if len(parts) == 1:
                return {"ok": True, "data": {}, "message": _summary_message()}
            if len(parts) == 2:
                return {"ok": True, "data": {}, "message": _detail_message(parts[1])}
            return {"ok": False, "error": "invalid_args", "message": "Usage: /knowledge [topic]"}

        result = super().command(user_id, text, channel_id)
        if result.get("ok") and parts and parts[0] == "/candidate" and len(parts) == 2:
            result["message"] += _candidate_suffix(parts[1])
        if result.get("ok") and parts and parts[0] == "/help" and len(parts) == 1:
            result["message"] += " | source-backed: /knowledge [topic]"
        return result

    def ensure_baseline(self) -> None:
        super().ensure_baseline()
        try:
            knowledge.sync_acknowledged_usage()
        except RuntimeError:
            # Presentation/evidence reconciliation must never take Discord down.
            pass

    def system_notices(self) -> list[str]:
        global _LAST_AUDIT_SYNC
        notices = super().system_notices()
        current = time.monotonic()
        if current - _LAST_AUDIT_SYNC >= AUDIT_SYNC_SECONDS:
            _LAST_AUDIT_SYNC = current
            try:
                knowledge.sync_acknowledged_usage()
            except RuntimeError:
                pass
        return notices


def main() -> None:
    # discord_collaboration.main resolves its module-global Control at runtime,
    # then delegates to the original discord_control event loop.
    base.Control = Control
    base.main()


if __name__ == "__main__":
    main()
