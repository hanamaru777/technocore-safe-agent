"""Discord overlay for versioned source-backed onboarding knowledge."""
from __future__ import annotations

import time

from . import discord_collaboration as base
from . import knowledge, knowledge_guard, observer, resident, tclk_triage, tclk_watch

knowledge_guard.install()

AUDIT_SYNC_SECONDS = 60
TCLK_NOTICE_POLL_SECONDS = 30
_LAST_AUDIT_SYNC = 0.0
_LAST_TCLK_NOTICE_POLL = 0.0
_TCLK_NOTICE_BASELINED = False
_TCLK_NOTICE_SEEN: set[str] = set()


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


def _render_tclk_item(item: dict) -> str:
    summary = base.base._tclk_offer_message(item)
    has_full = isinstance(item.get("terms_full"), str)
    terms = item.get("terms_full") if has_full else item.get("terms", "")
    rendered_terms = base.base.safe_excerpt(terms, tclk_watch.MAX_FRAME_CHARS) or "-"
    frame_hash = base.base.safe_excerpt(item.get("frame_sha256") or "-", 64)
    evidence = "stored full terms" if has_full else "legacy summary only"
    verdict = tclk_triage.classify(item)
    return "\n".join([
        summary,
        "",
        "=== FULL TERMS (untrusted / sanitized) ===",
        rendered_terms,
        "=== END FULL TERMS ===",
        f"review evidence: {evidence} | frame sha256: {frame_hash}",
        f"triage: {verdict['status']} | {verdict['reason']} | time left {verdict['seconds_left']}s",
        "review mode: read-only. This command did not accept, sign, post, lock, reveal, or pay.",
    ])


def _tclk_detail_message(offer_id: str) -> str:
    """Render locally retained full tclk review evidence without changing offer state."""
    status = tclk_watch.runtime_status()
    if status.get("ready") is not True:
        return f"🔴 tclk runtime unavailable/degraded ({status.get('reason', 'unknown')}). No offer state was changed."
    try:
        item = tclk_watch.offer(observer.load_state(), offer_id)
    except RuntimeError:
        item = None
    if item is None:
        return "No validated read-only tclk/1 offer found for that ID."
    return _render_tclk_item(item)


def _tclk_best_message() -> str:
    """Pick the earliest-expiring review-worthy offer; never mutates protocol state."""
    status = tclk_watch.runtime_status()
    if status.get("ready") is not True:
        return f"🔴 tclk runtime unavailable/degraded ({status.get('reason', 'unknown')}). No offer state was changed."
    try:
        items = tclk_watch.opportunities(observer.load_state())
    except RuntimeError:
        items = []
    rows = tclk_triage.review_candidates(items)
    if not rows:
        return (
            "🧭 tclk/1 best review candidate\n"
            "現在、first-pilot基準で十分な確認時間と安全条件を満たす候補はありません。\n"
            "結論: acceptしない。Residentのread-only監視を継続します。"
        )
    item = rows[0]["item"]
    verdict = rows[0]["verdict"]
    header = (
        "🧭 tclk/1 best review candidate\n"
        f"ID: {item.get('id')}\n"
        f"job: {item.get('job_proto')}/{item.get('job_id')}\n"
        f"review window: 約 {max(1, verdict['seconds_left'] // 60)}分\n"
        "注意: candidate判定はaccept承認ではありません。"
    )
    return header + "\n\n" + _render_tclk_item(item)


def _baseline_tclk_notices() -> None:
    """Suppress startup backlog; notify only offers first seen after this Discord process starts."""
    global _TCLK_NOTICE_BASELINED, _TCLK_NOTICE_SEEN
    try:
        items = tclk_watch.opportunities(observer.load_state())
    except RuntimeError:
        return
    _TCLK_NOTICE_SEEN = {
        str(item.get("id")) for item in items
        if isinstance(item.get("id"), str)
    }
    _TCLK_NOTICE_BASELINED = True


def _tclk_review_notice(item: dict, verdict: dict) -> str:
    offer_id = base.base.safe_excerpt(item.get("id") or "-", 70)
    job_proto = base.base.safe_excerpt(item.get("job_proto") or "-", 32)
    job_id = base.base.safe_excerpt(item.get("job_id") or "-", 64)
    minutes = max(1, verdict["seconds_left"] // 60)
    return "\n".join([
        "🟡 tclk/1 新しい協業レビュー候補",
        f"job: {job_proto}/{job_id}",
        f"残り確認時間: 約{minutes}分",
        "rail: PaperRail / no-value rehearsal",
        f"次にやること: /tclk {offer_id}",
        "まだaccept・署名・投稿はしません。",
    ])


def _new_tclk_review_notices() -> list[str]:
    """Return one-shot notices for new review-worthy offers; no network or state write."""
    global _TCLK_NOTICE_BASELINED, _TCLK_NOTICE_SEEN
    try:
        items = tclk_watch.opportunities(observer.load_state())
    except RuntimeError:
        return []
    active_ids = {
        str(item.get("id")) for item in items
        if isinstance(item.get("id"), str)
    }
    if not _TCLK_NOTICE_BASELINED:
        _TCLK_NOTICE_SEEN = set(active_ids)
        _TCLK_NOTICE_BASELINED = True
        return []

    new_items = [item for item in items if item.get("id") not in _TCLK_NOTICE_SEEN]
    # Keep dedupe bounded to currently live offers. Replayed old ids cannot be re-observed
    # as new because the Resident watcher also maintains its own bounded seen-offer guard.
    _TCLK_NOTICE_SEEN.intersection_update(active_ids)
    _TCLK_NOTICE_SEEN.update(active_ids)

    rows = tclk_triage.review_candidates(new_items)
    return [_tclk_review_notice(row["item"], row["verdict"]) for row in rows[:2]]


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

        if parts and parts[0] in {"/tclk", "/tclk-best"}:
            if channel_id is not None and channel_id != self.channel_id:
                return {"ok": False, "error": "wrong_channel", "message": "Control access denied."}
            if user_id not in self.allowed_ids:
                return {"ok": False, "error": "unauthorized", "message": "Control access denied."}
            if parts[0] == "/tclk-best" and len(parts) == 1:
                return {"ok": True, "data": {}, "message": _tclk_best_message()}
            if parts[0] == "/tclk" and len(parts) == 2:
                return {"ok": True, "data": {}, "message": _tclk_detail_message(parts[1])}
            usage = "Usage: /tclk <offer-id> | /tclk-best"
            return {"ok": False, "error": "invalid_args", "message": usage}

        result = super().command(user_id, text, channel_id)
        if result.get("ok") and parts and parts[0] == "/candidate" and len(parts) == 2:
            result["message"] += _candidate_suffix(parts[1])
        if result.get("ok") and parts and parts[0] == "/help" and len(parts) == 1:
            result["message"] += " | source-backed: /knowledge [topic] | tclk review: /tclk-best"
        return result

    def ensure_baseline(self) -> None:
        super().ensure_baseline()
        try:
            knowledge.sync_acknowledged_usage()
        except RuntimeError:
            # Presentation/evidence reconciliation must never take Discord down.
            pass
        _baseline_tclk_notices()

    def system_notices(self) -> list[str]:
        global _LAST_AUDIT_SYNC, _LAST_TCLK_NOTICE_POLL
        notices = super().system_notices()
        current = time.monotonic()
        if current - _LAST_AUDIT_SYNC >= AUDIT_SYNC_SECONDS:
            _LAST_AUDIT_SYNC = current
            try:
                knowledge.sync_acknowledged_usage()
            except RuntimeError:
                pass
        if current - _LAST_TCLK_NOTICE_POLL >= TCLK_NOTICE_POLL_SECONDS:
            _LAST_TCLK_NOTICE_POLL = current
            notices.extend(_new_tclk_review_notices())
        return notices


def main() -> None:
    # discord_collaboration.main resolves its module-global Control at runtime,
    # then delegates to the original discord_control event loop.
    base.Control = Control
    base.main()


if __name__ == "__main__":
    main()
