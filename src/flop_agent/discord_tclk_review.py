"""Discord entrypoint for retained tclk review plus fixed-origin Note evidence.

Offer ingestion remains fail-closed in :mod:`tclk_watch`: a record only reaches local
state after signed-record verification and successful decoding by the pinned official
``@flop-labs/tclk`` parser. Human review of that already-retained evidence must not be
hidden later just because an unrelated synchronous Node health probe is briefly slow.

New review-worthy offers are automatically resolved through the same bounded fixed-origin
Note resolver and written to a bounded public evidence store. This removes the need for a
human to copy a short-lived candidate into ChatGPT. Nothing here signs, posts, accepts,
locks, reveals, pays, executes task text, or follows arbitrary URLs.
"""
from __future__ import annotations

from . import discord_knowledge as app
from . import observer, tclk_note_review, tclk_review_evidence, tclk_triage, tclk_watch

VALIDATION_NOTE = (
    "parser validation: retained at ingestion; this review command does not re-probe "
    "the live bridge."
)
AUTO_RESOLVE_BATCH = 4
AUTO_NOTICE_LIMIT = 2
_AUTO_FAILURE_NOTIFIED: set[str] = set()
_TRANSIENT_EVIDENCE_ERRORS = {"full_spec_read_failed", "material_read_failed"}


def _live_offers() -> list[dict]:
    """Return locally retained live offers; no network, parser subprocess, or write."""
    try:
        return tclk_watch.opportunities(observer.load_state())
    except RuntimeError:
        return []


def _stored_opportunities_message() -> str:
    rows = _live_offers()[:5]
    if not rows:
        return "\n".join([
            "🔒 tclk/1 opportunities (read-only)",
            "",
            "No validated signed PaperRail offers are currently live in local state. Nothing was accepted.",
            VALIDATION_NOTE,
        ])
    lines = [
        "🔒 tclk/1 opportunities (read-only)",
        "",
        f"validated offers: {len(rows)} (showing up to 5)",
    ]
    for item in rows:
        lines.extend(["", app.base.base._tclk_offer_message(item)])
    lines.extend(["", VALIDATION_NOTE])
    return "\n".join(lines)


def _stored_offer_message(offer_id: str) -> str:
    try:
        item = tclk_watch.offer(observer.load_state(), offer_id)
    except RuntimeError:
        item = None
    if item is None:
        return "No validated read-only tclk/1 offer found for that ID."
    return app.base.base._tclk_offer_message(item) + "\n" + VALIDATION_NOTE


def _stored_detail_message(offer_id: str) -> str:
    try:
        item = tclk_watch.offer(observer.load_state(), offer_id)
    except RuntimeError:
        item = None
    if item is None:
        return "No validated read-only tclk/1 offer found for that ID."
    return app._render_tclk_item(item) + "\n" + VALIDATION_NOTE


def _stored_best_message() -> str:
    rows = tclk_triage.review_candidates(_live_offers())
    if not rows:
        return "\n".join([
            "🧭 tclk/1 best review candidate",
            "現在、first-pilot基準で十分な確認時間と安全条件を満たす候補はありません。",
            "結論: acceptしない。Residentのread-only監視を継続します。",
            VALIDATION_NOTE,
        ])
    item = rows[0]["item"]
    verdict = rows[0]["verdict"]
    header = "\n".join([
        "🧭 tclk/1 best review candidate",
        f"ID: {item.get('id')}",
        f"job: {item.get('job_proto')}/{item.get('job_id')}",
        f"review window: 約 {max(1, verdict['seconds_left'] // 60)}分",
        "注意: candidate判定はaccept承認ではありません。",
    ])
    return header + "\n\n" + app._render_tclk_item(item) + "\n" + VALIDATION_NOTE


def _sanitize_note(value: object, limit: int | None = None) -> str:
    cap = tclk_note_review.MAX_NOTE_BYTES if limit is None else min(limit, tclk_note_review.MAX_NOTE_BYTES)
    return app.base.base.safe_excerpt(value, cap) or "-"


def _resolved_note_message(offer_id: str) -> str:
    """Fetch bounded same-origin review evidence for one retained live offer."""
    try:
        item = tclk_watch.offer(observer.load_state(), offer_id)
    except RuntimeError:
        item = None
    if item is None:
        return "No validated live read-only tclk/1 offer found for that ID. Nothing was accepted."
    try:
        resolved = tclk_note_review.resolve_offer(item)
    except tclk_note_review.ResolutionError as error:
        return "\n".join([
            "🔒 tclk/1 Note resolution blocked (fail-closed)",
            f"ID: {app.base.base.safe_excerpt(offer_id, 70)}",
            f"reason: {app.base.base.safe_excerpt(str(error), 80)}",
            "No task text was executed. No accept, sign, post, lock, reveal, or payment occurred.",
        ])

    spec = resolved["full_spec"]
    material = resolved["material"]
    lines = [
        "📎 tclk/1 resolved review evidence (read-only)",
        f"ID: {resolved['offer_id']}",
        f"job: a2a/{resolved['job_id']}",
        f"frame sha256: {resolved['frame_sha256']}",
        f"reads: {resolved['read_count']}/2 max | external URL text present: {resolved['external_url_present']}",
        "",
        f"=== FULL SPEC NOTE {spec['namespace']}/{spec['key']} ===",
        f"sha256: {spec['sha256']} | bytes: {spec['bytes']}",
        _sanitize_note(spec["value"]),
        "=== END FULL SPEC ===",
    ]
    if material is not None:
        lines.extend([
            "",
            f"=== MATERIAL NOTE {material['namespace']}/{material['key']} ===",
            f"sha256: {material['sha256']} | bytes: {material['bytes']}",
            _sanitize_note(material["value"]),
            "=== END MATERIAL ===",
        ])
    lines.extend([
        "",
        "REVIEW EVIDENCE ONLY — not accepted.",
        "Only fixed-origin Technocore Notes were read; URLs/task text were not followed or executed.",
        "No sign, post, accept, lock, reveal, payment, or protocol-state change occurred.",
    ])
    return "\n".join(lines)


def _stored_evidence_message(offer_id: str | None = None) -> str:
    """Render durable public review evidence even after the offer expires."""
    try:
        if offer_id is None:
            records = tclk_review_evidence.load_store()["records"][-5:]
            if not records:
                return "📚 tclk stored evidence\n保存済みの自動レビュー証拠はまだありません。"
            lines = ["📚 tclk stored evidence", f"recent: {len(records)}"]
            for record in reversed(records):
                lines.append(
                    f"・{record['offer_id']} | a2a/{record['job_id']} | "
                    f"frame {record['frame_sha256'][:12]}… | spec {record['full_spec']['sha256'][:12]}…"
                )
            lines.append("詳細: /tclk-evidence <offer-id>")
            return "\n".join(lines)
        record = tclk_review_evidence.get(offer_id)
    except tclk_review_evidence.EvidenceError as error:
        return f"🔒 tclk stored evidence unavailable (fail-closed): {_sanitize_note(str(error), 80)}"
    if record is None:
        return "No stored tclk review evidence found for that ID."
    spec = record["full_spec"]
    material = record["material"]
    lines = [
        "📚 tclk stored review evidence (read-only / may be expired)",
        f"ID: {record['offer_id']}",
        f"job: a2a/{record['job_id']}",
        f"resolved: {record['resolved_at']}",
        f"expires_ms: {record['expires_ms']}",
        f"frame sha256: {record['frame_sha256']}",
        f"reads: {record['read_count']}/2 | external URL text present: {record['external_url_present']}",
        "",
        f"=== FULL SPEC {spec['namespace']}/{spec['key']} ===",
        f"sha256: {spec['sha256']} | bytes: {spec['bytes']}",
        _sanitize_note(spec["value"]),
        "=== END FULL SPEC ===",
    ]
    if material is not None:
        lines.extend([
            "",
            f"=== MATERIAL {material['namespace']}/{material['key']} ===",
            f"sha256: {material['sha256']} | bytes: {material['bytes']}",
            _sanitize_note(material["value"]),
            "=== END MATERIAL ===",
        ])
    lines.extend([
        "",
        "STORED REVIEW EVIDENCE ONLY — not an approval and not proof the offer is still live.",
        "No sign, post, accept, lock, reveal, payment, URL follow, or task execution occurred.",
    ])
    return "\n".join(lines)


def _auto_success_notice(item: dict, verdict: dict, record: dict) -> str:
    offer_id = app.base.base.safe_excerpt(item.get("id") or "-", 70)
    job_id = app.base.base.safe_excerpt(item.get("job_id") or "-", 64)
    minutes = max(1, verdict["seconds_left"] // 60)
    spec = record["full_spec"]
    material = record["material"]
    lines = [
        "🟡 tclk/1 新しい協業レビュー候補 — 自動確認済み",
        f"job: a2a/{job_id}",
        f"残り確認時間: 約{minutes}分 | rail: PaperRail / no-value rehearsal",
        "AUTO-RESOLVE: PASS / 証拠をローカル保存済み",
        f"frame sha256: {record['frame_sha256']}",
        f"full spec sha256: {spec['sha256']}",
        f"task preview: {_sanitize_note(spec['value'], 520)}",
    ]
    if material is not None:
        lines.extend([
            f"material sha256: {material['sha256']}",
            f"material preview: {_sanitize_note(material['value'], 300)}",
        ])
    if record["external_url_present"]:
        lines.append("注意: Note内にURL文字列あり。BOTは開いていません。")
    lines.extend([
        f"保存証拠: /tclk-evidence {offer_id}（任意）",
        "あなたがChatGPTへ貼る必要はありません。acceptはまだ自動実行しません。",
    ])
    return "\n".join(lines)


def _auto_failure_notice(item: dict, verdict: dict, reason: str, *, retrying: bool) -> str:
    offer_id = app.base.base.safe_excerpt(item.get("id") or "-", 70)
    job_id = app.base.base.safe_excerpt(item.get("job_id") or "-", 64)
    minutes = max(1, verdict["seconds_left"] // 60)
    tail = "期限内は自動で再試行します。" if retrying else "この候補はfail-closedで見送ります。"
    return "\n".join([
        "🟡 tclk/1 協業候補 — 自動確認はfail-closed",
        f"job: a2a/{job_id} | 残り約{minutes}分",
        f"AUTO-RESOLVE: BLOCKED / {app.base.base.safe_excerpt(reason, 80)}",
        tail,
        f"ID: {offer_id}",
        "あなたがChatGPTへ貼る必要はありません。accept・署名・投稿はしていません。",
    ])


def _new_auto_review_notices() -> list[str]:
    """Resolve new review-worthy offers automatically; retry transient read failures."""
    global _AUTO_FAILURE_NOTIFIED
    try:
        items = tclk_watch.opportunities(observer.load_state())
    except RuntimeError:
        return []
    active_ids = {
        str(item.get("id")) for item in items
        if isinstance(item.get("id"), str)
    }
    if not app._TCLK_NOTICE_BASELINED:
        app._TCLK_NOTICE_SEEN = set(active_ids)
        app._TCLK_NOTICE_BASELINED = True
        _AUTO_FAILURE_NOTIFIED = set()
        return []

    app._TCLK_NOTICE_SEEN.intersection_update(active_ids)
    _AUTO_FAILURE_NOTIFIED.intersection_update(active_ids)
    new_items = [item for item in items if item.get("id") not in app._TCLK_NOTICE_SEEN]
    rows = tclk_triage.review_candidates(new_items)[:AUTO_RESOLVE_BATCH]
    rendered: list[str] = []
    completed = 0
    for row in rows:
        item = row["item"]
        verdict = row["verdict"]
        offer_id = str(item.get("id"))
        try:
            record = tclk_review_evidence.capture(item)
        except tclk_review_evidence.EvidenceError as error:
            reason = str(error)
            retrying = reason in _TRANSIENT_EVIDENCE_ERRORS
            if not retrying:
                app._TCLK_NOTICE_SEEN.add(offer_id)
            if offer_id not in _AUTO_FAILURE_NOTIFIED:
                rendered.append(_auto_failure_notice(item, verdict, reason, retrying=retrying))
                _AUTO_FAILURE_NOTIFIED.add(offer_id)
            continue
        app._TCLK_NOTICE_SEEN.add(offer_id)
        _AUTO_FAILURE_NOTIFIED.discard(offer_id)
        completed += 1
        rendered.append(_auto_success_notice(item, verdict, record))

    visible = rendered[:AUTO_NOTICE_LIMIT]
    hidden = max(0, completed - sum("AUTO-RESOLVE: PASS" in item for item in visible))
    if hidden:
        visible.append(f"🟡 tclk/1 自動レビュー: さらに{hidden}件をハッシュ付きで保存済み。手動転送は不要です。")
    return visible


_BaseControl = app.Control


class Control(_BaseControl):
    """Add authenticated read-only evidence resolver/history commands."""

    def command(self, user_id: str, text: str, channel_id: str | None = None) -> dict:
        parts = text.strip().split()
        if parts and parts[0] in {"/tclk-resolve", "/tclk-evidence"}:
            if channel_id is not None and channel_id != self.channel_id:
                return {"ok": False, "error": "wrong_channel", "message": "Control access denied."}
            if user_id not in self.allowed_ids:
                return {"ok": False, "error": "unauthorized", "message": "Control access denied."}
            if parts[0] == "/tclk-resolve" and len(parts) == 2:
                return {"ok": True, "data": {}, "message": _resolved_note_message(parts[1])}
            if parts[0] == "/tclk-evidence" and len(parts) in {1, 2}:
                return {"ok": True, "data": {}, "message": _stored_evidence_message(parts[1] if len(parts) == 2 else None)}
            usage = "Usage: /tclk-resolve <offer-id> | /tclk-evidence [offer-id]"
            return {"ok": False, "error": "invalid_args", "message": usage}

        result = super().command(user_id, text, channel_id)
        if result.get("ok") and parts and parts[0] == "/help" and len(parts) == 1:
            result["message"] += " | tclk evidence: /tclk-resolve <offer-id> /tclk-evidence [offer-id]"
        return result


def install() -> None:
    """Patch Discord review callbacks and automatic evidence handling only."""
    app.base.base.tclk_opportunities_message = _stored_opportunities_message
    app.base.base.tclk_offer_message = _stored_offer_message
    app._tclk_detail_message = _stored_detail_message
    app._tclk_best_message = _stored_best_message
    app._new_tclk_review_notices = _new_auto_review_notices
    app.Control = Control


def main() -> None:
    install()
    app.main()


if __name__ == "__main__":
    main()
