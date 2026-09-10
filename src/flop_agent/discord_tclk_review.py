"""Discord entrypoint for retained tclk review plus fixed-origin Note evidence.

Offer ingestion remains fail-closed in :mod:`tclk_watch`: a record only reaches local
state after signed-record verification and successful decoding by the pinned official
``@flop-labs/tclk`` parser. Human review of that already-retained evidence must not be
hidden later just because an unrelated synchronous Node health probe is briefly slow.

The optional ``/tclk-resolve`` path may read at most two documented same-origin
Technocore Notes through :mod:`tclk_note_review`. It never signs, posts, accepts, locks,
reveals, pays, executes task text, or follows arbitrary URLs.
"""
from __future__ import annotations

from . import discord_knowledge as app
from . import observer, tclk_note_review, tclk_triage, tclk_watch

VALIDATION_NOTE = (
    "parser validation: retained at ingestion; this review command does not re-probe "
    "the live bridge."
)


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


def _sanitize_note(value: object) -> str:
    return app.base.base.safe_excerpt(value, tclk_note_review.MAX_NOTE_BYTES) or "-"


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


_BaseControl = app.Control


class Control(_BaseControl):
    """Add one authenticated human-triggered evidence resolver command."""

    def command(self, user_id: str, text: str, channel_id: str | None = None) -> dict:
        parts = text.strip().split()
        if parts and parts[0] == "/tclk-resolve":
            if channel_id is not None and channel_id != self.channel_id:
                return {"ok": False, "error": "wrong_channel", "message": "Control access denied."}
            if user_id not in self.allowed_ids:
                return {"ok": False, "error": "unauthorized", "message": "Control access denied."}
            if len(parts) != 2:
                return {"ok": False, "error": "invalid_args", "message": "Usage: /tclk-resolve <offer-id>"}
            return {"ok": True, "data": {}, "message": _resolved_note_message(parts[1])}

        result = super().command(user_id, text, channel_id)
        if result.get("ok") and parts and parts[0] == "/help" and len(parts) == 1:
            result["message"] += " | tclk evidence: /tclk-resolve <offer-id>"
        return result


def install() -> None:
    """Patch Discord review callbacks and the authenticated control subclass only."""
    app.base.base.tclk_opportunities_message = _stored_opportunities_message
    app.base.base.tclk_offer_message = _stored_offer_message
    app._tclk_detail_message = _stored_detail_message
    app._tclk_best_message = _stored_best_message
    app.Control = Control


def main() -> None:
    install()
    app.main()


if __name__ == "__main__":
    main()
