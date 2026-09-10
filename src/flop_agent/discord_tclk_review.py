"""Discord entrypoint that reviews retained tclk offers without a fresh parser probe.

Offer ingestion remains fail-closed in :mod:`tclk_watch`: a record only reaches local
state after signed-record verification and successful decoding by the pinned official
``@flop-labs/tclk`` parser.  Human review of that already-retained evidence must not be
hidden later just because an unrelated, synchronous Node health probe is briefly slow.

This module is presentation-only.  It never parses raw frames, signs, posts, accepts,
locks, reveals, pays, or changes protocol state.
"""
from __future__ import annotations

from . import discord_knowledge as app
from . import observer, tclk_triage, tclk_watch

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


def install() -> None:
    """Patch presentation callbacks only inside the Discord process."""
    app.base.base.tclk_opportunities_message = _stored_opportunities_message
    app.base.base.tclk_offer_message = _stored_offer_message
    app._tclk_detail_message = _stored_detail_message
    app._tclk_best_message = _stored_best_message


def main() -> None:
    install()
    app.main()


if __name__ == "__main__":
    main()
