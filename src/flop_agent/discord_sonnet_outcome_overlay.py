"""Presentation-only bridge from Sonnet Agent cockpit events into outcome summaries.

The legacy outcome scorecard counts Resident/Autopilot relationship records. Dedicated
Sonnet one-shot sends and signed room replies are surfaced by ``discord_agent_activity``
but intentionally do not enter Resident candidate/autopilot state, so the old 6-hour
summary could truthfully render the legacy counters as zero while Discord had just shown
real Agent send/receive activity.

This overlay does not reinterpret those events as legacy ACKs. Instead it adds a clearly
labelled cumulative Sonnet-cockpit event count and suppresses the misleading
"no direct interaction" wording when the cockpit has durable important-message IDs.
It reads only presentation state; no network, signer, protocol write, or safety state.
"""
from __future__ import annotations

from . import discord_agent_activity, discord_outcome_scorecard as score

_INSTALLED = False
_ORIGINAL_SNAPSHOT = None
_ORIGINAL_RELATIONSHIP_LINE = None
_ORIGINAL_ACTIVITY_MESSAGE = None
_ORIGINAL_DIGEST = None


def _sonnet_event_count() -> int:
    try:
        state = discord_agent_activity._load()
    except Exception:
        return 0
    notified = state.get("notified", []) if isinstance(state, dict) else []
    return sum(
        isinstance(item, str) and item.startswith("msg:")
        for item in notified
    )


def _activity_snapshot(*, sync_timeline: bool = True, include_trust: bool = True, status_fast: bool = False) -> dict:
    assert _ORIGINAL_SNAPSHOT is not None
    result = dict(
        _ORIGINAL_SNAPSHOT(
            sync_timeline=sync_timeline,
            include_trust=include_trust,
            status_fast=status_fast,
        )
    )
    result["sonnet_cockpit_events"] = _sonnet_event_count()
    return result


def _relationship_line(activity: dict) -> str:
    assert _ORIGINAL_RELATIONSHIP_LINE is not None
    legacy = _ORIGINAL_RELATIONSHIP_LINE(activity)
    return legacy + f" / Sonnet重要イベント累計 {int(activity.get('sonnet_cockpit_events', 0))}"


def _activity_message() -> str:
    assert _ORIGINAL_ACTIVITY_MESSAGE is not None
    rendered = _ORIGINAL_ACTIVITY_MESSAGE()
    count = _sonnet_event_count()
    if count and "直近の直接やりとり: なし" in rendered:
        rendered = rendered.replace(
            "直近の直接やりとり: なし",
            f"Sonnet Agent重要イベント: 累計{count}件（詳細はAgent送受信通知）",
        )
    return rendered


def _digest(control) -> str:
    assert _ORIGINAL_DIGEST is not None
    rendered = _ORIGINAL_DIGEST(control)
    count = _sonnet_event_count()
    if count and "直近の直接やりとり: なし（詳細: /history）" in rendered:
        rendered = rendered.replace(
            "直近の直接やりとり: なし（詳細: /history）",
            f"Sonnet Agent重要イベント: 累計{count}件（詳細はAgent送受信通知）",
        )
    return rendered


def install() -> None:
    """Install after ``discord_outcome_scorecard.install``; idempotent."""
    global _INSTALLED, _ORIGINAL_SNAPSHOT, _ORIGINAL_RELATIONSHIP_LINE
    global _ORIGINAL_ACTIVITY_MESSAGE, _ORIGINAL_DIGEST
    if _INSTALLED:
        return
    _ORIGINAL_SNAPSHOT = score._activity_snapshot
    _ORIGINAL_RELATIONSHIP_LINE = score._relationship_line
    _ORIGINAL_ACTIVITY_MESSAGE = score._activity_message
    _ORIGINAL_DIGEST = score._digest

    score._activity_snapshot = _activity_snapshot
    score._relationship_line = _relationship_line
    score._activity_message = _activity_message
    score._digest = _digest
    score.base.activity_snapshot = _activity_snapshot
    score.base.activity_message = _activity_message
    score.base.Control.digest = _digest
    _INSTALLED = True
