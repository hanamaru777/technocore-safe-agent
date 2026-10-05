"""Compact presentation wrapper for the standalone Airdrop Discord notifier.

The underlying notifier still owns delivery, dedupe, backoff, health/readiness
state, and Discord transport. This module replaces renderers only, then calls the
same ``airdrop_notifier.run_once`` path used in Production.
"""
from __future__ import annotations

import json
import sys

from . import airdrop_notifier as notifier
from . import discord_notice

_INSTALLED = False
_ORIGINAL_RENDER_DIGEST = notifier.render_digest


def _severity_kind(value: object) -> str:
    return "WARNING" if str(value) == "MEDIUM" else "ACTION"


def _source_state(payload: dict) -> str:
    source = notifier._safe_text(payload.get("source"), 90) or "公式ソース"
    tier = notifier._safe_text(payload.get("tier"), 20) or "?"
    authority = notifier._safe_text(payload.get("authority"), 80) or "authority不明"
    return f"{source} / Tier {tier} / {authority}"


def render_alert(payload: dict) -> str:
    key = notifier._display_key(payload.get("key"))
    before = notifier._operator_preview(payload.get("before"), 150)
    after = notifier._operator_preview(payload.get("after"), 150)
    step = notifier._safe_text(payload.get("safe_next_step"), 360)
    source_url = payload.get("source_url")
    detail = None
    if isinstance(source_url, str) and source_url.startswith("https://"):
        detail = "公式: " + notifier._safe_text(source_url, 340)
    else:
        event_id = notifier._short_event_id(payload.get("event_id"))
        detail = f"event {event_id}" if event_id else None

    deadline = payload.get("deadline")
    deadline_text = notifier._preview(deadline, 240) if isinstance(deadline, dict) else None
    return discord_notice.render(
        _severity_kind(payload.get("severity")),
        f"FLOP Airdrop: {notifier._safe_text(key, 48)} 更新",
        impact=notifier._safe_text(f"{before} → {after}", 400),
        state=_source_state(payload),
        next_action=step or "公式根拠を確認し、binding actionは別承認まで実行しない",
        deadline=deadline_text,
        detail=detail,
    )[: notifier.MAX_CONTENT]


def _selected_rows(items: list[dict], selected: list[str]) -> list[dict]:
    wanted = set(selected)
    rows: list[dict] = []
    for item in items:
        payload = item.get("payload") if isinstance(item, dict) else None
        if not isinstance(payload, dict):
            continue
        if payload.get("event_id") in wanted:
            rows.append(payload)
    return rows


def render_digest(items: list[dict]) -> tuple[str, list[str]]:
    # Delegate selection to the original renderer so atomic delivery bookkeeping
    # and max-event behavior remain byte-for-byte governed by the existing path.
    _legacy_text, selected = _ORIGINAL_RENDER_DIGEST(items)
    rows = _selected_rows(items, selected)
    summaries: list[str] = []
    for payload in rows[:2]:
        key = notifier._display_key(payload.get("key"))
        before = notifier._operator_preview(payload.get("before"), 85)
        after = notifier._operator_preview(payload.get("after"), 85)
        summaries.append(notifier._safe_text(f"{key}: {before} → {after}", 180))
    hidden = max(0, len(rows) - len(summaries))
    state = " / ".join(summaries) if summaries else "MEDIUM更新を検出"
    if hidden:
        state = notifier._safe_text(f"{state} / ほか{hidden}件", 400)

    short_ids = [notifier._short_event_id(value) for value in selected[:3]]
    detail = "events: " + ", ".join(short_ids)
    if len(selected) > 3:
        detail += f" / ほか{len(selected) - 3}件"
    return (
        discord_notice.render(
            "WARNING",
            "FLOP Airdrop Radar まとめ",
            impact=f"MEDIUM更新 {len(selected)}件をまとめました。",
            state=state,
            next_action="対応不要。必要な更新だけ公式根拠を確認する",
            detail=notifier._safe_text(detail, 400),
        )[: notifier.MAX_CONTENT],
        selected,
    )


def _health_reason(status: dict) -> str:
    if status.get("outcome") == "scan_failed":
        return "公式ソースの監視スキャンに失敗"
    if status.get("outcome") == "blocked_integrity":
        return "証拠整合性の確認で停止"
    if status.get("outcome") == "alert_routing_failed":
        return "通知振り分け処理で異常"
    if status.get("staging_outcome") == "failed":
        return "Action候補の準備処理で異常"
    if status.get("heartbeat_stale") and status.get("last_completed_at"):
        age = status.get("heartbeat_age_seconds")
        return f"監視更新が遅延（{age}秒）" if age is not None else "監視更新が遅延"
    return "監視状態を確認中"


def render_health_problem(status: dict) -> str:
    last = notifier._safe_text(status.get("last_completed_at"), 80) or "不明"
    return discord_notice.render(
        "WARNING",
        "FLOP Airdrop Radar監視異常",
        impact="公式条件の検知が一時的に不完全な可能性があります。",
        state=_health_reason(status),
        next_action="FLOPへの操作はせず、自動回復を待つ",
        detail=f"最終完了 {last}",
    )[: notifier.MAX_CONTENT]


def render_health_recovery(status: dict) -> str:
    last = notifier._safe_text(status.get("last_completed_at"), 80) or "不明"
    return discord_notice.render(
        "DONE",
        "FLOP Airdrop Radar監視復旧",
        impact="公式条件の監視が通常状態へ戻りました。",
        state="監視を継続しています。FLOPへの自動操作はありません。",
        next_action="対応不要",
        detail=f"最終完了 {last}",
    )[: notifier.MAX_CONTENT]


def _readiness_state(snapshot: dict) -> str:
    labels = {"BLOCKED": "保留", "IMPLEMENTATION_READY": "実装準備完了"}
    return " / ".join(
        f"{action}={labels.get(snapshot['actions'][action]['state'], snapshot['actions'][action]['state'])}"
        for action in notifier.READINESS_ACTIONS
    )


def _readiness_changes(previous: dict, current: dict) -> tuple[list[str], list[str], list[str]]:
    transitions: list[str] = []
    removed: list[str] = []
    added: list[str] = []
    for action in notifier.READINESS_ACTIONS:
        before = previous["actions"][action]
        after = current["actions"][action]
        if before == after:
            continue
        transitions.append(f"{action}: {before['state']} → {after['state']}")
        removed.extend(sorted(set(before["blockers"]) - set(after["blockers"])))
        added.extend(sorted(set(after["blockers"]) - set(before["blockers"])))
    return transitions, removed, added


def render_readiness_change(previous: dict, current: dict) -> str:
    transitions, removed, added = _readiness_changes(previous, current)
    ready_now = [
        action
        for action in notifier.READINESS_ACTIONS
        if current["actions"][action]["state"] == "IMPLEMENTATION_READY"
        and previous["actions"][action]["state"] != "IMPLEMENTATION_READY"
    ]
    transition_text = notifier._safe_text(" / ".join(transitions) or "readiness条件が更新", 300)

    if ready_now:
        return discord_notice.render(
            "ACTION",
            "FLOP Adapter Readiness: IMPLEMENTATION_READY",
            impact=(
                f"{transition_text}。IMPLEMENTATION_READYは実行許可ではありません。"
            ),
            state=_readiness_state(current),
            next_action="実行せず、別監査と承認を待つ",
            detail="実adapter実装・登録・外部writeは別の監査と承認が必要です。",
        )[: notifier.MAX_CONTENT]

    details: list[str] = []
    if removed:
        details.append("解消: " + notifier._safe_text(", ".join(removed), 180))
    if added:
        details.append("追加: " + notifier._safe_text(", ".join(added), 180))
    detail = " / ".join(details) or "blocker構成が更新されました。"
    return discord_notice.render(
        "WARNING",
        "FLOP Adapter Readiness 更新",
        impact=transition_text,
        state=_readiness_state(current),
        next_action="対応不要。公式条件の更新を待つ",
        detail=notifier._safe_text(detail, 400),
    )[: notifier.MAX_CONTENT]


def install() -> None:
    """Patch only render functions; state/delivery code remains in notifier."""
    global _INSTALLED
    if _INSTALLED:
        return
    notifier.render_alert = render_alert
    notifier.render_digest = render_digest
    notifier._render_health_problem = render_health_problem
    notifier._render_health_recovery = render_health_recovery
    notifier._render_readiness_change = render_readiness_change
    _INSTALLED = True


def main() -> None:
    install()
    try:
        output = notifier.run_once()
        print(json.dumps(output, ensure_ascii=False, indent=2))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
