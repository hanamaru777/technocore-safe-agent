"""Compact, action-first Mission Control and status presentation.

Presentation-only overlay. It derives text from existing local read models and does
not change candidates, trust, Observer, Autopilot, signer/Vault state, or external
execution. Detailed telemetry remains available through existing explicit commands.
"""
from __future__ import annotations

import json

from . import discord_control as base
from . import discord_notice
from . import discord_outcome_scorecard as outcome
from . import precontest_supervisor

_INSTALLED = False


def _next_action(activity: dict) -> str:
    snapshot = activity["snapshot"]
    if snapshot.get("problems"):
        return "安全状態が戻るまで不可逆操作を進めない"
    pending = activity.get("bootstrap_pending") or []
    if pending:
        return f"/reply-approved {pending[0].get('candidate_id')} SEND を確認して実行"
    if (
        snapshot.get("auto", {}).get("enabled")
        and not snapshot.get("auto", {}).get("paused")
        and not activity.get("trusted")
        and activity.get("trust_candidates")
    ):
        return "/trust-candidates を確認"
    if activity.get("oldest_unresolved_direct"):
        return "/activity で未解決directを1件確認する"
    if snapshot.get("auto", {}).get("queued", 0):
        return "対応不要。署名済みqueue処理を待つ"
    return "対応不要"


def _now_state(activity: dict, latest: dict | None) -> str:
    snapshot = activity["snapshot"]
    if snapshot.get("problems"):
        return "安全状態を確認中"
    if latest is not None:
        return f"{base.counterpart_label(latest)} との直接やりとりを監視中"
    if snapshot.get("health") == "ok":
        return "公開roomを安全に監視中"
    return f"監視状態 {snapshot.get('health', 'unknown')} を確認中"


def _collaboration_rows(*, reconcile: bool) -> list[dict]:
    try:
        from . import collaboration

        return collaboration.records(
            include_tclk=False,
            reconcile_state=reconcile,
        )
    except (ImportError, RuntimeError):
        return []


def _latest_line(
    activity: dict,
    latest: dict | None,
    collaboration_rows: list[dict],
) -> str:
    if latest is not None:
        return base.conversation_line(latest, limit=120)
    if collaboration_rows:
        row = collaboration_rows[0]
        label = base.counterpart_label(row)
        stage = base.safe_excerpt(row.get("stage"), 32) or "状態不明"
        summary = (
            base.safe_excerpt(row.get("task_summary"), 100)
            or "安全な会話状態を監視中"
        )
        return f"{label} — {stage} — {summary}"
    return "直接のやりとりはまだありません"


def _precontest_blocker() -> str | None:
    """Return one human blocker from the local supervisor, never raw telemetry."""
    path = precontest_supervisor.state_path()
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        return "次回キャンペーン準備状態を確認できません"
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return "次回キャンペーン準備状態を確認できません"
    if not isinstance(value, dict) or value.get("schema_version") != precontest_supervisor.SCHEMA_VERSION:
        return "次回キャンペーン準備状態を確認できません"
    if value.get("candidate_discovery_status") == "error":
        return "新しい公式challenge候補の検知状態を確認できません"
    count = value.get("unregistered_candidate_count", 0)
    if isinstance(count, int) and count > 0:
        return "新しい公式challenge候補のルール固定・spec登録が未完了"
    status = value.get("status")
    labels = {
        "BLOCKED_LIVE": "開始済みキャンペーンの実行準備が未完了",
        "ACTION_REQUIRED": "72時間以内に開始するキャンペーンの準備が未完了",
        "PREP_REQUIRED": "次回キャンペーンの事前準備が未完了",
    }
    return labels.get(status)


def _mission_blocker(activity: dict) -> str:
    return _precontest_blocker() or base._mission_blocker(activity)


def mission_message(
    activity: dict | None = None,
    *,
    reconcile_collaboration: bool = True,
) -> str:
    """Six-line operator view: state, goal, one next action, blocker, latest."""
    activity = activity or base.activity_snapshot(
        sync_timeline=False,
        include_trust=True,
    )
    interactions = activity.get("interactions", [])
    latest = interactions[-1] if interactions else None
    collaboration_rows = _collaboration_rows(reconcile=reconcile_collaboration)
    return "\n".join(
        [
            "🎯 FLOP AGENT MISSION CONTROL",
            f"状態: {_now_state(activity, latest)}",
            f"目標: {base._mission_goal(activity, collaboration_rows, latest)}",
            f"次: {_next_action(activity)}",
            f"阻害: {_mission_blocker(activity)}",
            f"直近: {_latest_line(activity, latest, collaboration_rows)}",
        ]
    )


def _status_activity() -> dict:
    """Retain the existing bounded status fast path and conditional trust loading."""
    activity = base.populate_status_trust(
        outcome._activity_snapshot(
            sync_timeline=False,
            include_trust=False,
            status_fast=True,
        )
    )
    snapshot = activity["snapshot"]
    if (
        snapshot.get("direct", 0) > 0
        or int(snapshot.get("resident", {}).get("approved", 0)) > 0
    ):
        activity["oldest_unresolved_direct"] = outcome._unresolved_direct(activity)
    return activity


def _problem_label(value: object) -> str:
    text = str(value)
    labels = {
        "Autopilot OFF": "自動対応が停止",
        "Autopilot 一時停止": "自動対応が一時停止",
        "Resident監視遅延": "監視更新が遅延",
        "Observer監視異常": "監視に異常",
    }
    return labels.get(text, base.safe_excerpt(text, 100) or "状態不明")


def status_message() -> str:
    activity = _status_activity()
    snapshot = activity["snapshot"]
    problems = snapshot.get("problems") or []
    if problems:
        return discord_notice.render(
            "WARNING",
            "FLOP Agent 異常",
            impact="安全性に関わる異常があるため通常処理を保留します。",
            state=" / ".join(_problem_label(item) for item in problems),
            next_action="安全状態が戻るまで不可逆操作を進めない",
            detail="`/mission` で阻害要因、`/activity` で24時間詳細を確認できます。",
        )

    rendered = mission_message(activity, reconcile_collaboration=False)
    auto_label = (
        "ON"
        if snapshot.get("auto", {}).get("enabled")
        and not snapshot.get("auto", {}).get("paused")
        else "停止/一時停止"
    )
    detail = (
        "詳細: "
        f"監視:{'正常' if snapshot.get('health') == 'ok' else snapshot.get('health', 'unknown')} / "
        f"自動対応:{auto_label} / queue:{snapshot.get('auto', {}).get('queued', 0)} / "
        f"緊急:{snapshot.get('critical', 0)} — `/activity` で24時間成果、`/history` で会話"
    )
    return rendered + "\n" + detail


def install() -> None:
    """Install presentation-only replacements after the outcome scorecard."""
    global _INSTALLED
    if _INSTALLED:
        return
    base.mission_message = mission_message
    base.status_message = status_message
    _INSTALLED = True
