"""Outcome-focused Discord presentation for useful Agent relationships.

Presentation/read-only only. This module derives its scorecard from existing durable
Resident candidate state, acknowledged Autopilot receipts, trusted relationships,
already-recorded collaboration state, repository-owned public artifact metadata and
Observer health. It never signs, posts, approves, mutates protocol state, follows URLs,
or changes safety/rate/continuity gates.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from . import collaboration
from . import discord_control as base
from . import resident

_INSTALLED = False
_ORIGINAL_ACTIVITY = base.activity_snapshot
_REPO_ROOT = Path(__file__).resolve().parents[2]
_PUBLIC_PROFILE_PATH = _REPO_ROOT / "public-profile.json"
_MAX_PUBLIC_ARTIFACTS = 16


def _stamp(value: object) -> datetime | None:
    parsed = base._parse_time(value)
    if parsed is not None and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _collaboration_counts() -> tuple[int, int]:
    """Read already-durable collaboration state without reconciling or mutating it."""
    try:
        state = collaboration.load_state()
    except RuntimeError:
        return 0, 0
    records = [
        item
        for item in state.get("records", {}).values()
        if isinstance(item, dict)
    ]
    active = sum(
        item.get("stage") in {"replied", "task_candidate", "human_review", "active"}
        for item in records
    )
    completed = sum(item.get("stage") == "completed" for item in records)
    completed += sum(
        isinstance(item, dict)
        for item in state.get("completed_evidence_index", [])
    )
    return active, completed


def _repo_file_exists(path_value: object) -> bool:
    """Accept only an existing relative file inside the checked-out repository."""
    if not isinstance(path_value, str) or not path_value.strip():
        return False
    relative = Path(path_value)
    if relative.is_absolute() or ".." in relative.parts:
        return False
    root = _REPO_ROOT.resolve()
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return candidate.is_file()


def _public_artifact_count() -> int:
    """Count explicit published utilities backed by repository files only."""
    try:
        payload = json.loads(_PUBLIC_PROFILE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return 0
    knowledge = payload.get("knowledge") if isinstance(payload, dict) else None
    artifacts = knowledge.get("public_artifacts") if isinstance(knowledge, dict) else None
    if not isinstance(artifacts, list):
        return 0

    count = 0
    for item in artifacts[:_MAX_PUBLIC_ARTIFACTS]:
        if not isinstance(item, dict):
            continue
        if item.get("kind") != "public_utility" or item.get("status") != "published":
            continue
        artifact_id = item.get("id")
        if not isinstance(artifact_id, str) or not artifact_id.strip():
            continue
        if not _repo_file_exists(item.get("documentation")):
            continue
        if not _repo_file_exists(item.get("entrypoint")):
            continue
        count += 1
    return count


def _unresolved_direct(activity: dict) -> dict | None:
    """Return the oldest live signed direct request without a recorded reply."""
    resolved = {
        item.get("conversation_id")
        for item in activity.get("sent", [])
        if isinstance(item, dict) and item.get("conversation_id")
    }
    now_value = datetime.now(UTC)
    try:
        state = resident.load_state()
    except RuntimeError:
        return None

    rows: list[dict] = []
    for item in state.get("candidates", {}).values():
        if not isinstance(item, dict) or item.get("status") not in {"pending", "approved"}:
            continue
        signals = item.get("signals", {})
        direct = (
            isinstance(signals, dict)
            and signals.get("direct_public_signed") is True
        ) or item.get("category") == "direct_inbound"
        if not direct or item.get("candidate_id") in resolved:
            continue
        expiry = _stamp(item.get("expires_at"))
        created = _stamp(item.get("created_at"))
        if expiry is None or expiry <= now_value or created is None:
            continue
        rows.append(item)

    if not rows:
        return None
    oldest = min(rows, key=lambda item: _stamp(item.get("created_at")) or now_value)
    return {
        "candidate_id": oldest.get("candidate_id"),
        "fingerprint": oldest.get("fingerprint"),
        "room": oldest.get("room"),
        "seq": oldest.get("seq"),
        "created_at": oldest.get("created_at"),
    }


def _activity_snapshot(*, sync_timeline: bool = True, include_trust: bool = True) -> dict:
    activity = dict(
        _ORIGINAL_ACTIVITY(
            sync_timeline=sync_timeline,
            include_trust=include_trust,
        )
    )
    collaboration_active, collaboration_completed = _collaboration_counts()
    activity["signed_direct_requests"] = len(activity.get("received", []))
    activity["acked_replies"] = len(activity.get("sent", []))
    activity["active_trusted"] = len(activity.get("trusted", []))
    activity["collaboration_active"] = collaboration_active
    activity["collaboration_completed"] = collaboration_completed
    activity["public_artifacts"] = _public_artifact_count()
    activity["oldest_unresolved_direct"] = _unresolved_direct(activity)
    return activity


def _non_action_reason(activity: dict) -> str:
    reasons = activity.get("reasons", {})
    if isinstance(reasons, dict) and reasons:
        return max(reasons, key=reasons.get)
    return activity.get("zero_reason") or "なし"


def _oldest_line(activity: dict) -> str:
    item = activity.get("oldest_unresolved_direct")
    if not isinstance(item, dict):
        return "未解決direct: なし"
    age = base.human_age(item.get("created_at"))
    return (
        "未解決direct: "
        f"{base.short_fingerprint(item.get('fingerprint'))} / {age} / "
        f"{item.get('room', '?')} #{item.get('seq', '?')}"
    )


def _relationship_line(activity: dict) -> str:
    return (
        "関係24h: "
        f"署名direct {activity['signed_direct_requests']} / "
        f"ACK返信 {activity['acked_replies']} / "
        f"ユニーク相手 {activity['counterparts']}人"
    )


def _durable_line(activity: dict) -> str:
    return (
        "継続成果: "
        f"active trust {activity['active_trusted']} / "
        f"協業進行 {activity['collaboration_active']} / "
        f"協業完了 {activity['collaboration_completed']} / "
        f"公開artifact {activity['public_artifacts']}"
    )


def _status_message() -> str:
    activity = _activity_snapshot(sync_timeline=False, include_trust=True)
    snapshot = activity["snapshot"]
    interactions = activity.get("interactions", [])
    latest = interactions[-1] if interactions else None
    needs_attention = bool(
        snapshot["problems"]
        or snapshot["critical"]
        or activity.get("oldest_unresolved_direct")
        or snapshot["auto"].get("queued", 0)
    )
    icon = "🔴" if snapshot["problems"] else "🟡" if needs_attention else "🟢"
    title = "異常" if snapshot["problems"] else "確認あり" if needs_attention else "正常"
    auto_label = (
        "ON"
        if snapshot["auto"].get("enabled") and not snapshot["auto"].get("paused")
        else "停止/一時停止"
    )
    lines = [
        f"{icon} FLOP Agent {title}",
        f"監視: {'監視中' if snapshot['health'] == 'ok' else '監視状態 ' + str(snapshot['health'])}",
        f"Autopilot: {auto_label}",
        _relationship_line(activity),
        _durable_line(activity),
        f"自動投稿: {activity['posts']}（24h / safety cap 6、目標ではありません）",
        _oldest_line(activity),
        f"queue: {snapshot['auto'].get('queued', 0)} / 緊急 {snapshot['critical']}",
        f"主な非アクション理由: {_non_action_reason(activity)}",
        f"最終監視: {snapshot['last_refresh_age']}",
    ]
    if latest:
        lines.append(
            "最終やりとり: "
            f"{base.short_fingerprint(latest.get('fingerprint'))} / "
            f"{latest.get('direction')} / {base.human_age(latest.get('at'))}"
        )
    if snapshot["problems"]:
        lines.extend([
            "異常: " + " / ".join(snapshot["problems"]),
            "結論: 対応が必要です。詳細は /status を再確認してください。",
        ])
    elif needs_attention:
        lines.append("結論: 未解決directまたはqueueを確認してください。")
    else:
        lines.append("結論: 対応不要。そのまま稼働中。")
    return "\n".join(lines)


def _activity_message() -> str:
    activity = _activity_snapshot()
    snapshot = activity["snapshot"]
    recent = activity.get("interactions", [])[-3:]
    # The existing discord_collaboration overlay appends its detailed collaboration
    # pipeline line to /activity. Keep this renderer focused on 24h relationship
    # outcomes so the final layered command does not report collaboration twice.
    lines = [
        "📊 FLOP Agent 24時間アウトカム",
        f"監視: {'監視中' if snapshot['health'] == 'ok' else '監視状態 ' + str(snapshot['health'])}",
        _relationship_line(activity),
        f"active trust: {activity['active_trusted']}",
        f"公開artifact: {activity['public_artifacts']}",
        f"自動投稿: {activity['posts']}（24h / safety cap 6、目標ではありません）",
        _oldest_line(activity),
        f"主な非アクション理由: {_non_action_reason(activity)}",
        f"queue: {snapshot['auto'].get('queued', 0)}",
    ]
    if recent:
        lines.append("直近のやりとり:")
        for item in recent:
            content = (
                item.get("summary", "")
                if item.get("direction") == "送信" and item.get("exact_text")
                else base.safe_excerpt(item.get("summary", ""), 80)
            )
            lines.append(
                f"- {base.short_fingerprint(item.get('fingerprint'))} / "
                f"{item.get('direction')} / {content}"
            )
    else:
        lines.append("直近の直接やりとり: なし")
    return "\n".join(lines)


def _digest(_control) -> str:
    activity = _activity_snapshot()
    snapshot = activity["snapshot"]
    current_metrics = base._observer_metrics()
    ui = base.load_ui_state()
    baseline = ui.get("digest_baseline") or {
        **current_metrics,
        "at": datetime.now(UTC).isoformat(),
    }
    new_gaps = max(
        0,
        current_metrics["message_gaps"] - int(baseline.get("message_gaps", 0)),
    )
    ui["digest_baseline"] = {**current_metrics, "at": datetime.now(UTC).isoformat()}
    ui["pending_gap_delta"] = 0
    base.save_ui_state(ui)

    attention = snapshot["critical"] + int(activity.get("oldest_unresolved_direct") is not None)
    if snapshot["problems"]:
        icon, title, conclusion = "🔴", "異常", "対応が必要です。/status を確認してください。"
    elif attention or new_gaps:
        icon, title, conclusion = "🟡", "確認あり", "確認事項があります。/status を確認してください。"
    else:
        icon, title, conclusion = "🟢", "正常", "対応不要。そのまま稼働中。"

    recent = activity.get("interactions", [])[-3:]
    if recent:
        interaction_line = (
            "直近のやりとり: "
            + " / ".join(
                f"{base.short_fingerprint(item.get('fingerprint'))} "
                f"{item.get('direction')} {base.safe_excerpt(item.get('summary', ''), 60)}"
                for item in recent
            )
            + "\n詳細: /history\n"
        )
    else:
        interaction_line = "直近の直接やりとり: なし（詳細: /history）\n"

    return (
        f"{icon} FLOP Agent 6時間アウトカム（{title}）\n"
        f"{_relationship_line(activity)}\n"
        f"{_durable_line(activity)}\n"
        f"自動投稿 {activity['posts']}（24h / safety cap 6、目標ではありません） / "
        f"新しいgap +{new_gaps} / queue {snapshot['auto'].get('queued', 0)}\n"
        f"{_oldest_line(activity)}\n"
        f"主な非アクション理由: {_non_action_reason(activity)}\n"
        f"最終監視: {snapshot['last_refresh_age']}\n"
        + interaction_line
        + f"結論: {conclusion}"
    )


def install() -> None:
    """Install presentation-only wrappers once."""
    global _INSTALLED
    if _INSTALLED:
        return
    base.activity_snapshot = _activity_snapshot
    base.status_message = _status_message
    base.activity_message = _activity_message
    base.Control.digest = _digest
    _INSTALLED = True
