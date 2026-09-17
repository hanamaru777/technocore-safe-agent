"""Coalesce short health flaps into one Discord incident plus final recovery.

This is presentation-only. It wraps the existing Discord health-notice method,
reads the same local health snapshot, and stores a tiny UI-only incident state.
It never changes Observer health, Autopilot policy, signing, posting, recovery,
or any protected continuity counter.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import discord_agent_activity, discord_control, observer, resident

SCHEMA_VERSION = 1
STATE_FILE = "discord-health-coalescing.json"
RECOVERY_GRACE = timedelta(minutes=5)
MAX_SIGNATURES = 8
_INSTALLED = False
_ORIGINAL_SYSTEM_NOTICES = None


def state_path() -> Path:
    return resident.resident_dir() / STATE_FILE


def _default_state() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "incident_open": False,
        "opened_at": None,
        "recovery_since": None,
        "seen_red_signatures": [],
    }


def _load_state() -> dict:
    path = state_path()
    if not path.exists():
        return _default_state()
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        # Presentation state must fail open: never hide a real alert because the
        # coalescer's own tiny state file is unreadable.
        return _default_state()
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != SCHEMA_VERSION
        or not isinstance(value.get("incident_open"), bool)
        or not isinstance(value.get("seen_red_signatures"), list)
    ):
        return _default_state()
    defaults = _default_state()
    for key, default in defaults.items():
        value.setdefault(key, default)
    value["seen_red_signatures"] = [
        item for item in value["seen_red_signatures"] if isinstance(item, str)
    ][-MAX_SIGNATURES:]
    return value


def _save_state(value: dict) -> None:
    value["seen_red_signatures"] = value.get("seen_red_signatures", [])[-MAX_SIGNATURES:]
    observer.atomic_json_write(state_path(), value, compact=True)


def _stamp(value: object) -> datetime | None:
    parsed = observer.parse_time(value) if isinstance(value, str) else None
    if parsed is not None and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _red_signature(notice: str) -> str:
    lines = [line.strip() for line in notice.splitlines() if line.strip()]
    # Ignore the common title and volatile age line. The remaining first stable
    # line identifies degraded/stale/paused/off incidents well enough for dedupe.
    for line in lines[1:]:
        if line.startswith("最終正常監視の確認:") or line.startswith("最終監視:"):
            continue
        if line.startswith("次にやること:"):
            continue
        return line[:160]
    return "health_incident"


def _is_red_health(notice: str) -> bool:
    return notice.startswith("🔴 FLOP Agent 異常")


def _is_green_health(notice: str) -> bool:
    return notice.startswith("🟢 FLOP Agent 復旧") or notice.startswith("🟢 FLOP Agent 監視復旧")


def _notice_value(notice: str, prefix: str) -> str | None:
    for line in notice.splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped[len(prefix):].strip()
    return None


def _humanize_notice(notice: str) -> str:
    """Render health-only notices for a non-operator without changing semantics."""
    if _is_red_health(notice):
        last_ok = _notice_value(notice, "最終正常監視の確認:")
        last_seen = _notice_value(notice, "最終監視:")
        reference = last_ok or last_seen

        if "Autopilot OFF" in notice:
            title = "🔴 自動対応が停止"
            action = "今やること: `/status` で状態確認"
            meaning = "意味: 自動対応機能がOFFになっています。"
        elif "Autopilot 一時停止" in notice:
            title = "🔴 自動対応が一時停止"
            action = "今やること: `/status` で状態確認"
            meaning = "意味: 自動対応機能が一時停止しています。"
        elif "監視状態 degraded" in notice:
            title = "🔴 監視が不安定"
            action = "今やること: 基本は待機"
            meaning = "意味: 監視データが5分以上、不安定な状態です。"
        elif "最終監視 " in notice or "Resident監視遅延" in notice:
            title = "🔴 監視更新が遅れています"
            action = "今やること: `/status` で状態確認"
            meaning = "意味: 監視データの更新が通常より遅れています。"
        else:
            title = "🔴 監視に異常"
            action = "今やること: `/status` で状態確認"
            meaning = "意味: 監視または自動対応で確認が必要な状態を検出しました。"

        lines = [title, "", action, meaning]
        if reference:
            lines.append(f"参考: 最終確認 {reference}")
        if "基本は待機" in action:
            lines.append("必要なら: `/status` で詳細確認")
        return "\n".join(lines)

    if _is_green_health(notice):
        return (
            "🟢 監視復旧\n\n"
            "今やること: なし\n"
            "意味: 監視と自動対応が通常状態に戻りました。"
        )

    if notice.startswith("🟡 FLOP Agent 通信欠落を複数検出"):
        count = _notice_value(notice, "未通知gap:")
        last_seen = _notice_value(notice, "最終監視:")
        lines = [
            "🟡 通信抜けを複数検出",
            "",
            "今やること: 基本は待機",
            "意味: 短時間に複数の通信抜けを検出しました。単発の通信抜けは自動でまとめています。",
        ]
        details = []
        if count:
            details.append(f"今回 {count.lstrip('+')}件")
        if last_seen:
            details.append(f"最終監視 {last_seen}")
        if details:
            lines.append("参考: " + " / ".join(details))
        lines.append("必要なら: `/status` で詳細確認")
        return "\n".join(lines)

    return notice


def _healthy_now() -> bool:
    snapshot = discord_control._health_snapshot()
    return snapshot.get("health") == "ok" and not snapshot.get("problems")


def _final_recovery_notice() -> str:
    return (
        "🟢 監視復旧\n\n"
        "今やること: なし\n"
        "意味: 監視と自動対応が5分間安定したため、通常状態に戻りました。"
    )


def _coalesced_system_notices(control) -> list[str]:
    """Health-only coalescer. Agent polling is added by the installed wrapper."""
    assert _ORIGINAL_SYSTEM_NOTICES is not None
    raw = _ORIGINAL_SYSTEM_NOTICES(control)
    state = _load_state()
    now_value = datetime.now(UTC)
    output: list[str] = []

    for notice in raw:
        if _is_red_health(notice):
            signature = _red_signature(notice)
            if not state["incident_open"]:
                state["incident_open"] = True
                state["opened_at"] = now_value.isoformat()
                state["seen_red_signatures"] = [signature]
                output.append(_humanize_notice(notice))
            elif signature not in state["seen_red_signatures"]:
                # Do not hide a materially new failure class while an incident is
                # already open. Repeat flaps of the same class stay silent.
                state["seen_red_signatures"].append(signature)
                output.append(_humanize_notice(notice))
            state["recovery_since"] = None
            continue

        if _is_green_health(notice) and state["incident_open"]:
            # The base UI resolves on the first healthy sample. Suppress that
            # premature green; this wrapper closes only after a stable grace.
            if state.get("recovery_since") is None:
                state["recovery_since"] = now_value.isoformat()
            continue

        output.append(_humanize_notice(notice))

    if state["incident_open"]:
        if _healthy_now():
            recovery_since = _stamp(state.get("recovery_since"))
            if recovery_since is None:
                state["recovery_since"] = now_value.isoformat()
            elif now_value - recovery_since >= RECOVERY_GRACE:
                output.append(_final_recovery_notice())
                state = _default_state()
        else:
            # Any renewed unhealthy sample keeps the same incident open and starts
            # the healthy grace from zero without generating another red merely
            # because the base UI toggled in between.
            state["recovery_since"] = None

    _save_state(state)
    return output


def _system_notices_with_agent_activity(control) -> list[str]:
    # main() installs the outcome scorecard after this health wrapper. Install the
    # Sonnet bridge lazily on the first notice poll so it always wraps the final
    # scorecard functions rather than being overwritten by scorecard.install().
    from . import discord_sonnet_outcome_overlay
    discord_sonnet_outcome_overlay.install()
    return [
        *_coalesced_system_notices(control),
        *discord_agent_activity.poll_notices(),
    ]


def install() -> None:
    """Patch only Discord presentation, exactly once."""
    global _INSTALLED, _ORIGINAL_SYSTEM_NOTICES
    if _INSTALLED:
        return
    _ORIGINAL_SYSTEM_NOTICES = discord_control.Control.system_notices
    discord_control.Control.system_notices = _system_notices_with_agent_activity
    _INSTALLED = True
