"""Read-only Close Call progress notices for the existing Discord control plane."""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Callable

from . import close_call, observer, resident

LOG = logging.getLogger(__name__)

SCHEMA_VERSION = 1
STATE_FILE = "close1-discord-progress.json"
POLL_INTERVAL_SECONDS = 5 * 60
STATUS_INTERVAL_SECONDS = 30 * 60
TOP3_MATERIAL_DELTA = Decimal("10")


def state_path() -> Path:
    return resident.resident_dir() / STATE_FILE


def _default_state() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "last_attempt_at": None,
        "last_success_at": None,
        "last_notice_at": None,
        "last_fresh": None,
        "last_top3_cutoff": None,
        "last_sweep": None,
        "failure_count": 0,
        "last_failure_notice_at": None,
    }


def _load_state() -> dict:
    path = state_path()
    if not path.exists():
        return _default_state()
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        LOG.warning("Close Call Discord progress state unreadable; rebuilding presentation state")
        return _default_state()
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        return _default_state()
    result = _default_state()
    result.update(data)
    return result


def _save_state(state: dict) -> None:
    try:
        observer.atomic_json_write(state_path(), state, compact=True)
    except OSError:
        LOG.exception("Close Call Discord progress state could not be persisted")


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    parsed = observer.parse_time(value)
    if parsed is None:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _elapsed(current: datetime, value: object) -> float | None:
    parsed = _parse_time(value)
    if parsed is None:
        return None
    return (current - parsed.astimezone(UTC)).total_seconds()


def _decimal_or_none(value: object) -> Decimal | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = Decimal(value)
    except Exception:
        return None
    return parsed if parsed.is_finite() else None


def _leader_score(snapshot: close_call.LiveSnapshot) -> Decimal | None:
    return snapshot.pnl_top[0][1] if snapshot.pnl_top else None


def render_snapshot(snapshot: close_call.LiveSnapshot, *, reason: str = "定期進捗") -> str:
    leader = _leader_score(snapshot)
    cutoff = snapshot.top3_cutoff
    freshness = "PASS" if snapshot.reference_fresh_for_strategy else "STOP"
    decision = (
        "戦略監視継続。exact trade候補はChatGPT側で別評価し、binding取引は個別承認後のみ。"
        if snapshot.reference_fresh_for_strategy
        else "DO_NOT_TRADE。基準価格がローカル安全基準120秒を超えています。"
    )
    return "\n".join([
        f"🟦 Close Call 進捗 — {reason}",
        f"sweep: {snapshot.sweep}",
        f"NVDA reference: {snapshot.reference} / age {snapshot.reference_age_seconds}s / freshness {freshness}",
        f"visible leader: {('+' + str(leader)) if leader is not None else 'n/a'} POLF",
        f"visible top3 cutoff: {('+' + str(cutoff)) if cutoff is not None else 'n/a'} POLF",
        f"positions: long {snapshot.longs} / short {snapshot.shorts} / open {snapshot.open_notional} POLF",
        f"現在判断: {decision}",
    ])


def status_message(
    *,
    fetcher: Callable[[], close_call.LiveSnapshot] | None = None,
) -> str:
    fetch = fetcher or close_call.fetch_live_snapshot
    try:
        snapshot = fetch()
    except Exception as error:
        return (
            "🟡 Close Call status unavailable (read-only)\n"
            f"reason: {type(error).__name__}\n"
            "取引・署名・POSTは行っていません。"
        )
    return render_snapshot(snapshot, reason="手動確認")


def periodic_notices(
    *,
    now: datetime | None = None,
    fetcher: Callable[[], close_call.LiveSnapshot] | None = None,
) -> list[str]:
    """Return compact notices; never signs, posts, or changes contest state."""
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("close1_discord_timestamp_timezone_required")
    current = current.astimezone(UTC)
    state = _load_state()

    since_attempt = _elapsed(current, state.get("last_attempt_at"))
    if since_attempt is not None and since_attempt < POLL_INTERVAL_SECONDS:
        return []

    state["last_attempt_at"] = current.isoformat()
    fetch = fetcher or close_call.fetch_live_snapshot
    try:
        snapshot = fetch()
    except Exception as error:
        state["failure_count"] = int(state.get("failure_count", 0) or 0) + 1
        notices: list[str] = []
        since_failure_notice = _elapsed(current, state.get("last_failure_notice_at"))
        if (
            state["failure_count"] >= 6
            and (since_failure_notice is None or since_failure_notice >= STATUS_INTERVAL_SECONDS)
        ):
            notices.append(
                "🟡 Close Call read-only監視が30分以上連続で取得失敗\n"
                f"reason: {type(error).__name__}\n"
                "既存FLOP Agentは継続。取引・署名・POSTは行っていません。"
            )
            state["last_failure_notice_at"] = current.isoformat()
        _save_state(state)
        return notices

    previous_fresh = state.get("last_fresh")
    previous_cutoff = _decimal_or_none(state.get("last_top3_cutoff"))
    since_notice = _elapsed(current, state.get("last_notice_at"))
    cutoff = snapshot.top3_cutoff

    reasons: list[str] = []
    if state.get("last_notice_at") is None:
        reasons.append("監視開始")
    elif isinstance(previous_fresh, bool) and previous_fresh != snapshot.reference_fresh_for_strategy:
        reasons.append("安全状態変化")
    if previous_cutoff is not None and cutoff is not None:
        if abs(cutoff - previous_cutoff) >= TOP3_MATERIAL_DELTA:
            reasons.append("top3水準変化")
    if since_notice is None or since_notice >= STATUS_INTERVAL_SECONDS:
        reasons.append("30分定期")

    notices = []
    if reasons:
        notices.append(render_snapshot(snapshot, reason=" / ".join(dict.fromkeys(reasons))))
        state["last_notice_at"] = current.isoformat()

    state.update(
        last_success_at=current.isoformat(),
        last_fresh=snapshot.reference_fresh_for_strategy,
        last_top3_cutoff=str(cutoff) if cutoff is not None else None,
        last_sweep=snapshot.sweep,
        failure_count=0,
    )
    _save_state(state)
    return notices
