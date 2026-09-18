"""Reliable Discord delivery for local FLOP Airdrop Radar alerts.

This module writes only to the configured Discord channel. It never signs or writes
to FLOP/Technocore/X and it never persists the Discord bot token.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable

import httpx

from . import airdrop_monitor

SCHEMA_VERSION = 1
STATE_NAME = "discord-notifier-state.json"
DISCORD_API_BASE = "https://discord.com/api/v10"
MAX_CONTENT = 1900
MAX_IMMEDIATE_PER_RUN = 6
MAX_DIGEST_EVENTS = 20
DIGEST_INTERVAL_SECONDS = 6 * 60 * 60
BASE_BACKOFF_SECONDS = 60
MAX_BACKOFF_SECONDS = 15 * 60
DISCORD_TIMEOUT_SECONDS = 12.0
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
PROBLEM_OUTCOMES = {"scan_failed", "blocked_integrity", "alert_routing_failed"}


class NotifierSendError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        status_code: int | None = None,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds


def notifier_dir() -> Path:
    return airdrop_monitor.monitor_dir()


def state_path() -> Path:
    return notifier_dir() / STATE_NAME


def _utc(value: datetime | None = None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("airdrop_notifier_timestamp_timezone_required")
    return current.astimezone(UTC).isoformat()


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("airdrop_notifier_timestamp_timezone_required")
    return parsed.astimezone(UTC)


def _atomic_json_write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
        newline="\n",
    )
    try:
        with handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    finally:
        if os.path.exists(handle.name):
            os.unlink(handle.name)


def _default_state() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "last_run_at": None,
        "last_success_at": None,
        "failure_count": 0,
        "next_attempt_at": None,
        "last_error_type": None,
        "digest_due_at": None,
        "health_notice_state": None,
        "health_notice_at": None,
    }


def _load_state() -> dict:
    path = state_path()
    if not path.exists():
        return _default_state()
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("airdrop_notifier_state_corrupt") from error
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("airdrop_notifier_state_schema_mismatch")
    result = _default_state()
    result.update(value)
    return result


def _save_state(value: dict) -> None:
    clean = _default_state()
    for key in clean:
        if key in value:
            clean[key] = value[key]
    clean["schema_version"] = SCHEMA_VERSION
    _atomic_json_write(state_path(), clean)


def _safe_text(value: object, limit: int = 360) -> str:
    text = CONTROL_RE.sub("", str(value if value is not None else ""))
    text = text.replace("@", "＠")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _preview(value: object, limit: int = 320) -> str:
    if value is None:
        return "-"
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        rendered = str(value)
    return _safe_text(rendered, limit)


def _event_icon(severity: object) -> str:
    if severity == "ACTION_NOW":
        return "🔴"
    if severity == "HIGH":
        return "🟠"
    return "🟡"


def render_alert(payload: dict) -> str:
    severity = _safe_text(payload.get("severity"), 20) or "UNKNOWN"
    event_id = _safe_text(payload.get("event_id"), 40)
    key = _safe_text(payload.get("key"), 180)
    source = _safe_text(payload.get("source"), 80) or "official source"
    tier = _safe_text(payload.get("tier"), 20)
    authority = _safe_text(payload.get("authority"), 80)
    before = _preview(payload.get("before"))
    after = _preview(payload.get("after"))
    step = _safe_text(payload.get("safe_next_step"), 360)

    lines = [
        f"{_event_icon(payload.get('severity'))} FLOP Airdrop Radar [{severity}]",
        f"項目: {key}",
        f"変化: {before} → {after}",
        f"根拠: {source} / Tier {tier or '?'} / {authority or 'authority unknown'}",
    ]
    deadline = payload.get("deadline")
    gate = payload.get("deadline_gate")
    if isinstance(deadline, dict):
        lines.append(f"期限: {_preview(deadline, 240)}")
    if isinstance(gate, dict):
        lines.append(f"残り: {_preview(gate, 160)}")
    source_url = payload.get("source_url")
    if isinstance(source_url, str) and source_url.startswith("https://"):
        lines.append(f"公式: {_safe_text(source_url, 500)}")
    if step:
        lines.append(f"次: {step}")
    lines.append(f"event: {event_id}")

    rendered = "\n".join(lines)
    return rendered[:MAX_CONTENT]


def render_digest(items: list[dict]) -> tuple[str, list[str]]:
    if not items:
        raise ValueError("airdrop_notifier_digest_empty")
    lines = ["🟡 FLOP Airdrop Radar まとめ"]
    selected: list[str] = []
    for item in items[:MAX_DIGEST_EVENTS]:
        payload = item.get("payload") if isinstance(item, dict) else None
        if not isinstance(payload, dict):
            continue
        event_id = _safe_text(payload.get("event_id"), 40)
        line = (
            f"・[{_safe_text(payload.get('severity'), 16)}] "
            f"{_safe_text(payload.get('key'), 90)} | "
            f"{_safe_text(payload.get('source'), 50)} | "
            f"{_preview(payload.get('before'), 90)} → {_preview(payload.get('after'), 90)} "
            f"| {event_id}"
        )
        candidate = "\n".join([*lines, line])
        if len(candidate) > MAX_CONTENT:
            break
        lines.append(line)
        if event_id:
            selected.append(event_id)
    if not selected:
        raise RuntimeError("airdrop_notifier_digest_render_failed")
    lines.extend(
        [
            "",
            "MEDIUMはまとめ通知です。公式条件を確認してから必要な対応だけ進めます。",
        ]
    )
    rendered = "\n".join(lines)
    return rendered[:MAX_CONTENT], selected


def _render_health_problem(status: dict) -> str:
    reasons: list[str] = []
    if status.get("outcome") in PROBLEM_OUTCOMES:
        reasons.append(str(status.get("outcome")))
    if status.get("staging_outcome") == "failed":
        detail = status.get("staging_error_type") or "unknown"
        reasons.append(f"action_staging_failed:{detail}")
    if status.get("heartbeat_stale") and status.get("last_completed_at"):
        reasons.append(
            f"heartbeat stale {status.get('heartbeat_age_seconds')}s"
        )
    return "\n".join(
        [
            "🔴 FLOP Airdrop Radar 監視異常",
            f"状態: {_safe_text(' / '.join(reasons) or 'unknown', 240)}",
            f"最終完了: {_safe_text(status.get('last_completed_at'), 80) or '不明'}",
            f"Radar health: {_safe_text(status.get('radar_health'), 40) or '不明'}",
            "重要: 監視異常をルール変更とは扱っていません。FLOPへの自動操作も行っていません。",
        ]
    )[:MAX_CONTENT]


def _render_health_recovery(status: dict) -> str:
    return "\n".join(
        [
            "🟢 FLOP Airdrop Radar 監視復旧",
            f"最終完了: {_safe_text(status.get('last_completed_at'), 80)}",
            f"Radar health: {_safe_text(status.get('radar_health'), 40)}",
            "監視を継続します。FLOPへの自動操作はありません。",
        ]
    )[:MAX_CONTENT]


def _health_class(status: dict) -> str:
    outcome = status.get("outcome")
    if outcome == "never_run" or status.get("last_attempt_at") is None:
        return "unknown"
    if outcome in PROBLEM_OUTCOMES:
        return "problem"
    if status.get("staging_outcome") == "failed":
        return "problem"
    if status.get("heartbeat_stale") and status.get("last_completed_at"):
        return "problem"
    return "healthy"


def _discord_sender_from_env() -> Callable[[str], str]:
    token = os.environ.get("DISCORD_BOT_TOKEN")
    channel_id = os.environ.get("DISCORD_CHANNEL_ID", "")
    if not token:
        raise RuntimeError("airdrop_notifier_discord_token_missing")
    if not channel_id.isdecimal():
        raise RuntimeError("airdrop_notifier_discord_channel_invalid")
    endpoint = f"{DISCORD_API_BASE}/channels/{channel_id}/messages"

    def send(content: str) -> str:
        body = {
            "content": content[:MAX_CONTENT],
            "allowed_mentions": {"parse": []},
            "flags": 4,
        }
        with httpx.Client(
            timeout=DISCORD_TIMEOUT_SECONDS,
            follow_redirects=False,
            headers={
                "Authorization": f"Bot {token}",
                "User-Agent": "technocore-safe-agent-airdrop-notifier/1",
            },
        ) as client:
            response = client.post(endpoint, json=body)

        if response.status_code == 429:
            retry_after = None
            try:
                data = response.json()
                raw = data.get("retry_after") if isinstance(data, dict) else None
                if isinstance(raw, (int, float)) and raw >= 0:
                    retry_after = max(1, int(float(raw) + 0.999))
            except (ValueError, TypeError):
                pass
            raise NotifierSendError(
                "airdrop_notifier_discord_rate_limited",
                status_code=429,
                retry_after_seconds=retry_after,
            )
        if response.status_code not in {200, 201}:
            raise NotifierSendError(
                "airdrop_notifier_discord_http_error",
                status_code=response.status_code,
            )
        try:
            data = response.json()
        except ValueError as error:
            raise NotifierSendError("airdrop_notifier_discord_response_invalid") from error
        message_id = data.get("id") if isinstance(data, dict) else None
        if not isinstance(message_id, str) or not message_id.isdecimal():
            raise NotifierSendError("airdrop_notifier_discord_receipt_invalid")
        return message_id

    return send


def _backoff_seconds(failure_count: int, error: Exception) -> int:
    base = min(
        MAX_BACKOFF_SECONDS,
        BASE_BACKOFF_SECONDS * (2 ** max(0, failure_count - 1)),
    )
    if isinstance(error, NotifierSendError) and error.retry_after_seconds:
        return min(
            MAX_BACKOFF_SECONDS,
            max(base, error.retry_after_seconds),
        )
    return base


def _failure_result(
    state: dict,
    error: Exception,
    current: datetime,
    *,
    sent: int,
) -> dict:
    failures = min(10, int(state.get("failure_count", 0) or 0) + 1)
    wait = _backoff_seconds(failures, error)
    state.update(
        last_run_at=current.isoformat(),
        failure_count=failures,
        next_attempt_at=(current + timedelta(seconds=wait)).isoformat(),
        last_error_type=error.__class__.__name__,
    )
    _save_state(state)
    return {
        "outcome": "send_failed",
        "sent": sent,
        "error_type": error.__class__.__name__,
        "retry_in_seconds": wait,
    }


def _backoff_active(state: dict, current: datetime) -> tuple[bool, int]:
    raw = state.get("next_attempt_at")
    if not isinstance(raw, str):
        return False, 0
    target = _parse_utc(raw)
    seconds = int((target - current).total_seconds())
    return seconds > 0, max(0, seconds)


def _pending_by_route() -> tuple[list[dict], list[dict]]:
    rows = airdrop_monitor.pending_alerts().get("alerts", [])
    immediate = [
        row for row in rows
        if isinstance(row, dict) and row.get("route") == "immediate"
    ]
    digest = [
        row for row in rows
        if isinstance(row, dict) and row.get("route") == "digest"
    ]
    return immediate, digest


def run_once(
    *,
    sender: Callable[[str], str] | None = None,
    now: datetime | None = None,
) -> dict:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("airdrop_notifier_timestamp_timezone_required")
    current = current.astimezone(UTC)
    state = _load_state()

    active, wait = _backoff_active(state, current)
    if active:
        return {
            "outcome": "backoff",
            "sent": 0,
            "retry_in_seconds": wait,
        }

    send = sender or _discord_sender_from_env()
    state["last_run_at"] = current.isoformat()
    sent = 0

    immediate, digest = _pending_by_route()
    for item in immediate[:MAX_IMMEDIATE_PER_RUN]:
        payload = item.get("payload")
        event_id = item.get("event_id")
        if not isinstance(payload, dict) or not isinstance(event_id, str):
            continue
        try:
            receipt = send(render_alert(payload))
        except Exception as error:
            return _failure_result(state, error, current, sent=sent)
        airdrop_monitor.mark_alert_delivered(
            event_id,
            transport="discord",
            receipt=receipt,
            now=current,
        )
        sent += 1

    # Health notices are deduped separately from event delivery.
    try:
        monitor_status = airdrop_monitor.monitor_status(now=current)
    except Exception as error:
        return _failure_result(state, error, current, sent=sent)
    health = _health_class(monitor_status)
    previous_health = state.get("health_notice_state")
    health_message = None
    next_health_state = previous_health
    if health == "problem" and previous_health != "problem":
        health_message = _render_health_problem(monitor_status)
        next_health_state = "problem"
    elif health == "healthy" and previous_health == "problem":
        health_message = _render_health_recovery(monitor_status)
        next_health_state = "healthy"
    elif health == "healthy" and previous_health is None:
        next_health_state = "healthy"

    if health_message:
        try:
            send(health_message)
        except Exception as error:
            return _failure_result(state, error, current, sent=sent)
        sent += 1
        state["health_notice_at"] = current.isoformat()
        state["health_notice_state"] = next_health_state
    elif next_health_state != previous_health:
        state["health_notice_state"] = next_health_state

    # Re-read after immediate deliveries so a concurrent monitor write is visible.
    _, digest = _pending_by_route()
    if digest:
        raw_due = state.get("digest_due_at")
        if not isinstance(raw_due, str):
            state["digest_due_at"] = (
                current + timedelta(seconds=DIGEST_INTERVAL_SECONDS)
            ).isoformat()
        elif _parse_utc(raw_due) <= current:
            content, event_ids = render_digest(digest)
            try:
                receipt = send(content)
            except Exception as error:
                return _failure_result(state, error, current, sent=sent)
            airdrop_monitor.mark_alerts_delivered(
                event_ids,
                transport="discord",
                receipt=receipt,
                now=current,
            )
            sent += 1
            _, remaining = _pending_by_route()
            state["digest_due_at"] = (
                (current + timedelta(minutes=1)).isoformat()
                if remaining
                else None
            )
    else:
        state["digest_due_at"] = None

    state.update(
        last_success_at=current.isoformat(),
        failure_count=0,
        next_attempt_at=None,
        last_error_type=None,
    )
    _save_state(state)
    immediate_left, digest_left = _pending_by_route()
    return {
        "outcome": "ok",
        "sent": sent,
        "pending_immediate": len(immediate_left),
        "pending_digest": len(digest_left),
        "health": health,
    }


def status(*, now: datetime | None = None) -> dict:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("airdrop_notifier_timestamp_timezone_required")
    current = current.astimezone(UTC)
    state = _load_state()
    active, wait = _backoff_active(state, current)
    immediate, digest = _pending_by_route()
    return {
        "schema_version": SCHEMA_VERSION,
        "last_run_at": state.get("last_run_at"),
        "last_success_at": state.get("last_success_at"),
        "failure_count": state.get("failure_count", 0),
        "backoff_active": active,
        "retry_in_seconds": wait,
        "last_error_type": state.get("last_error_type"),
        "digest_due_at": state.get("digest_due_at"),
        "health_notice_state": state.get("health_notice_state"),
        "pending_immediate": len(immediate),
        "pending_digest": len(digest),
    }
