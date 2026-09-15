"""Durable read-only Agent activity notices for Discord.

This watcher is presentation-only. It never signs, posts to Technocore, reads
signer-private state, or touches the active capture SQLite DB. Outbound history
comes from the existing shared hash-chained ``activities.jsonl`` audit plus the
public room tail; inbound/result events come only from signed public records.
"""
from __future__ import annotations

import json
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path

from . import core, discord_control, observer, resident
from .public_record import verify_signed_record

DISCOVERY_ROOM = "mb-sonnet-2-discovery"
RESULTS_ROOM = "d-sonnet-2-results"
FIXED_ROOMS = (DISCOVERY_ROOM, RESULTS_ROOM)
MARU_DID = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
REFEREE_DID = "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
MITSURI_DID = "did:key:z6MkrjMTaN3kDvff5kdE6BhNxgErLdpz58kmsipP3PuHwoct"
MITSURI_REQUEST_ID = "maru-mitsuri-contact-20260915-1"
STARTED_AT = datetime(2026, 9, 15, 10, 3, 26, tzinfo=UTC)
STATE_NAME = "discord-agent-activity.json"
MAX_NOTIFIED = 1024
MAX_NOTICES_PER_POLL = 12
ACTIVITY_TAIL_BYTES = 512 * 1024


def state_path() -> Path:
    return resident.resident_dir() / STATE_NAME


def activity_path() -> Path:
    return core.STATE / "activities.jsonl"


def _default() -> dict:
    return {"schema_version": 1, "notified": []}


def _load() -> dict:
    try:
        value = json.loads(state_path().read_text("utf-8"))
    except FileNotFoundError:
        return _default()
    except (OSError, json.JSONDecodeError):
        return _default()
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or not isinstance(value.get("notified"), list)
    ):
        return _default()
    return {
        "schema_version": 1,
        "notified": [
            str(item) for item in value["notified"] if isinstance(item, str)
        ][-MAX_NOTIFIED:],
    }


def _save(value: dict) -> None:
    value["notified"] = value["notified"][-MAX_NOTIFIED:]
    observer.atomic_json_write(state_path(), value, compact=True, mode=0o600)


def _stamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return stamp.astimezone(UTC)


def _time_label(value: object) -> str:
    stamp = _stamp(value)
    if stamp is None:
        return "時刻不明"
    return stamp.astimezone(discord_control.DISPLAY_TZ).strftime("%m/%d %H:%M")


def _agent_label(did: object) -> str:
    if did == MITSURI_DID:
        return "Mitsuri Agent"
    if isinstance(did, str) and did:
        return f"Agent …{did[-8:]}"
    return "unknown Agent"


def _decoded_text(raw: object) -> object:
    text = str(raw or "")
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return text


def _safe_body(decoded: object, raw: object) -> str:
    value = decoded.get("text", raw) if isinstance(decoded, dict) else raw
    return discord_control.safe_excerpt(value, 760)


def _target_label(decoded: object) -> str:
    target = decoded.get("target_did") if isinstance(decoded, dict) else None
    if isinstance(target, str) and target:
        return _agent_label(target)
    return "room broadcast"


def _request_id(decoded: object) -> str | None:
    value = decoded.get("request_id") if isinstance(decoded, dict) else None
    return value if isinstance(value, str) and value else None


def _read_activity_tail() -> list[dict]:
    """Read only a bounded suffix of the shared, non-secret activity audit."""
    path = activity_path()
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            start = max(0, size - ACTIVITY_TAIL_BYTES)
            handle.seek(start)
            data = handle.read(ACTIVITY_TAIL_BYTES)
    except (FileNotFoundError, OSError):
        return []
    if start:
        _, sep, data = data.partition(b"\n")
        if not sep:
            return []
    rows: list[dict] = []
    for line in data.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _outbound_notice(room: str, seq: int, ts: str, raw: object) -> str:
    decoded = _decoded_text(raw)
    request_id = _request_id(decoded)
    lines = [
        "📤 Agent送信 — posted",
        f"相手: {_target_label(decoded)}",
    ]
    if request_id:
        lines.append(f"request_id: {request_id}")
    lines.append(f"room: {room} | seq: {seq} | 時刻: {_time_label(ts)}")
    body = _safe_body(decoded, raw)
    if body:
        lines.append(f"本文: {body}")
    lines.append("状態: Technocore受理済み。再送不要。")
    return "\n".join(lines)


def _activity_events() -> tuple[list[tuple[str, datetime, str]], set[str]]:
    events: list[tuple[str, datetime, str]] = []
    request_ids = {MITSURI_REQUEST_ID}
    for row in _read_activity_tail():
        if row.get("did") != MARU_DID or row.get("room") not in FIXED_ROOMS:
            continue
        seq = row.get("seq")
        ts = row.get("ts")
        stamp = _stamp(ts)
        if type(seq) is not int or seq < 0 or stamp is None or stamp < STARTED_AT:
            continue
        raw = row.get("text", "")
        decoded = _decoded_text(raw)
        request_id = _request_id(decoded)
        if request_id:
            request_ids.add(request_id)
        room = str(row["room"])
        events.append(
            (f"msg:{room}:{seq}", stamp, _outbound_notice(room, seq, str(ts), raw))
        )
    return events, request_ids


def _parse_room(value: object) -> list[dict]:
    rows = (
        value
        if isinstance(value, list)
        else value.get("messages")
        if isinstance(value, dict)
        else None
    )
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def _contains_maru(value: object, request_ids: set[str]) -> bool:
    anchors = {MARU_DID.lower(), "minermaru73", *{item.lower() for item in request_ids}}
    if isinstance(value, dict):
        if value.get("target_did") == MARU_DID:
            return True
        return any(_contains_maru(item, request_ids) for item in value.values())
    if isinstance(value, list):
        return any(_contains_maru(item, request_ids) for item in value)
    if isinstance(value, str):
        lowered = value.lower()
        return any(anchor in lowered for anchor in anchors) or bool(
            re.search(r"\bmaru\b", lowered)
        )
    return False


def _room_events(
    room: str,
    rows: list[dict],
    request_ids: set[str],
) -> tuple[list[tuple[str, datetime, str]], set[str]]:
    events: list[tuple[str, datetime, str]] = []
    discovered_ids: set[str] = set()
    for row in rows:
        seq = row.get("seq")
        sender = row.get("from")
        ts = row.get("ts")
        stamp = _stamp(ts)
        if (
            type(seq) is not int
            or seq < 0
            or not isinstance(sender, str)
            or stamp is None
            or stamp < STARTED_AT
        ):
            continue
        try:
            verify_signed_record(room, row)
        except (KeyError, TypeError, ValueError, RuntimeError):
            continue
        raw = row.get("text", "")
        decoded = _decoded_text(raw)
        request_id = _request_id(decoded)
        if sender == MARU_DID:
            if request_id:
                discovered_ids.add(request_id)
            events.append(
                (f"msg:{room}:{seq}", stamp, _outbound_notice(room, seq, str(ts), raw))
            )
            continue
        if not _contains_maru(decoded, request_ids | discovered_ids):
            continue
        sender_label = _agent_label(sender)
        excerpt = _safe_body(decoded, raw)
        if room == RESULTS_ROOM and sender == REFEREE_DID:
            kind = (
                str(decoded.get("type") or "official")
                if isinstance(decoded, dict)
                else "official"
            )
            game = decoded.get("game_id") if isinstance(decoded, dict) else None
            lines = [
                "🏛️ Sonnet公式更新 — 要確認",
                f"type: {kind}",
                f"seq: {seq} | 時刻: {_time_label(ts)}",
            ]
            if game:
                lines.append(f"game_id: {game}")
            if request_id:
                lines.append(f"request_id: {request_id}")
            if excerpt:
                lines.append(f"内容: {excerpt}")
            lines.append("次: roster / accepted word / submission等への影響を確認。")
        else:
            lines = [
                "📥 Agent受信 — 要確認",
                f"相手: {sender_label}",
                f"room: {room} | seq: {seq} | 時刻: {_time_label(ts)}",
            ]
            if request_id:
                lines.append(f"request_id: {request_id}")
            if excerpt:
                lines.append(f"内容: {excerpt}")
            lines.append("次: 内容を確認し、必要なら返信。自動同意はしていません。")
        events.append((f"msg:{room}:{seq}", stamp, "\n".join(lines)))
    return events, discovered_ids


def poll_notices(*, room_read=core.read_room) -> list[str]:
    """Return new important Agent notices with durable de-duplication."""
    state = _load()
    notified = set(state["notified"])
    activity_events, request_ids = _activity_events()
    events: dict[str, tuple[datetime, str]] = {
        event_id: (stamp, notice) for event_id, stamp, notice in activity_events
    }

    for room in FIXED_ROOMS:
        try:
            payload = room_read(room, limit=200, cache_buster=secrets.token_hex(8))
        except Exception:
            continue
        room_events, discovered = _room_events(
            room, _parse_room(payload), request_ids
        )
        request_ids.update(discovered)
        for event_id, stamp, notice in room_events:
            events[event_id] = (stamp, notice)

    fresh = [
        (event_id, stamp, notice)
        for event_id, (stamp, notice) in events.items()
        if event_id not in notified
    ]
    fresh.sort(key=lambda item: (item[1], item[0]))
    fresh = fresh[:MAX_NOTICES_PER_POLL]
    if fresh:
        state["notified"].extend(event_id for event_id, _, _ in fresh)
        _save(state)
    return [notice for _, _, notice in fresh]
