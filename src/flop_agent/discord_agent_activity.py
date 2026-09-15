"""Durable read-only Agent activity notices for Discord.

This watcher is intentionally presentation-only.  It never signs, posts to
Technocore, reads signer secrets, or touches the active capture SQLite DB.
It surfaces important Sonnet-2 outbound receipts, signed inbound messages
addressed to MARU, and referee records materially involving MARU.
"""
from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime
from pathlib import Path

from . import core, discord_control, observer, resident
from .public_record import verify_signed_record

DISCOVERY_ROOM = "mb-sonnet-2-discovery"
RESULTS_ROOM = "d-sonnet-2-results"
MARU_DID = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
REFEREE_DID = "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
MITSURI_DID = "did:key:z6MkrjMTaN3kDvff5kdE6BhNxgErLdpz58kmsipP3PuHwoct"
STATE_NAME = "discord-agent-activity.json"
MAX_NOTIFIED = 1024
MAX_NOTICES_PER_POLL = 12


def state_path() -> Path:
    return resident.resident_dir() / STATE_NAME


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
        "notified": [str(item) for item in value["notified"] if isinstance(item, str)][-MAX_NOTIFIED:],
    }


def _save(value: dict) -> None:
    value["notified"] = value["notified"][-MAX_NOTIFIED:]
    observer.atomic_json_write(state_path(), value, compact=True, mode=0o600)


def _time_label(value: object) -> str:
    if not isinstance(value, str):
        return "時刻不明"
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=UTC)
        return stamp.astimezone(discord_control.DISPLAY_TZ).strftime("%m/%d %H:%M")
    except ValueError:
        return "時刻不明"


def _safe_payload_text(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    text = value.get("text")
    return discord_control.safe_excerpt(text, 700) if isinstance(text, str) else ""


def _public_request_ids() -> set[str]:
    result: set[str] = set()
    root = core.STATE / "signer"
    try:
        paths = sorted(root.glob("sonnet-2-*.json"))
    except OSError:
        return result
    for path in paths:
        try:
            value = json.loads(path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict):
            continue
        request_id = value.get("request_id")
        if isinstance(request_id, str) and request_id:
            result.add(request_id)
        payload = value.get("payload")
        if isinstance(payload, dict):
            nested = payload.get("request_id")
            if isinstance(nested, str) and nested:
                result.add(nested)
    return result


def _local_outbound_events() -> list[tuple[str, str]]:
    events: list[tuple[str, str]] = []
    root = core.STATE / "signer"
    try:
        paths = sorted(root.glob("sonnet-2-*.json"))
    except OSError:
        return events
    for path in paths:
        try:
            value = json.loads(path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict) or value.get("state") != "posted":
            continue
        seq = value.get("seq")
        ts = value.get("ts")
        if type(seq) is not int or seq < 0 or not isinstance(ts, str):
            continue
        payload = value.get("payload") if isinstance(value.get("payload"), dict) else {}
        request_id = value.get("request_id") or payload.get("request_id") or "不明"
        target = value.get("target_did") or payload.get("target_did")
        target_label = "Mitsuri Agent" if target == MITSURI_DID else discord_control.short_fingerprint(target or "unknown")
        body = _safe_payload_text(payload)
        event_id = f"out:{path.name}:{seq}"
        lines = [
            "📤 Agent送信 — posted",
            f"相手: {target_label}",
            f"request_id: {request_id}",
            f"seq: {seq} | 時刻: {_time_label(ts)}",
        ]
        if body:
            lines.append(f"本文: {body}")
        lines.append("状態: Technocore受理済み。再送不要。")
        events.append((event_id, "\n".join(lines)))
    return events


def _parse_room(value: object) -> list[dict]:
    rows = value if isinstance(value, list) else value.get("messages") if isinstance(value, dict) else None
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
        return any(anchor in lowered for anchor in anchors)
    return False


def _room_events(room: str, rows: list[dict], request_ids: set[str]) -> list[tuple[str, str]]:
    events: list[tuple[str, str]] = []
    for row in rows:
        seq = row.get("seq")
        sender = row.get("from")
        if type(seq) is not int or seq < 0 or not isinstance(sender, str):
            continue
        if sender == MARU_DID:
            # Local receipt state is the authoritative outbound notification source.
            continue
        try:
            verify_signed_record(room, row)
        except (KeyError, TypeError, ValueError, RuntimeError):
            continue
        raw = str(row.get("text") or "")
        try:
            decoded = json.loads(raw)
        except (TypeError, ValueError):
            decoded = raw
        if not _contains_maru(decoded, request_ids):
            continue
        sender_label = "Mitsuri Agent" if sender == MITSURI_DID else discord_control.short_fingerprint(sender)
        excerpt = discord_control.safe_excerpt(
            decoded.get("text", raw) if isinstance(decoded, dict) else raw,
            760,
        )
        ts = row.get("ts")
        if room == RESULTS_ROOM and sender == REFEREE_DID:
            kind = str(decoded.get("type") or "official") if isinstance(decoded, dict) else "official"
            game = decoded.get("game_id") if isinstance(decoded, dict) else None
            request_id = decoded.get("request_id") if isinstance(decoded, dict) else None
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
                f"seq: {seq} | 時刻: {_time_label(ts)}",
            ]
            if excerpt:
                lines.append(f"内容: {excerpt}")
            lines.append("次: 内容を確認し、必要なら返信。自動同意はしていません。")
        events.append((f"room:{room}:{seq}", "\n".join(lines)))
    return events


def poll_notices(*, room_read=core.read_room) -> list[str]:
    """Return new important Agent notices with durable de-duplication."""
    state = _load()
    notified = set(state["notified"])
    request_ids = _public_request_ids()
    events = _local_outbound_events()
    for room in (DISCOVERY_ROOM, RESULTS_ROOM):
        try:
            payload = room_read(room, limit=200, cache_buster=secrets.token_hex(8))
        except Exception:
            continue
        events.extend(_room_events(room, _parse_room(payload), request_ids))

    fresh: list[tuple[str, str]] = []
    for event_id, notice in events:
        if event_id in notified:
            continue
        fresh.append((event_id, notice))
    fresh = fresh[-MAX_NOTICES_PER_POLL:]
    if fresh:
        state["notified"].extend(event_id for event_id, _ in fresh)
        _save(state)
    return [notice for _, notice in fresh]
