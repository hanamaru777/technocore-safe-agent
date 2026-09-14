"""Bounded read-only Sonnet-2 operator notices for the existing Discord bot."""
from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime

import httpx

from . import discord_control, observer, resident

REPO = "flop-labs/technocore-sonnet-challenge"
ISSUES = (25, 16, 22)
INVITE_IDS = ("maru-invite-lon-20260914-1", "maru-invite-fuego-20260914-1", "maru-invite-hunte-20260912-1", "maru-invite-shrimp-20260912-1", "maru-invite-noob-20260912-1")
POLL_SECONDS = 300
MAX_BACKOFF_SECONDS = 1800
SEEN_LIMIT = 256


def state_path():
    return resident.resident_dir() / "discord-sonnet-alerts.json"


def _default() -> dict:
    return {"schema_version": 1, "seen": [], "next_poll_at": 0.0, "failures": 0}


def _load() -> dict:
    try:
        value = json.loads(state_path().read_text("utf-8"))
    except FileNotFoundError:
        return _default()
    except (OSError, TypeError, ValueError):
        return _default()
    if not isinstance(value, dict) or value.get("schema_version") != 1 or not isinstance(value.get("seen"), list):
        return _default()
    return {"schema_version": 1, "seen": [x for x in value["seen"] if isinstance(x, str)][-SEEN_LIMIT:], "next_poll_at": float(value.get("next_poll_at", 0)), "failures": max(0, int(value.get("failures", 0)))}


def _save(value: dict) -> None:
    observer.atomic_json_write(state_path(), value, compact=True, mode=0o600)


def _event_id(issue: int, row: dict) -> str:
    stable = f"{issue}|{row.get('id', '')}|{row.get('updated_at', '')}|{row.get('state', '')}|{row.get('body', '')}"
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()


def _authoritative(row: dict) -> bool:
    return str(row.get("author_association", "")).upper() in {"OWNER", "MEMBER", "COLLABORATOR"}


def _relevant(issue: int, row: dict) -> tuple[str, str] | None:
    if not _authoritative(row):
        return None
    text = str(row.get("body") or "").lower()
    if issue == 25 and any(request_id in text for request_id in INVITE_IDS):
        return ("MARU discovery invitation update", "返信・状態の公式更新です。roster consent は推測していません。")
    if issue in {16, 25}:
        if "maru" not in text or not any(term in text for term in ("writer", "team", "setup", "room", "accept", "declin", "disposition")):
            return None
        if "maru73s2" in text and any(term in text for term in ("setup", "room", "team room")):
            return ("MARU team-room setup evidence", "チームルームの公式設定根拠を確認してください。")
        return ("MARU official disposition update", "writer/team の公式判断を確認してください。")
    # #22 is deliberately inert unless an existing local Asad support record marks it active.
    if issue == 22 and _asad_support_active() and "asad" in text:
        return ("Asad support-lane update", "現在のAsad支援レーンに関係する公式更新です。")
    return None


def _asad_support_active() -> bool:
    """Only use an explicit, non-secret local support flag; absent means inactive."""
    path = resident.resident_dir() / "sonnet-asad-support.json"
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, TypeError, ValueError):
        return False
    return isinstance(value, dict) and value.get("schema_version") == 1 and value.get("active") is True


def _fetch(issue: int) -> list[dict]:
    url = f"https://api.github.com/repos/{REPO}/issues/{issue}/comments?per_page=100&sort=created&direction=asc"
    response = httpx.get(url, headers={"Accept": "application/vnd.github+json"}, timeout=5.0)
    response.raise_for_status()
    value = response.json()
    if not isinstance(value, list):
        raise ValueError("github_shape")
    return [row for row in value if isinstance(row, dict)]


def poll_notices(*, now: float | None = None, fetch=_fetch) -> list[str]:
    """Poll fixed public sources only. All callers run this on Discord's worker thread."""
    current = time.time() if now is None else now
    state = _load()
    if current < state["next_poll_at"]:
        return []
    try:
        records = [(issue, row) for issue in ISSUES for row in fetch(issue)]
    except (httpx.HTTPError, OSError, TypeError, ValueError):
        failures = min(state["failures"] + 1, 6)
        state.update(failures=failures, next_poll_at=current + min(MAX_BACKOFF_SECONDS, 30 * (2 ** (failures - 1))))
        _save(state)
        return []
    seen = set(state["seen"])
    notices: list[str] = []
    for issue, row in records:
        event_id = _event_id(issue, row)
        relevant = _relevant(issue, row)
        if event_id in seen or relevant is None:
            continue
        headline, why = relevant
        excerpt = discord_control.safe_excerpt(row.get("body", ""), 220)
        notices.append("\n".join([
            f"🟣 Sonnet-2: {headline}",
            f"何が起きた: {excerpt or '公式更新を検出'}",
            f"重要性: {why}",
            f"MARU: GitHub Issue #{issue} の公式更新を確認",
            "注意: 返信・招待・roster consent・投稿は行っていません。",
        ]))
        seen.add(event_id)
    # Mark every observed item as seen so irrelevant history cannot be reconsidered later.
    for issue, row in records:
        seen.add(_event_id(issue, row))
    state.update(seen=list(seen)[-SEEN_LIMIT:], failures=0, next_poll_at=current + POLL_SECONDS)
    _save(state)
    return notices[:4]
