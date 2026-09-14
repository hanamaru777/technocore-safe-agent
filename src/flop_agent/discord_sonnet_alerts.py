"""Bounded, read-only Sonnet-2 action notices for the existing Discord bot."""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime

import httpx

from . import core, discord_control, observer, resident
from .public_record import verify_signed_record

REPO = "flop-labs/technocore-sonnet-challenge"
ISSUES = (25, 16, 22)
OFFICIAL_MAINTAINERS = {"sv"}
DISCOVERY_ROOM = "mb-sonnet-2-discovery"
RESULTS_ROOM = "d-sonnet-2-results"
REFEREE_DID = "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
TEAM_ROOM = "d-sonnet-2-team-maru73s2"
GAME_ID = "maru73s2"
INVITE_IDS = ("maru-invite-lon-20260914-1", "maru-invite-fuego-20260914-1", "maru-invite-hunte-20260912-1", "maru-invite-shrimp-20260912-1", "maru-invite-noob-20260912-1")
POLL_SECONDS, MAX_BACKOFF_SECONDS, SEEN_LIMIT = 300, 1800, 256


def state_path(): return resident.resident_dir() / "discord-sonnet-alerts.json"
INVITED_DIDS = {
    "maru-invite-lon-20260914-1": "did:key:z6MkqRmKyNcvzfYX2PRXj2TRoXMYDKDy6RQzL6VAwj4DBhhj",
    "maru-invite-fuego-20260914-1": "did:key:z6Mkt6jAezZ7WyPyN1bTXX63ps4vn8MSvNwtfA9JFgsqeFTB",
    "maru-invite-hunte-20260912-1": "did:key:z6MkuEVGgRAqUR3KyBFLMHqE15dosbpFPoqpjz5b1VrUgatq",
    "maru-invite-shrimp-20260912-1": "did:key:z6Mkt1dE2bNSCEti4oVvjvuWzQAdEAG98t3T9naCQFLHoenj",
    "maru-invite-noob-20260912-1": "did:key:z6MkmVhZbUKWmg3r6TTi3SVM3myYJ9BLbWYPSdc5iWPuPhb6",
}
def _default() -> dict: return {"schema_version": 3, "initialized": False, "github": {}, "rooms": {}, "next_poll_at": 0.0, "failures": 0}


def _load() -> dict:
    try: value = json.loads(state_path().read_text("utf-8"))
    except (FileNotFoundError, OSError, TypeError, ValueError): return _default()
    if not isinstance(value, dict) or value.get("schema_version") != 3 or not isinstance(value.get("github"), dict) or not isinstance(value.get("rooms"), dict): return _default()
    return {"schema_version": 3, "initialized": value.get("initialized") is True, "github": value["github"], "rooms": value["rooms"], "next_poll_at": float(value.get("next_poll_at", 0)), "failures": max(0, int(value.get("failures", 0)))}


def _save(value: dict) -> None: observer.atomic_json_write(state_path(), value, compact=True, mode=0o600)
def _event_id(source: str, row: dict) -> str: return hashlib.sha256((source + "|" + json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)).encode()).hexdigest()


def _authoritative(row: dict) -> bool:
    association = str(row.get("author_association", "")).upper()
    login = str((row.get("user") or {}).get("login", "")).lower() if isinstance(row.get("user"), dict) else ""
    return association in {"OWNER", "MEMBER", "COLLABORATOR"} or login in OFFICIAL_MAINTAINERS


def _github_relevant(issue: int, row: dict) -> tuple[str, str] | None:
    if not _authoritative(row): return None
    text = str(row.get("body") or "").lower()
    if issue == 25 and any(request_id in text for request_id in INVITE_IDS): return ("MARU discovery invitation update", "返信・状態の公式更新です。roster consent は推測していません。")
    if issue in {16, 25} and "maru" in text and any(term in text for term in ("writer", "team", "disposition", "accept", "declin")): return ("MARU official disposition update", "writer/team の公式判断を確認してください。")
    if issue == 22 and "asad" in text and any(term in text for term in ("writer", "role", "resolution", "disposition")): return ("Asad support-lane update", "Asad の現在の役割解決に関係する公式更新です。")
    return None


def _fetch(issue: int) -> list[dict]:
    response = httpx.get(f"https://api.github.com/repos/{REPO}/issues/{issue}/comments?per_page=100&sort=created&direction=asc", headers={"Accept": "application/vnd.github+json"}, timeout=5.0)
    response.raise_for_status(); value = response.json()
    if not isinstance(value, list): raise ValueError("github_shape")
    return [row for row in value if isinstance(row, dict)]


def _room_rows(room: str) -> list[dict]:
    payload = core.read_room(room, limit=200)
    rows = payload if isinstance(payload, list) else payload.get("messages") if isinstance(payload, dict) else None
    if not isinstance(rows, list): raise ValueError("room_shape")
    return [row for row in rows if isinstance(row, dict)]


def _public_evidence(rows: list[tuple[str, dict]]) -> list[tuple[str, dict, tuple[str, str]]]:
    result = []
    for room, row in rows:
        try: verify_signed_record(room, row); payload = json.loads(row["text"])
        except (KeyError, TypeError, ValueError, RuntimeError): continue
        if not isinstance(payload, dict): continue
        if room == DISCOVERY_ROOM and payload.get("type") in {"sonnet.invite-response.v1", "sonnet.invite-status.v1"} and payload.get("contest_id") == "sonnet-2" and payload.get("request_id") in INVITED_DIDS and row.get("from") == INVITED_DIDS[payload["request_id"]]:
            result.append(("invite", row, ("MARU discovery invitation response", "署名済みの返信・状態を確認。roster consent や参加承諾は推測していません。")))
        if room == RESULTS_ROOM and row.get("from") == REFEREE_DID and payload.get("contest_id") == "sonnet-2" and payload.get("game_id") == GAME_ID and payload.get("poem_room") == TEAM_ROOM and payload.get("type") in {"sonnet.setup.v1", "sonnet.resetup.v1"} and type(payload.get("room_generation")) is int and payload["room_generation"] > 0:
            result.append(("team", row, ("MARU team-room generation/setup receipt", "referee の署名済みgeneration/setup receipt を確認しました。team request 自体から参加・権限は推測していません。")))
    return result


def _created_after(row: dict, cutoff: float) -> bool:
    try: return datetime.fromisoformat(str(row.get("created_at") or row.get("updated_at")).replace("Z", "+00:00")).timestamp() > cutoff
    except ValueError: return False


def poll_notices(*, now: float | None = None, fetch=_fetch, room_read=_room_rows) -> list[str]:
    """Fixed GET-only polling; called by Discord's existing ``to_thread`` worker."""
    current = time.time() if now is None else now; state = _load()
    if current < state["next_poll_at"]: return []
    github, public, successes = [], [], 0
    for issue in ISSUES:
        try: github.extend((f"gh:{issue}", row, _github_relevant(issue, row)) for row in fetch(issue)); successes += 1
        except (httpx.HTTPError, OSError, TypeError, ValueError, RuntimeError): pass
    for room in (DISCOVERY_ROOM, RESULTS_ROOM):
        try: public.extend((room, row) for row in room_read(room)); successes += 1
        except (httpx.HTTPError, OSError, TypeError, ValueError, RuntimeError): pass
    if not successes:
        failures = min(state["failures"] + 1, 6); state.update(failures=failures, next_poll_at=current + min(MAX_BACKOFF_SECONDS, 30 * 2 ** (failures - 1))); _save(state); return []
    evidence = [*github, *((f"tc:{kind}", row, relevant) for kind, row, relevant in _public_evidence(public))]
    notices = []
    for source, row, relevant in evidence:
        initial_old = not state["initialized"] and not _created_after(row, current)
        if source.startswith("gh:"):
            progress = state["github"].get(source, {}); identifier = row.get("id") if type(row.get("id")) is int else -1; updated = str(row.get("updated_at", "")); prior_id = progress.get("max_id") if type(progress.get("max_id")) is int else -1; is_new = identifier > prior_id or updated > str(progress.get("max_updated_at", "")); progress["max_id"] = max(identifier, prior_id); progress["max_updated_at"] = max(updated, str(progress.get("max_updated_at", ""))); state["github"][source] = progress
        else:
            room = DISCOVERY_ROOM if source == "tc:invite" else RESULTS_ROOM; progress = state["rooms"].get(room) if type(state["rooms"].get(room)) is int else -1; sequence = row.get("seq") if type(row.get("seq")) is int else -1; is_new = sequence > progress; state["rooms"][room] = max(progress, sequence)
        if relevant and is_new and not initial_old:
            headline, why = relevant; excerpt = discord_control.safe_excerpt(row.get("body", row.get("text", "")), 220)
            notices.append("\n".join([f"🟣 Sonnet-2: {headline}", f"何が起きた: {excerpt or '署名済み/公式更新を検出'}", f"重要性: {why}", "MARU: 公式・署名済みの根拠を確認", "注意: 返信・招待・roster consent・投稿は行っていません。"]))
    state.update(initialized=True, failures=0, next_poll_at=current + POLL_SECONDS); _save(state)
    return notices[:4]
