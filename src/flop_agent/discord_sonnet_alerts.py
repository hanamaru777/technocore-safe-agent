"""Bounded, read-only Sonnet-2 action notices for the existing Discord bot."""
from __future__ import annotations

import json
import time
from datetime import datetime
from urllib.parse import quote

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
MARU_DID = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
MARU_REGISTRATION_REQUEST_ID = "32c15433c6d73af1cea5d6467dece016"

POLL_SECONDS = 300
MAX_BACKOFF_SECONDS = 1800
PENDING_LIMIT = 32
GITHUB_PAGE_LIMIT = 5
PROCESS_STARTED_AT = time.time()

INVITATIONS = {
    "maru-invite-lon-20260914-1": {
        "did": "did:key:z6MkqRmKyNcvzfYX2PRXj2TRoXMYDKDy6RQzL6VAwj4DBhhj",
        "sent_seq": 84020,
    },
    "maru-invite-fuego-20260914-1": {
        "did": "did:key:z6Mkt6jAezZ7WyPyN1bTXX63ps4vn8MSvNwtfA9JFgsqeFTB",
        "sent_seq": 84021,
    },
    "maru-invite-hunte-20260912-1": {
        "did": "did:key:z6MkuEVGgRAqUR3KyBFLMHqE15dosbpFPoqpjz5b1VrUgatq",
        "sent_seq": 8995,
    },
    "maru-invite-shrimp-20260912-1": {
        "did": "did:key:z6Mkt1dE2bNSCEti4oVvjvuWzQAdEAG98t3T9naCQFLHoenj",
        "sent_seq": 8997,
    },
    "maru-invite-noob-20260912-1": {
        "did": "did:key:z6MkmVhZbUKWmg3r6TTi3SVM3myYJ9BLbWYPSdc5iWPuPhb6",
        "sent_seq": 9000,
    },
}
INVITED_DIDS = {request_id: item["did"] for request_id, item in INVITATIONS.items()}
INVITE_BY_DID = {item["did"]: request_id for request_id, item in INVITATIONS.items()}
INVITE_IDS = tuple(INVITATIONS)
FIXED_ROOMS = {DISCOVERY_ROOM, RESULTS_ROOM}


class RoomRetentionGap(RuntimeError):
    """A live room cursor fell behind the newest-limit window and export is partial."""

    def __init__(self, room: str, missing_from: int, missing_to: int, rows: list[dict]):
        super().__init__(f"{room} missing seq {missing_from}..{missing_to}")
        self.room = room
        self.missing_from = missing_from
        self.missing_to = missing_to
        self.rows = rows


def state_path():
    return resident.resident_dir() / "discord-sonnet-alerts.json"


def _default(*, initial_cutoff: float | None = None) -> dict:
    return {
        "schema_version": 6,
        "initial_cutoff": PROCESS_STARTED_AT if initial_cutoff is None else float(initial_cutoff),
        "github": {},
        "rooms": {},
        "pending": [],
        "next_poll_at": 0.0,
        "failures": 0,
    }


def _corrupt_default() -> dict:
    """Baseline at corruption-detection time so lost cursors cannot replay history."""
    return _default(initial_cutoff=time.time())


def _load() -> dict:
    try:
        value = json.loads(state_path().read_text("utf-8"))
    except FileNotFoundError:
        return _default()
    except (OSError, TypeError, ValueError):
        return _corrupt_default()
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 6
        or not isinstance(value.get("github"), dict)
        or not isinstance(value.get("rooms"), dict)
        or not isinstance(value.get("pending"), list)
    ):
        return _corrupt_default()
    try:
        initial_cutoff = float(value.get("initial_cutoff"))
        next_poll_at = float(value.get("next_poll_at", 0))
        failures = max(0, int(value.get("failures", 0)))
    except (TypeError, ValueError, OverflowError):
        return _corrupt_default()
    return {
        "schema_version": 6,
        "initial_cutoff": initial_cutoff,
        "github": value["github"],
        "rooms": value["rooms"],
        "pending": [item for item in value["pending"] if isinstance(item, str)][:PENDING_LIMIT],
        "next_poll_at": next_poll_at,
        "failures": failures,
    }


def _save(value: dict) -> None:
    observer.atomic_json_write(state_path(), value, compact=True, mode=0o600)


def _authoritative(row: dict) -> bool:
    association = str(row.get("author_association", "")).upper()
    login = (
        str((row.get("user") or {}).get("login", "")).lower()
        if isinstance(row.get("user"), dict)
        else ""
    )
    return association in {"OWNER", "MEMBER", "COLLABORATOR"} or login in OFFICIAL_MAINTAINERS


def _github_relevant(issue: int, row: dict) -> tuple[str, str] | None:
    if not _authoritative(row):
        return None

    text = str(row.get("body") or "")
    lowered = text.lower()

    # #25 is a narrow, MARU-only authoritative lookup. Any authoritative new
    # comment on that issue is actionable; do not require the maintainer to
    # repeat our handle or request_id in the response.
    if issue == 25:
        return (
            "MARU official disposition update",
            "MARU専用の公式照会 #25 に authoritative な新規/更新コメントがあります。",
        )

    maru_anchors = (
        "maru",
        MARU_DID.lower(),
        MARU_REGISTRATION_REQUEST_ID.lower(),
        GAME_ID,
    )
    if issue == 16 and any(anchor in lowered for anchor in maru_anchors):
        if any(
            term in lowered
            for term in ("writer", "team", "disposition", "accept", "declin", "registration")
        ):
            return (
                "MARU official disposition update",
                "writer/team の公式判断に関係する更新です。",
            )

    if issue == 22 and "asad" in lowered and any(
        term in lowered
        for term in (
            "writer",
            "role",
            "resolution",
            "disposition",
            "attribution",
            "migration",
        )
    ):
        return (
            "Asad support-lane update",
            "Asad の役割・移行・attribution 解決に関係する公式更新です。",
        )
    return None


def _fetch(issue: int) -> list[dict]:
    rows: list[dict] = []
    for page in range(1, GITHUB_PAGE_LIMIT + 1):
        response = httpx.get(
            f"https://api.github.com/repos/{REPO}/issues/{issue}/comments",
            params={
                "per_page": 100,
                "page": page,
                "sort": "created",
                "direction": "asc",
            },
            headers={"Accept": "application/vnd.github+json"},
            timeout=5.0,
        )
        response.raise_for_status()
        value = response.json()
        if not isinstance(value, list):
            raise ValueError("github_shape")
        page_rows = [row for row in value if isinstance(row, dict)]
        rows.extend(page_rows)
        if len(value) < 100:
            return rows
    raise RuntimeError("github_comment_page_limit")


def _parse_room_payload(payload: object) -> list[dict]:
    rows = payload if isinstance(payload, list) else payload.get("messages") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise ValueError("room_shape")
    return [row for row in rows if isinstance(row, dict)]


def _room_export(room: str) -> list[dict]:
    if room not in FIXED_ROOMS:
        raise ValueError("room_not_allowlisted")
    response = httpx.get(
        f"{core.BASE_URL}/r/{quote(room, safe='')}/export",
        timeout=20,
    )
    response.raise_for_status()
    rows: list[dict] = []
    for line in response.text.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError("room_export_shape") from error
        if not isinstance(row, dict):
            raise ValueError("room_export_shape")
        rows.append(row)
    return rows


def _room_rows(room: str, since: int | None = None) -> list[dict]:
    if room not in FIXED_ROOMS:
        raise ValueError("room_not_allowlisted")
    if since is None:
        return _room_export(room)

    rows = _parse_room_payload(core.read_room(room, since=since, limit=200))
    if not rows:
        return []
    sequences = [row.get("seq") for row in rows if type(row.get("seq")) is int]
    if not sequences:
        raise ValueError("room_seq_shape")
    first_seq = min(sequences)
    if first_seq <= since + 1:
        return rows

    exported = _room_export(room)
    retained = [
        row
        for row in exported
        if type(row.get("seq")) is int and row["seq"] > since
    ]
    retained_sequences = [row["seq"] for row in retained]
    if not retained_sequences:
        raise RoomRetentionGap(room, since + 1, first_seq - 1, [])
    export_first = min(retained_sequences)
    if export_first > since + 1:
        raise RoomRetentionGap(room, since + 1, export_first - 1, retained)
    return retained


def _candidate_targets_maru(row: dict, request_id: str) -> bool:
    raw = str(row.get("text") or "")
    lowered = raw.lower()
    anchors = (
        MARU_DID.lower(),
        "minermaru73",
        GAME_ID,
        request_id.lower(),
    )
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        payload = None
    if isinstance(payload, dict):
        if payload.get("target_did") == MARU_DID:
            return True
        if payload.get("request_id") == request_id:
            return True
        message = str(payload.get("text") or "").lower()
        if any(anchor in message for anchor in anchors):
            return True
    return any(anchor in lowered for anchor in anchors)


def _public_evidence(
    rows: list[tuple[str, dict]],
) -> list[tuple[str, dict, tuple[str, str]]]:
    result = []

    for room, row in rows:
        sender = row.get("from")
        sequence = row.get("seq")

        invite_candidate = False
        if (
            room == DISCOVERY_ROOM
            and sender in INVITE_BY_DID
            and type(sequence) is int
        ):
            request_id = INVITE_BY_DID[sender]
            invite_candidate = (
                sequence > INVITATIONS[request_id]["sent_seq"]
                and _candidate_targets_maru(row, request_id)
            )

        team_candidate = False
        if room == RESULTS_ROOM and sender == REFEREE_DID:
            try:
                decoded = json.loads(row.get("text", ""))
            except (TypeError, ValueError):
                decoded = None
            if isinstance(decoded, dict):
                team_candidate = (
                    decoded.get("contest_id") == "sonnet-2"
                    and decoded.get("game_id") == GAME_ID
                    and decoded.get("poem_room") == TEAM_ROOM
                    and decoded.get("type") in {"sonnet.setup.v1", "sonnet.resetup.v1"}
                    and type(decoded.get("room_generation")) is int
                    and decoded["room_generation"] > 0
                )

        if not (invite_candidate or team_candidate):
            continue

        try:
            verify_signed_record(room, row)
        except (KeyError, TypeError, ValueError, RuntimeError):
            continue

        if invite_candidate:
            result.append(
                (
                    "invite",
                    row,
                    (
                        "招待済みwriterからMARU宛てactivity",
                        "招待後に本人DIDの署名済みMARU宛てdiscovery投稿を確認。参加意思・availability・roster consentとはまだ断定しません。",
                    ),
                )
            )

        if team_candidate:
            result.append(
                (
                    "team",
                    row,
                    (
                        "MARU team-room generation/setup receipt",
                        "referee の署名済みresults recordで正式room/generationを確認しました。team request自体から参加・権限は推測していません。",
                    ),
                )
            )

    return result


def _record_time(row: dict) -> float | None:
    for key in ("updated_at", "created_at", "ts"):
        value = row.get(key)
        if not isinstance(value, str) or not value:
            continue
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            continue
    return None


def _initial_new(row: dict, cutoff: float) -> bool:
    timestamp = _record_time(row)
    return timestamp is not None and timestamp > cutoff


def _notice(row: dict, relevant: tuple[str, str]) -> str:
    headline, why = relevant
    excerpt = discord_control.safe_excerpt(
        row.get("body", row.get("text", "")),
        220,
    )
    return "\n".join(
        [
            f"🟣 Sonnet-2: {headline}",
            f"何が起きた: {excerpt or '署名済み/公式更新を検出'}",
            f"重要性: {why}",
            "MARU: 公式・署名済みの根拠を確認",
            "注意: activity・返信・招待はroster consentを自動では意味しません。このwatcherは署名・投稿を行っていません。",
        ]
    )


def _gap_notice(error: RoomRetentionGap) -> str:
    return "\n".join(
        [
            "🔴 Sonnet-2: 監視ギャップを検出",
            f"何が起きた: {error.room} の seq {error.missing_from}..{error.missing_to} はexport保持範囲にも残っていません。",
            "重要性: この区間にMARU関連のactivity・setup証拠があった可能性を自動では否定できません。",
            "MARU: 公式状態を手動再確認するまで不可逆操作を進めない",
            "注意: 自動送信・再招待・roster consent は行っていません。",
        ]
    )


def _github_poll(
    state: dict,
    issue: int,
    rows: list[dict],
    notices: list[str],
) -> None:
    source = f"gh:{issue}"
    raw_progress = state["github"].get(source)
    progress = raw_progress if isinstance(raw_progress, dict) else {}
    initialized = progress.get("initialized") is True
    baseline_id = progress.get("max_id") if type(progress.get("max_id")) is int else -1
    baseline_updated = str(progress.get("max_updated_at", ""))
    next_id = baseline_id
    next_updated = baseline_updated

    for row in rows:
        identifier = row.get("id") if type(row.get("id")) is int else -1
        updated = str(row.get("updated_at", ""))
        is_new = identifier > baseline_id or updated > baseline_updated
        relevant = _github_relevant(issue, row)

        if relevant and (
            (initialized and is_new)
            or (not initialized and _initial_new(row, state["initial_cutoff"]))
        ):
            notices.append(_notice(row, relevant))

        next_id = max(next_id, identifier)
        next_updated = max(next_updated, updated)

    state["github"][source] = {
        "initialized": True,
        "max_id": next_id,
        "max_updated_at": next_updated,
    }


def _room_poll(
    state: dict,
    room: str,
    rows: list[dict],
    notices: list[str],
) -> None:
    raw_progress = state["rooms"].get(room)
    progress = raw_progress if isinstance(raw_progress, dict) else {}
    initialized = progress.get("initialized") is True
    prior_seq = progress.get("seq") if type(progress.get("seq")) is int else -1

    for row in rows:
        sequence = row.get("seq") if type(row.get("seq")) is int else -1
        is_new = sequence > prior_seq

        for _kind, evidence_row, relevant in _public_evidence([(room, row)]):
            if (
                (initialized and is_new)
                or (
                    not initialized
                    and _initial_new(evidence_row, state["initial_cutoff"])
                )
            ):
                notices.append(_notice(evidence_row, relevant))

        prior_seq = max(prior_seq, sequence)

    state["rooms"][room] = {
        "initialized": True,
        "seq": prior_seq,
    }


def poll_notices(
    *,
    now: float | None = None,
    fetch=_fetch,
    room_read=_room_rows,
) -> list[str]:
    """Fixed GET-only polling; called by Discord's existing ``to_thread`` worker."""
    current = time.time() if now is None else now
    state = _load()

    if state["pending"]:
        batch = state["pending"][:4]
        state["pending"] = state["pending"][4:]
        _save(state)
        return batch

    if current < state["next_poll_at"]:
        return []

    notices: list[str] = []
    successes = 0

    for issue in ISSUES:
        try:
            rows = fetch(issue)
        except (
            httpx.HTTPError,
            OSError,
            TypeError,
            ValueError,
            RuntimeError,
        ):
            continue

        successes += 1
        _github_poll(state, issue, rows, notices)

    for room in (DISCOVERY_ROOM, RESULTS_ROOM):
        raw_progress = state["rooms"].get(room)
        progress = raw_progress if isinstance(raw_progress, dict) else {}
        initialized = progress.get("initialized") is True
        since = (
            progress.get("seq")
            if initialized and type(progress.get("seq")) is int
            else None
        )

        gap_error: RoomRetentionGap | None = None
        try:
            rows = room_read(room, since)
        except RoomRetentionGap as error:
            rows = error.rows
            gap_error = error
        except (
            httpx.HTTPError,
            OSError,
            TypeError,
            ValueError,
            RuntimeError,
        ):
            continue

        successes += 1
        _room_poll(state, room, rows, notices)
        if gap_error is not None:
            notices.append(_gap_notice(gap_error))

    if not successes:
        failures = min(state["failures"] + 1, 6)
        state.update(
            failures=failures,
            next_poll_at=current
            + min(
                MAX_BACKOFF_SECONDS,
                30 * 2 ** (failures - 1),
            ),
        )
        _save(state)
        return []

    state.update(
        failures=0,
        next_poll_at=current + POLL_SECONDS,
    )
    state["pending"] = notices[4 : 4 + PENDING_LIMIT]
    _save(state)
    return notices[:4]
