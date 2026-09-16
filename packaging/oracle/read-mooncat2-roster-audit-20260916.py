from __future__ import annotations

import json
import secrets

from flop_agent import core
from flop_agent.public_record import verify_signed_record

DISCOVERY = "mb-sonnet-2-discovery"
TEAM_ROOM = "d-sonnet-2-team-mooncat2"
REFEREE_DID = "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
MARU_DID = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
GAME_ID = "mooncat2"
EXPECTED_ROOM_GENERATION = 2
SOURCE_ROSTER_SEQ = 116895
DISCOVERY_START = 116000
PAGE_LIMIT = 200
MAX_DISCOVERY_PAGES = 10
MAX_TEAM_PAGES = 10


def _rows(payload: object) -> list[dict]:
    if isinstance(payload, list):
        values = payload
    elif isinstance(payload, dict):
        values = payload.get("messages", [])
    else:
        raise RuntimeError("invalid_room_payload")
    if not isinstance(values, list):
        raise RuntimeError("invalid_messages_payload")
    return [item for item in values if isinstance(item, dict)]


def _read_bounded(room: str, start: int, max_pages: int) -> tuple[list[dict], dict]:
    cursor = start
    seen: list[dict] = []
    meta = {"room": room, "start": start, "gap": None, "first_seq": None, "last_seq": start, "pages": 0}
    for page in range(max_pages):
        payload = core.read_room(
            room,
            since=cursor,
            wait=0,
            limit=PAGE_LIMIT,
            cache_buster=secrets.token_hex(8),
        )
        rows = _rows(payload)
        if isinstance(payload, dict):
            first_seq = payload.get("first_seq")
            if type(first_seq) is int:
                meta["first_seq"] = first_seq if meta["first_seq"] is None else min(meta["first_seq"], first_seq)
                if page == 0 and first_seq > cursor + 1:
                    meta["gap"] = {"cursor": cursor, "first_seq": first_seq}
        if not rows:
            break
        max_seq = cursor
        for row in rows:
            seq = row.get("seq")
            if type(seq) is int:
                max_seq = max(max_seq, seq)
                meta["last_seq"] = max(meta["last_seq"], seq)
        seen.extend(rows)
        meta["pages"] = page + 1
        if max_seq <= cursor:
            meta["non_advancing"] = True
            break
        cursor = max_seq
        if len(rows) < PAGE_LIMIT:
            break
    return seen, meta


def _decoded_signed(room: str, row: dict) -> dict | None:
    try:
        verify_signed_record(room, row)
        value = json.loads(row.get("text", ""))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _compact(row: dict, payload: dict) -> dict:
    return {
        "seq": row.get("seq"),
        "ts": row.get("ts"),
        "from": row.get("from"),
        "type": payload.get("type"),
        "request_id": payload.get("request_id"),
        "status": payload.get("status"),
        "game_id": payload.get("game_id"),
        "poem_room": payload.get("poem_room"),
        "room_generation": payload.get("room_generation"),
        "members": payload.get("members"),
        "intake_seq": payload.get("intake_seq"),
        "version": payload.get("version"),
        "reason": payload.get("reason") or payload.get("reason_code") or payload.get("error"),
    }


def main() -> None:
    discovery_rows, discovery_meta = _read_bounded(DISCOVERY, DISCOVERY_START, MAX_DISCOVERY_PAGES)
    team_rows, team_meta = _read_bounded(TEAM_ROOM, 0, MAX_TEAM_PAGES)

    print("DISCOVERY_META=" + json.dumps(discovery_meta, sort_keys=True))
    print("TEAM_META=" + json.dumps(team_meta, sort_keys=True))

    mooncat_discovery: list[dict] = []
    source_roster: dict | None = None
    roster_signers: list[dict] = []
    withdrawals: list[dict] = []
    referee_discovery: list[dict] = []

    for row in discovery_rows:
        payload = _decoded_signed(DISCOVERY, row)
        if payload is None:
            continue
        text = row.get("text", "")
        related = payload.get("game_id") == GAME_ID or GAME_ID in str(payload.get("request_id", "")) or GAME_ID in text
        if not related and row.get("seq") != SOURCE_ROSTER_SEQ:
            continue
        item = _compact(row, payload)
        mooncat_discovery.append(item)
        if row.get("from") == REFEREE_DID:
            referee_discovery.append(item)
        if payload.get("type") == "sonnet.withdraw.v1" and payload.get("game_id") == GAME_ID:
            withdrawals.append(item)
        if payload.get("type") == "sonnet.roster.v1" and payload.get("game_id") == GAME_ID:
            roster_signers.append(item)
        if row.get("seq") == SOURCE_ROSTER_SEQ:
            source_roster = {"summary": item, "payload": payload}

    referee_team: list[dict] = []
    for row in team_rows:
        if row.get("from") != REFEREE_DID:
            continue
        payload = _decoded_signed(TEAM_ROOM, row)
        if payload is None:
            continue
        referee_team.append(_compact(row, payload))

    print("MOONCAT_DISCOVERY=" + json.dumps(mooncat_discovery, ensure_ascii=False, sort_keys=True))
    print("REFEREE_DISCOVERY=" + json.dumps(referee_discovery, ensure_ascii=False, sort_keys=True))
    print("ROSTER_SIGNERS=" + json.dumps(roster_signers, ensure_ascii=False, sort_keys=True))
    print("WITHDRAWALS=" + json.dumps(withdrawals, ensure_ascii=False, sort_keys=True))
    print("REFEREE_TEAM=" + json.dumps(referee_team, ensure_ascii=False, sort_keys=True))

    if source_roster is None:
        print("SOURCE_ROSTER=NOT_RETAINED")
        return

    payload = source_roster["payload"]
    members = payload.get("members")
    member_dids = [item.get("did") for item in members] if isinstance(members, list) and all(isinstance(item, dict) for item in members) else []
    checks = {
        "type": payload.get("type") == "sonnet.roster.v1",
        "contest_id": payload.get("contest_id") == "sonnet-2",
        "game_id": payload.get("game_id") == GAME_ID,
        "poem_room": payload.get("poem_room") == TEAM_ROOM,
        "room_generation": payload.get("room_generation") == EXPECTED_ROOM_GENERATION,
        "member_count_4_to_8": 4 <= len(member_dids) <= 8,
        "members_unique": len(member_dids) == len(set(member_dids)),
        "maru_in_members": MARU_DID in member_dids,
        "sender_in_members": source_roster["summary"].get("from") in member_dids,
    }
    print("SOURCE_ROSTER_PAYLOAD=" + json.dumps(payload, ensure_ascii=False, sort_keys=True))
    print("SOURCE_ROSTER_CHECKS=" + json.dumps(checks, sort_keys=True))
    print("SOURCE_ROSTER_ALL_BASIC_CHECKS=" + ("PASS" if all(checks.values()) else "FAIL"))


if __name__ == "__main__":
    main()
