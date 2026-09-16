from __future__ import annotations

import json
import secrets

from flop_agent import core
from flop_agent.public_record import verify_signed_record

ROOM = "mb-sonnet-2-registration"
REFEREE_DID = "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
MARU_DID = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
REQUEST_ID = "32c15433c6d73af1cea5d6467dece016"
START_SEQ = 2_451_083
PAGE_LIMIT = 200
MAX_PAGES = 150


def matching_receipt(payload: object) -> dict | None:
    if not isinstance(payload, dict):
        return None
    if payload.get("type") == "sonnet.receipt.v1":
        candidates = [payload]
    elif payload.get("type") == "sonnet.receipts.v1" and isinstance(payload.get("receipts"), list):
        candidates = [item for item in payload["receipts"] if isinstance(item, dict)]
    else:
        return None
    for item in candidates:
        if str(item.get("request_id", "")) != REQUEST_ID:
            continue
        participant = item.get("participant_did", item.get("sender_did", item.get("did")))
        if str(participant) != MARU_DID:
            continue
        status = str(item.get("status", "")).lower()
        if status not in {"accepted", "rejected"}:
            continue
        return item
    return None


def main() -> None:
    cursor = START_SEQ
    scanned = 0
    pages = 0
    first_seen: int | None = None
    last_seen = START_SEQ

    while pages < MAX_PAGES:
        payload = core.read_room(
            ROOM,
            since=cursor,
            wait=0,
            limit=PAGE_LIMIT,
            cache_buster=secrets.token_hex(8),
        )
        rows = payload if isinstance(payload, list) else payload.get("messages", [])
        if not isinstance(rows, list):
            raise SystemExit("READBACK=STOP:invalid_room_payload")

        first_seq = payload.get("first_seq") if isinstance(payload, dict) else None
        if type(first_seq) is int:
            first_seen = first_seq if first_seen is None else min(first_seen, first_seq)
            if first_seq > cursor + 1:
                print(json.dumps({
                    "result": "GAP_BEFORE_SCAN",
                    "cursor": cursor,
                    "first_seq": first_seq,
                    "pages": pages,
                    "scanned": scanned,
                }, sort_keys=True))
                return

        if not rows:
            print(json.dumps({
                "result": "NO_MATCH_CAUGHT_UP",
                "start_seq": START_SEQ,
                "last_scanned_seq": last_seen,
                "pages": pages,
                "scanned": scanned,
                "first_seen": first_seen,
            }, sort_keys=True))
            return

        max_row_seq = cursor
        for row in rows:
            if not isinstance(row, dict):
                continue
            seq = row.get("seq")
            if type(seq) is int:
                max_row_seq = max(max_row_seq, seq)
                last_seen = max(last_seen, seq)
            scanned += 1
            if row.get("from") != REFEREE_DID:
                continue
            try:
                verify_signed_record(ROOM, row)
                decoded = json.loads(row.get("text", ""))
            except (ValueError, TypeError, json.JSONDecodeError):
                continue
            receipt = matching_receipt(decoded)
            if receipt is None:
                continue
            print(json.dumps({
                "result": "OFFICIAL_RECEIPT_FOUND",
                "status": str(receipt.get("status")).lower(),
                "request_id": REQUEST_ID,
                "participant_did": MARU_DID,
                "receipt_room_seq": row.get("seq"),
                "receipt_room_ts": row.get("ts"),
                "intake_seq": receipt.get("intake_seq"),
                "reason": receipt.get("reason") or receipt.get("reason_code") or receipt.get("error"),
                "pages": pages + 1,
                "scanned": scanned,
            }, sort_keys=True))
            return

        if max_row_seq <= cursor:
            print(json.dumps({
                "result": "STOP_NON_ADVANCING_CURSOR",
                "cursor": cursor,
                "pages": pages + 1,
                "scanned": scanned,
            }, sort_keys=True))
            return

        cursor = max_row_seq
        pages += 1

    print(json.dumps({
        "result": "BOUNDED_SCAN_LIMIT_REACHED",
        "start_seq": START_SEQ,
        "last_scanned_seq": last_seen,
        "pages": pages,
        "scanned": scanned,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
