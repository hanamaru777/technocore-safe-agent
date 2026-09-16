#!/usr/bin/env python3
"""Read-only authoritative Sonnet-2 registration/identity readback for MARU.

Reads only public Technocore room exports, verifies referee-signed records locally,
and prints a narrow status summary. It never signs, posts, mutates repo/state, or
reads signer-private material.
"""
from __future__ import annotations

import json
from collections.abc import Iterable

import httpx

from flop_agent.public_record import verify_signed_record

BASE = "https://technocore.chat/r"
REGISTRATION_ROOM = "mb-sonnet-2-registration"
RESULTS_ROOM = "d-sonnet-2-results"
REFEREE_DID = "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
DID = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
REQUEST_ID = "32c15433c6d73af1cea5d6467dece016"
EXPECTED_REGISTRATION = {
    "type": "sonnet.register.v1",
    "contest_id": "sonnet-2",
    "role": "writer",
    "x_account_url": "https://x.com/MinerMaru73",
    "request_id": REQUEST_ID,
}


def iter_export(room: str) -> Iterable[dict]:
    timeout = httpx.Timeout(35.0, connect=10.0)
    with httpx.stream(
        "GET",
        f"{BASE}/{room}/export",
        timeout=timeout,
        headers={"user-agent": "technocore-safe-agent/maru-registration-readback"},
    ) as response:
        response.raise_for_status()
        for line in response.iter_lines():
            if not line or not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                yield value


def _did_matches(payload: dict) -> bool:
    for key in ("participant_did", "sender_did", "did"):
        value = payload.get(key)
        if value is not None:
            return str(value) == DID
    return True


def receipt_from_payload(payload: object) -> dict | None:
    if not isinstance(payload, dict):
        return None
    typ = payload.get("type")
    if typ == "sonnet.receipt.v1":
        if str(payload.get("request_id", "")) == REQUEST_ID and _did_matches(payload):
            return payload
        return None
    if typ == "sonnet.receipts.v1":
        receipts = payload.get("receipts")
        if not isinstance(receipts, list):
            return None
        for item in receipts:
            if (
                isinstance(item, dict)
                and str(item.get("request_id", "")) == REQUEST_ID
                and _did_matches(item)
            ):
                return item
    return None


def contains_did(value: object) -> bool:
    if isinstance(value, str):
        return value == DID
    if isinstance(value, list):
        return any(contains_did(item) for item in value)
    if isinstance(value, dict):
        return any(contains_did(item) for item in value.values())
    return False


def official_payload(room: str, row: dict) -> dict | None:
    if row.get("from") != REFEREE_DID:
        return None
    try:
        verify_signed_record(room, row)
        payload = json.loads(row.get("text", ""))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def scan_registration() -> tuple[dict | None, dict | None, int, int]:
    receipt = None
    own_registration = None
    rows = 0
    max_seq = 0
    for row in iter_export(REGISTRATION_ROOM):
        rows += 1
        if type(row.get("seq")) is int:
            max_seq = max(max_seq, row["seq"])
        if row.get("from") == DID:
            try:
                verify_signed_record(REGISTRATION_ROOM, row)
                payload = json.loads(row.get("text", ""))
            except (ValueError, TypeError, json.JSONDecodeError):
                payload = None
            if payload == EXPECTED_REGISTRATION:
                own_registration = row
        payload = official_payload(REGISTRATION_ROOM, row)
        if payload is None:
            continue
        candidate = receipt_from_payload(payload)
        if candidate is not None:
            receipt = {"row": row, "receipt": candidate, "envelope_type": payload.get("type")}
    return receipt, own_registration, rows, max_seq


def scan_results() -> tuple[dict | None, int, int]:
    attestation = None
    rows = 0
    max_seq = 0
    for row in iter_export(RESULTS_ROOM):
        rows += 1
        if type(row.get("seq")) is int:
            max_seq = max(max_seq, row["seq"])
        payload = official_payload(RESULTS_ROOM, row)
        if payload is None or payload.get("type") != "sonnet.identities.v1":
            continue
        if contains_did(payload):
            attestation = {"row": row, "payload": payload}
    return attestation, rows, max_seq


def safe_status(receipt: dict) -> str:
    value = str(receipt.get("status", "unknown")).lower()
    return value if value in {"accepted", "rejected"} else "unknown"


def main() -> None:
    print("MARU_REGISTRATION_AUTHORITY_READBACK=START")
    try:
        receipt, own, reg_rows, reg_max = scan_registration()
        attestation, results_rows, results_max = scan_results()
    except Exception as error:
        print("READBACK=FAIL:" + type(error).__name__)
        raise SystemExit(1) from None

    print(f"REG_EXPORT_ROWS={reg_rows} MAX_SEQ={reg_max}")
    print(f"RESULTS_EXPORT_ROWS={results_rows} MAX_SEQ={results_max}")
    if own is None:
        print("REGISTRATION_RECORD=CURRENT_EXPORT_NOT_FOUND")
    else:
        print(f"REGISTRATION_RECORD=FOUND SEQ={own.get('seq')} TS={own.get('ts')}")

    if attestation is None:
        print("IDENTITY_ATTESTATION=CURRENT_RESULTS_EXPORT_NOT_FOUND")
    else:
        row = attestation["row"]
        print(f"IDENTITY_ATTESTATION=FOUND SEQ={row.get('seq')} TS={row.get('ts')} SIGNATURE=VERIFIED")

    if receipt is None:
        print("OFFICIAL_REGISTRATION_RECEIPT=CURRENT_EXPORT_NOT_FOUND")
        print("AUTHORITATIVE_STATUS=UNRESOLVED_BY_CURRENT_PUBLIC_EXPORT")
        print("NOTE=absence_from_rolling_registration_export_is_not_historical_rejection")
        return

    row = receipt["row"]
    item = receipt["receipt"]
    status = safe_status(item)
    intake_seq = item.get("intake_seq")
    reason = item.get("reason") or item.get("reason_code") or item.get("error")
    print(f"OFFICIAL_REGISTRATION_RECEIPT=FOUND STATUS={status} ROOM_SEQ={row.get('seq')} TS={row.get('ts')} SIGNATURE=VERIFIED")
    print(f"RECEIPT_INTAKE_SEQ={intake_seq}")
    if reason is not None:
        print("RECEIPT_REASON=" + str(reason).replace("\n", " ")[:300])
    if status == "accepted":
        print("AUTHORITATIVE_STATUS=ACCEPTED")
    elif status == "rejected":
        print("AUTHORITATIVE_STATUS=REJECTED")
    else:
        print("AUTHORITATIVE_STATUS=UNKNOWN_RECEIPT_STATUS")


if __name__ == "__main__":
    main()
