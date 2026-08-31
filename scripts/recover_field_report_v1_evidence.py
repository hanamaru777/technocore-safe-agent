#!/usr/bin/env python3
"""Recover public cryptographic evidence for the acknowledged Contribution #2.

No network write is performed and the contribution POST is never retried.
This helper is for the case where the server already acknowledged the fixed
field-report message but a later read-only `/export` capture missed the record
because the room ring advanced.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from flop_agent import core, oracle_signer
from publish_field_report_v1 import ACTION, CONTRIBUTION_ID, FIELD_REPORT_TEXT, ROOM, load_receipt

OUT_NAME = f"{CONTRIBUTION_ID}-ack-signature-evidence.json"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {char: index for index, char in enumerate(B58)}
MULTICODEC_ED25519 = b"\xed\x01"


def now() -> str:
    return datetime.now(UTC).isoformat()


def output_path() -> Path:
    return core.STATE / "contributions" / OUT_NAME


def b58decode(value: str) -> bytes:
    if not value or any(char not in B58_INDEX for char in value):
        raise RuntimeError("invalid did:key base58btc")
    number = 0
    for char in value:
        number = number * 58 + B58_INDEX[char]
    raw = b"" if number == 0 else number.to_bytes((number.bit_length() + 7) // 8, "big")
    leading = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading + raw


def public_key(did: str) -> Ed25519PublicKey:
    if not did.startswith("did:key:z6Mk"):
        raise RuntimeError("unexpected DID")
    decoded = b58decode(did.removeprefix("did:key:z"))
    if len(decoded) != 34 or decoded[:2] != MULTICODEC_ED25519:
        raise RuntimeError("DID is not Ed25519")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def decode_sig(value: str) -> bytes:
    raw = base64.urlsafe_b64decode(value + "==")
    if len(value) != 86 or len(raw) != 64:
        raise RuntimeError("invalid public signature encoding")
    return raw


def matching_activity(receipt: dict) -> dict:
    path = core.STATE / "activities.jsonl"
    if not path.exists():
        raise RuntimeError("acknowledged activity log is missing")
    matches: list[dict] = []
    for line in path.read_text("utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if (
            record.get("action") == ACTION
            and record.get("room") == ROOM
            and record.get("seq") == receipt.get("seq")
            and record.get("did") == receipt.get("did")
            and str(record.get("nonce")) == str(receipt.get("nonce"))
            and record.get("text") == FIELD_REPORT_TEXT
        ):
            matches.append(record)
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one acknowledged activity record, found {len(matches)}")
    if not core.verify_activity_log()[0]:
        raise RuntimeError("activity hash-chain verification failed")
    return matches[0]


def build() -> dict:
    if len(sys.argv) != 1:
        raise RuntimeError("fixed-function recovery helper accepts no arguments")
    receipt = load_receipt()
    if not isinstance(receipt, dict) or receipt.get("state") != "acknowledged":
        raise RuntimeError("Contribution #2 is not locally acknowledged; refusing recovery")
    if not isinstance(receipt.get("seq"), int) or receipt["seq"] < 0:
        raise RuntimeError("acknowledged receipt has no valid server seq")
    if not isinstance(receipt.get("ts"), str):
        raise RuntimeError("acknowledged receipt has no server timestamp")
    if receipt.get("text_hash") != hashlib.sha256(FIELD_REPORT_TEXT.encode()).hexdigest():
        raise RuntimeError("acknowledged receipt text hash mismatch")

    activity = matching_activity(receipt)
    did = oracle_signer.verify_did()
    if did != receipt["did"]:
        raise RuntimeError("continuing signer DID does not match acknowledged receipt")

    signed = oracle_signer.with_vault_seed(
        lambda: core.invoke_signer("say", ROOM, str(receipt["nonce"]), FIELD_REPORT_TEXT)
    )
    if len(signed) != 2 or signed[0] != receipt["did"]:
        raise RuntimeError("official signer reconstruction failed")
    signature = signed[1]
    canonical = f"{ROOM}|{receipt['nonce']}|{FIELD_REPORT_TEXT}".encode("utf-8")
    try:
        public_key(receipt["did"]).verify(decode_sig(signature), canonical)
    except InvalidSignature as error:
        raise RuntimeError("reconstructed signature failed offline verification") from error

    return {
        "schema_version": 1,
        "kind": "technocore_acknowledged_signature_reconstruction",
        "evidence_class": "acknowledged_post_receipt_plus_deterministic_ed25519_reconstruction",
        "created_at": now(),
        "room": ROOM,
        "record": {
            "seq": receipt["seq"],
            "ts": receipt["ts"],
            "from": receipt["did"],
            "nonce": str(receipt["nonce"]),
            "text": FIELD_REPORT_TEXT,
            "sig": signature,
        },
        "canonical_sha256": hashlib.sha256(canonical).hexdigest(),
        "signature_verified": True,
        "local_ack": {
            "acknowledged_at": receipt.get("acknowledged_at"),
            "activity_hash": activity.get("hash"),
            "activity_previous_hash": activity.get("previous_hash"),
            "git_commit_sha": activity.get("git_commit_sha"),
            "official_commit": activity.get("official_commit"),
            "action": ACTION,
        },
        "signer_provenance": {
            "official_signer_blob_sha": core.SIGNER_BLOB_SHA,
            "official_signer_sha256": core.SIGNER_SHA256,
        },
        "limitations": [
            "The message was already acknowledged before this recovery step; this helper performs no POST.",
            "The room record was not retained in a later official /export capture, so seq and ts are anchored by the locally persisted exact-validated POST receipt/activity rather than a retained export record.",
            "The Ed25519 signature covers room|nonce|text; server-assigned seq and ts are not covered by that signature.",
        ],
    }


def main() -> None:
    try:
        evidence = build()
        path = output_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            existing = json.loads(path.read_text("utf-8"))
            lhs = {key: value for key, value in existing.items() if key != "created_at"}
            rhs = {key: value for key, value in evidence.items() if key != "created_at"}
            if lhs != rhs:
                raise RuntimeError("existing recovery evidence differs; refusing overwrite")
            print(json.dumps(existing, ensure_ascii=False, indent=2, sort_keys=True))
            return
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(evidence, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(path, 0o600)
        print(json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True))
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
