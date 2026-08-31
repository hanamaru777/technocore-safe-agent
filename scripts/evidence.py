# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.28,<1", "cryptography>=45,<47"]
# ///
"""Capture and verify a public Technocore signed-message evidence snapshot.

No seed/private key is accepted. Capture is read-only and talks only to the
hard-coded public Technocore origin.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BASE_URL = "https://technocore.chat"
ROOM_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
DID_RE = re.compile(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{20,128}")
NONCE_RE = re.compile(r"[0-9]{1,19}")
SIG_RE = re.compile(r"[A-Za-z0-9_-]{86}")
MULTICODEC_ED25519 = b"\xed\x01"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {char: index for index, char in enumerate(B58)}
MAX_EXPORT_BYTES = 12 * 1024 * 1024
RETRYABLE_STATUS = {429, 502, 503, 504}
PUBLIC_RECORD_FIELDS = ("seq", "ts", "from", "nonce", "text", "sig")


def b58decode(value: str) -> bytes:
    if not value or any(char not in B58_INDEX for char in value):
        raise ValueError("invalid base58btc")
    number = 0
    for char in value:
        number = number * 58 + B58_INDEX[char]
    raw = b"" if number == 0 else number.to_bytes((number.bit_length() + 7) // 8, "big")
    leading = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading + raw


def public_key_from_did(did: str) -> Ed25519PublicKey:
    if not DID_RE.fullmatch(did):
        raise ValueError("invalid Ed25519 did:key")
    decoded = b58decode(did.removeprefix("did:key:z"))
    if len(decoded) != 34 or decoded[:2] != MULTICODEC_ED25519:
        raise ValueError("did:key is not Ed25519 multicodec")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def decode_signature(signature: str) -> bytes:
    if not SIG_RE.fullmatch(signature):
        raise ValueError("invalid Technocore signature encoding")
    try:
        raw = base64.urlsafe_b64decode(signature + "==")
    except Exception as error:
        raise ValueError("invalid Technocore signature encoding") from error
    if len(raw) != 64:
        raise ValueError("invalid Ed25519 signature length")
    return raw


def canonical_bytes(room: str, record: dict) -> bytes:
    if not ROOM_RE.fullmatch(room):
        raise ValueError("invalid room")
    nonce = str(record.get("nonce", ""))
    text = record.get("text")
    if not NONCE_RE.fullmatch(nonce) or not isinstance(text, str):
        raise ValueError("invalid signed record")
    return f"{room}|{nonce}|{text}".encode("utf-8")


def verify_record(room: str, record: dict) -> str:
    if not isinstance(record, dict):
        raise ValueError("record must be an object")
    did = record.get("from")
    signature = record.get("sig")
    if not isinstance(did, str) or not isinstance(signature, str):
        raise ValueError("record is not signed")
    canonical = canonical_bytes(room, record)
    try:
        public_key_from_did(did).verify(decode_signature(signature), canonical)
    except InvalidSignature as error:
        raise ValueError("signature verification failed") from error
    return hashlib.sha256(canonical).hexdigest()


def fetch_export(room: str) -> tuple[bytes, str]:
    if not ROOM_RE.fullmatch(room):
        raise ValueError("invalid room")
    url = f"{BASE_URL}/r/{quote(room, safe='')}/export"
    delays = (0, 2, 5, 10, 20)
    last_error: Exception | None = None
    for delay in delays:
        if delay:
            time.sleep(delay)
        try:
            with httpx.stream("GET", url, timeout=30, follow_redirects=False) as response:
                if response.status_code in RETRYABLE_STATUS:
                    retry_after = response.headers.get("retry-after")
                    if retry_after and retry_after.isdecimal():
                        time.sleep(min(int(retry_after), 30))
                    last_error = RuntimeError(
                        f"Technocore export temporarily unavailable: HTTP {response.status_code}"
                    )
                    continue
                response.raise_for_status()
                generation = response.headers.get("x-room-generation")
                if generation is None or not generation.isdecimal():
                    raise RuntimeError("Technocore export missing valid X-Room-Generation")
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > MAX_EXPORT_BYTES:
                        raise RuntimeError("Technocore export exceeded the local safety cap")
                    chunks.append(chunk)
                return b"".join(chunks), generation
        except (httpx.HTTPError, RuntimeError) as error:
            last_error = error
            if (
                isinstance(error, httpx.HTTPStatusError)
                and error.response.status_code not in RETRYABLE_STATUS
            ):
                raise
    raise RuntimeError(
        f"Technocore export failed after bounded read-only retries: {last_error}"
    )


def matching_record(raw: bytes, *, seq: int, did: str) -> tuple[dict, bytes]:
    matches: list[tuple[dict, bytes]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("Technocore export contains invalid JSONL") from error
        if isinstance(record, dict) and record.get("seq") == seq and record.get("from") == did:
            matches.append((record, line))
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one seq/DID match, found {len(matches)}")
    return matches[0]


def build_snapshot(
    room: str, generation: str, export_raw: bytes, record: dict, raw_line: bytes
) -> dict:
    canonical_sha256 = verify_record(room, record)
    public_record = {field: record[field] for field in PUBLIC_RECORD_FIELDS}
    return {
        "schema_version": 1,
        "kind": "technocore_signed_message_evidence",
        "source": {
            "origin": BASE_URL,
            "room": room,
            "room_generation": int(generation),
            "captured_at": datetime.now(UTC).isoformat(),
            "export_sha256": hashlib.sha256(export_raw).hexdigest(),
            "record_jsonl_sha256": hashlib.sha256(raw_line).hexdigest(),
        },
        "record": public_record,
        "canonical_sha256": canonical_sha256,
        "signature_verified": True,
    }


def validate_snapshot(snapshot: dict) -> str:
    if (
        not isinstance(snapshot, dict)
        or snapshot.get("schema_version") != 1
        or snapshot.get("kind") != "technocore_signed_message_evidence"
    ):
        raise ValueError("invalid evidence snapshot schema")
    source = snapshot.get("source")
    record = snapshot.get("record")
    if (
        not isinstance(source, dict)
        or source.get("origin") != BASE_URL
        or not isinstance(record, dict)
    ):
        raise ValueError("invalid evidence snapshot source")
    if set(record) != set(PUBLIC_RECORD_FIELDS):
        raise ValueError("evidence record fields are not allowlisted")
    room = source.get("room")
    if not isinstance(room, str):
        raise ValueError("invalid evidence room")
    digest = verify_record(room, record)
    if snapshot.get("canonical_sha256") != digest or snapshot.get("signature_verified") is not True:
        raise ValueError("evidence digest mismatch")
    for field in ("export_sha256", "record_jsonl_sha256"):
        value = source.get(field)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError(f"invalid {field}")
    generation = source.get("room_generation")
    if not isinstance(generation, int) or generation < 0:
        raise ValueError("invalid room generation")
    return digest


def write_new(path: Path, snapshot: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(snapshot, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    capture = sub.add_parser("capture", help="read-only capture from official /export")
    capture.add_argument("--room", required=True)
    capture.add_argument("--seq", required=True, type=int)
    capture.add_argument("--did", required=True)
    capture.add_argument("--out", required=True, type=Path)

    verify = sub.add_parser("verify", help="offline verify a saved evidence snapshot")
    verify.add_argument("snapshot", type=Path)

    args = parser.parse_args()
    try:
        if args.command == "capture":
            if args.seq < 0:
                raise ValueError("seq must be non-negative")
            if not DID_RE.fullmatch(args.did):
                raise ValueError("invalid expected DID")
            raw, generation = fetch_export(args.room)
            record, raw_line = matching_record(raw, seq=args.seq, did=args.did)
            snapshot = build_snapshot(args.room, generation, raw, record, raw_line)
            write_new(args.out, snapshot)
            print(
                json.dumps(
                    {
                        "ok": True,
                        "snapshot": str(args.out),
                        "seq": args.seq,
                        "room_generation": int(generation),
                        "canonical_sha256": snapshot["canonical_sha256"],
                    },
                    indent=2,
                )
            )
        else:
            snapshot = json.loads(args.snapshot.read_text("utf-8"))
            digest = validate_snapshot(snapshot)
            print(
                json.dumps(
                    {
                        "ok": True,
                        "signature_verified": True,
                        "canonical_sha256": digest,
                    },
                    indent=2,
                )
            )
    except (OSError, ValueError, RuntimeError, httpx.HTTPError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
