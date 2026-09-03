"""Offline verification for public Technocore signed records.

This is the package counterpart of the existing public evidence verifier.  It
accepts no secret material and only verifies ``room|nonce|text`` locally.
"""
from __future__ import annotations

import base64
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOM_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
DID_RE = re.compile(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{20,128}")
NONCE_RE = re.compile(r"[0-9]{1,19}")
SIG_RE = re.compile(r"[A-Za-z0-9_-]{86}")
MULTICODEC_ED25519 = b"\xed\x01"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {char: index for index, char in enumerate(B58)}


def _b58decode(value: str) -> bytes:
    if not value or any(char not in B58_INDEX for char in value):
        raise ValueError("invalid base58btc")
    number = 0
    for char in value:
        number = number * 58 + B58_INDEX[char]
    raw = b"" if number == 0 else number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + raw


def _public_key(did: str) -> Ed25519PublicKey:
    if not DID_RE.fullmatch(did):
        raise ValueError("invalid Ed25519 did:key")
    decoded = _b58decode(did.removeprefix("did:key:z"))
    if len(decoded) != 34 or decoded[:2] != MULTICODEC_ED25519:
        raise ValueError("did:key is not Ed25519 multicodec")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def verify_signed_record(room: str, record: dict) -> None:
    """Raise on every malformed or unsigned record; never performs I/O."""
    did, signature, text = record.get("from"), record.get("sig"), record.get("text")
    nonce = str(record.get("nonce", ""))
    if not ROOM_RE.fullmatch(room) or not isinstance(did, str) or not isinstance(signature, str) or not isinstance(text, str):
        raise ValueError("record is not signed")
    if not NONCE_RE.fullmatch(nonce) or not SIG_RE.fullmatch(signature):
        raise ValueError("invalid signed record")
    try:
        raw = base64.urlsafe_b64decode(signature + "==")
    except Exception as error:
        raise ValueError("invalid Technocore signature encoding") from error
    if len(raw) != 64:
        raise ValueError("invalid Ed25519 signature length")
    try:
        _public_key(did).verify(raw, f"{room}|{nonce}|{text}".encode("utf-8"))
    except InvalidSignature as error:
        raise ValueError("signature verification failed") from error
