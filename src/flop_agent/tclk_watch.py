"""Read-only tclk/1 offer validation through the official parser runtime."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from .public_record import verify_signed_record


OFFER_ROOM = "tclk-offers"
PAPER_RAIL = "paper"
TCLK_PREFIX = "tclk1 "
MAX_FRAME_CHARS = 4096
BRIDGE = Path(__file__).resolve().parents[2] / "tools" / "tclk_decode.mjs"
DID = re.compile(r"^did:key:z6Mk[A-Za-z0-9]{44}$")
OFFER_ID = re.compile(r"^0x[0-9a-f]{64}$")


def _node_environment() -> dict[str, str]:
    """Pass only OS launch essentials; never forward keys or the full environment."""
    allowed = {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP"}
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}


def official_offer(text: object) -> dict | None:
    """Decode with pinned @flop-labs/tclk; malformed/runtime failures stay invisible."""
    if not isinstance(text, str) or not text.startswith(TCLK_PREFIX) or len(text) > MAX_FRAME_CHARS:
        return None
    if not all(0x20 <= ord(char) <= 0x7E for char in text):
        return None
    try:
        result = subprocess.run(
            ["node", str(BRIDGE)], input=json.dumps({"text": text}), text=True,
            capture_output=True, timeout=3, check=False, env=_node_environment(),
        )
        if result.returncode != 0:
            return None
        decoded = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None
    if not isinstance(decoded, dict) or set(decoded) != {"frame"} or not isinstance(decoded["frame"], dict):
        return None
    return decoded["frame"]


def _tclk_state(state: dict) -> dict | None:
    data = state.setdefault("tclk", {"schema_version": 1, "offers": {}, "seen_offer_ids": []})
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("offers"), dict) or not isinstance(data.get("seen_offer_ids"), list):
        return None
    return data


def observe_offer(state: dict, message: dict, transport_from: str | None) -> dict | None:
    """Accept one safe, unseen, signed PaperRail hash offer; never posts or signs."""
    if transport_from is None or not DID.fullmatch(transport_from):
        return None
    try:
        verify_signed_record(OFFER_ROOM, message)
    except ValueError:
        return None
    frame = official_offer(message.get("text"))
    if frame is None or frame.get("from") != transport_from or frame.get("type") != "offer":
        return None
    if frame.get("lock") != "hash" or frame.get("rails") != [PAPER_RAIL]:
        return None
    offer_id = frame.get("id")
    expires = frame.get("expiresMs")
    amount, asset, role = frame.get("amount"), frame.get("asset"), frame.get("role")
    if not isinstance(offer_id, str) or not OFFER_ID.fullmatch(offer_id) or not isinstance(expires, int) or expires <= int(datetime.now(UTC).timestamp() * 1000):
        return None
    if not isinstance(amount, str) or not amount.isdecimal() or not isinstance(asset, str) or not asset or role not in {"payer", "payee"}:
        return None
    data = _tclk_state(state)
    if data is None or offer_id in data["seen_offer_ids"]:
        return None
    job = frame.get("job") if isinstance(frame.get("job"), dict) else {}
    context = job.get("context") if isinstance(job.get("context"), str) else ""
    record = {
        "id": offer_id, "counterpart_fingerprint": hashlib.sha256(transport_from.encode()).hexdigest()[:16],
        "from": transport_from, "frame_type": "offer", "job_proto": job.get("proto") if isinstance(job.get("proto"), str) else None,
        "job_id": job.get("id") if isinstance(job.get("id"), str) else None, "amount": amount, "asset": asset,
        "rail": PAPER_RAIL, "expires_ms": expires, "terms": context[:280], "room": OFFER_ROOM,
        "seq": message.get("seq"), "ts": message.get("ts"), "untrusted": True, "read_only": True, "accepted": False,
    }
    data["seen_offer_ids"].append(offer_id)
    del data["seen_offer_ids"][:-1000]
    data["offers"][offer_id] = record
    if len(data["offers"]) > 250:
        oldest = next(iter(data["offers"]))
        del data["offers"][oldest]
    return record


def opportunities(state: dict) -> list[dict]:
    data = state.get("tclk")
    if not isinstance(data, dict) or not isinstance(data.get("offers"), dict):
        return []
    rows = [item for item in data["offers"].values() if isinstance(item, dict) and item.get("read_only") is True and item.get("accepted") is False]
    return sorted(rows, key=lambda item: item.get("expires_ms", 0))


def offer(state: dict, offer_id: str) -> dict | None:
    data = state.get("tclk")
    item = data.get("offers", {}).get(offer_id) if isinstance(data, dict) else None
    return item if isinstance(item, dict) and item.get("read_only") is True and item.get("accepted") is False else None
