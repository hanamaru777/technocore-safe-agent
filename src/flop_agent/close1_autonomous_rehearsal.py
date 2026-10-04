"""Non-binding rehearsal for the resident-side Close Call orchestration path.

Consumes the local rehearsal stage after one checked attempt, writes no signer
approval, never accesses Vault material, and never posts. It independently
revalidates a staged offer/account/deadline/policy and reports whether the
existing exact executor would be eligible to start.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from . import close1_account_reconciliation as account
from . import close1_autonomous_stage as stage_mod
from . import close_call, core, observer, public_record

SCHEMA_VERSION = 1
MAX_STAGE_BYTES = 16 * 1024
MAX_STAGE_AGE_SECONDS = 15


def _now() -> datetime:
    return datetime.now(UTC)


def result_path() -> Path:
    return core.STATE / "close1" / "close1-autonomous-rehearsal.json"


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise RuntimeError("close1_auto_rehearsal_duplicate_field")
        value[key] = item
    return value


def _time(value: object) -> datetime:
    if not isinstance(value, str):
        raise RuntimeError("close1_auto_rehearsal_time_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RuntimeError("close1_auto_rehearsal_time_invalid") from error
    if parsed.tzinfo is None:
        raise RuntimeError("close1_auto_rehearsal_time_invalid")
    return parsed.astimezone(UTC)


def _load_stage(*, now: datetime | None = None) -> tuple[dict, str]:
    path = stage_mod.stage_path()
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("close1_auto_rehearsal_stage_missing")
    raw = path.read_bytes()
    if len(raw) > MAX_STAGE_BYTES:
        raise RuntimeError("close1_auto_rehearsal_stage_too_large")
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("close1_auto_rehearsal_stage_invalid") from error
    if not isinstance(value, dict) or set(value) != stage_mod.STAGE_FIELDS:
        raise RuntimeError("close1_auto_rehearsal_stage_schema_invalid")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("owner_did") != account.OWNER_DID:
        raise RuntimeError("close1_auto_rehearsal_stage_identity_invalid")
    current = now or _now()
    if current.tzinfo is None:
        raise RuntimeError("close1_auto_rehearsal_time_invalid")
    age = (current.astimezone(UTC) - _time(value.get("staged_at"))).total_seconds()
    if not 0 <= age <= MAX_STAGE_AGE_SECONDS:
        raise RuntimeError("close1_auto_rehearsal_stage_stale")
    return value, hashlib.sha256(raw).hexdigest()


def _fresh_revalidate(stage: dict, *, now: datetime | None = None) -> dict:
    current = now or _now()
    if current.tzinfo is None:
        raise RuntimeError("close1_auto_rehearsal_time_invalid")
    current = current.astimezone(UTC)
    if current >= close_call.LOCK:
        raise RuntimeError("close1_auto_rehearsal_contest_locked")
    wall_sweep = int((current - close_call.OPENING).total_seconds() // 300)
    if wall_sweep < 0 or wall_sweep >= close_call.LOCK_SWEEP:
        raise RuntimeError("close1_auto_rehearsal_sweep_invalid")

    ledger = account.load_ledger(owner_did=account.OWNER_DID)
    account._validate_ledger(ledger, owner_did=account.OWNER_DID)
    if ledger["pending_trade_ids"] or ledger["pending_trades"]:
        raise RuntimeError("close1_auto_rehearsal_pending")
    if stage["trade_id"] in ledger["settled_trade_ids"] or stage["trade_id"] in ledger["void_trades"]:
        raise RuntimeError("close1_auto_rehearsal_terminal")
    cash_text, position = account.scanner_account(ledger)
    cash = Decimal(cash_text)

    response = core.read_room(
        stage["offer_room"],
        since=stage["offer_seq"] - 1,
        limit=200,
        cache_buster=secrets.token_hex(16),
    )
    rows = response.get("messages") if isinstance(response, dict) else None
    if not isinstance(rows, list):
        raise RuntimeError("close1_auto_rehearsal_offer_missing")
    matches = [row for row in rows if isinstance(row, dict) and row.get("seq") == stage["offer_seq"]]
    if len(matches) != 1:
        raise RuntimeError("close1_auto_rehearsal_offer_missing")
    message = matches[0]
    offer = close_call.parse_verified_public_offer(
        message,
        current_sweep=wall_sweep,
        our_did=account.OWNER_DID,
        room=stage["offer_room"],
    )
    try:
        payload = json.loads(message["text"], object_pairs_hook=_unique)
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("close1_auto_rehearsal_offer_invalid") from error
    terms = payload.get("terms") if isinstance(payload, dict) else None
    if not isinstance(terms, dict):
        raise RuntimeError("close1_auto_rehearsal_offer_invalid")
    exact = {
        "trade_id": terms.get("id"),
        "maker": terms.get("maker"),
        "maker_side": terms.get("side"),
        "taker_side": offer.taker_side,
        "qty": terms.get("qty"),
        "px": terms.get("px"),
        "until": terms.get("until"),
        "maker_sig": payload.get("maker_sig"),
    }
    if any(stage.get(key) != value for key, value in exact.items()):
        raise RuntimeError("close1_auto_rehearsal_offer_changed")

    price_response = core.read_room(
        "d-close1-price", limit=1, cache_buster=secrets.token_hex(16)
    )
    price_rows = price_response.get("messages") if isinstance(price_response, dict) else None
    if not isinstance(price_rows, list) or len(price_rows) != 1:
        raise RuntimeError("close1_auto_rehearsal_price_missing")
    public_record.verify_signed_record("d-close1-price", price_rows[0])
    json.loads(price_rows[0]["text"], object_pairs_hook=_unique)
    price = close_call._referee_payload(price_rows[0], "price")
    ref = price.get("ref")
    age = price.get("age_s")
    if not isinstance(ref, dict) or type(age) is not int or age < 0:
        raise RuntimeError("close1_auto_rehearsal_price_invalid")
    risk = close_call.evaluate_verified_offer_as_taker(
        message,
        current_sweep=wall_sweep,
        our_did=account.OWNER_DID,
        room=stage["offer_room"],
        reference_price=ref.get("px"),
        reference_age_seconds=age,
        available_cash=cash_text,
        current_position=position,
    )
    required = Decimal(risk["required_cash_before_unknown_clawback"])
    edge = stage_mod._edge_bps(
        taker_side=offer.taker_side,
        px=offer.px,
        reference=Decimal(str(risk["reference"])),
    )
    if offer.qty < stage_mod.MIN_MATERIAL_QTY:
        raise RuntimeError("close1_auto_rehearsal_not_material")
    if required > cash * stage_mod.MAX_CASH_FRACTION:
        raise RuntimeError("close1_auto_rehearsal_cash_budget")
    if edge < stage_mod.MIN_EDGE_BPS:
        raise RuntimeError("close1_auto_rehearsal_edge")

    return {
        "wall_sweep": wall_sweep,
        "cash": cash_text,
        "position": position,
        "required_cash": format(required, "f"),
        "price_edge_bps": format(edge, "f"),
        "offer_fresh": True,
        "price_fresh": True,
        "account_ready": True,
    }


def _record_skip(trade_id: str) -> None:
    skipped = stage_mod._load_skips()
    skipped.add(trade_id)
    if len(skipped) > stage_mod.MAX_SKIP_IDS:
        raise RuntimeError("close1_auto_rehearsal_skip_capacity")
    observer.atomic_json_write(
        stage_mod.skip_path(),
        {"schema_version": SCHEMA_VERSION, "trade_ids": sorted(skipped)},
        compact=True,
        mode=0o660,
    )


def _consume_stage(expected_digest: str) -> None:
    path = stage_mod.stage_path()
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise RuntimeError("close1_auto_rehearsal_stage_changed")
    path.unlink()
    if os.name == "posix":
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def run_once(*, now: datetime | None = None) -> dict:
    current = now or _now()
    stage, digest = _load_stage(now=current)
    fresh = _fresh_revalidate(stage, now=current)
    detected = _time(stage["detected_at"])
    staged = _time(stage["staged_at"])
    capture_to_rehearsal_ms = int((current.astimezone(UTC) - detected).total_seconds() * 1000)
    stage_latency_ms = int((staged - detected).total_seconds() * 1000)
    result = {
        "schema_version": SCHEMA_VERSION,
        "status": "WOULD_EXECUTE",
        "non_binding": True,
        "trade_id": stage["trade_id"],
        "stage_sha256": digest,
        "capture_to_rehearsal_ms": capture_to_rehearsal_ms,
        "capture_to_stage_ms": stage_latency_ms,
        "target_capture_to_executor_ms": 5000,
        "target_met": capture_to_rehearsal_ms <= 5000,
        "fresh_policy": fresh,
        "signer_access": False,
        "approval_written": False,
        "post_attempted": False,
        "evaluated_at": current.astimezone(UTC).isoformat(),
    }
    observer.atomic_json_write(result_path(), result, compact=True, mode=0o660)
    _record_skip(stage["trade_id"])
    _consume_stage(digest)
    return result


def main() -> int:
    try:
        result = run_once()
    except Exception as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result["target_met"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
