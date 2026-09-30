"""Read-only Close Call owner-account reconciliation from the official archive.

The ledger starts at the independently verified sweep-189 mint checkpoint.  A
future binding lane must call :func:`mark_pending` before its irreversible
write and provide the exact sweep expected to settle that trade.  This module
never signs or posts; it only reads fixed official archive paths and folds
authoritative outcomes into a public-safe local ledger.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.request
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Callable

from . import close_call, observer, resident

SCHEMA_VERSION = 2
STATE_FILE = "close1-own-account.json"
OWNER_DID = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
CHECKPOINT_SWEEP = 189
ARCHIVE_BASE = "https://challenges.technocore.chat/close-1/"
INDEX_URL = ARCHIVE_BASE + "index.json"
INDEX_MAX_BYTES = 2 * 1024 * 1024
SWEEP_MAX_BYTES = 8 * 1024 * 1024
MAX_PENDING_SWEEPS_PER_RUN = 4
HEX64_RE = re.compile(r"[0-9a-f]{64}")
ARCHIVE_PATH_RE = re.compile(r"sweeps/([0-9a-f]{64})\.json")
STATUSES = {
    "flat_confirmed",
    "own_state_pending",
    "reconciled",
    "own_state_unreconciled",
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def state_path() -> Path:
    return resident.resident_dir() / STATE_FILE


def _decimal(value: object, *, label: str, nonnegative: bool = True) -> Decimal:
    if not isinstance(value, str):
        raise ValueError(f"close1_account_{label}_invalid")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise ValueError(f"close1_account_{label}_invalid") from error
    if not parsed.is_finite() or (nonnegative and parsed < 0):
        raise ValueError(f"close1_account_{label}_invalid")
    return parsed


def _text(value: Decimal) -> str:
    return format(value, "f")


def checkpoint_ledger(*, owner_did: str = OWNER_DID) -> dict:
    if owner_did != OWNER_DID:
        raise ValueError("close1_account_owner_mismatch")
    close_call._did(owner_did, label="owner")
    return {
        "schema_version": SCHEMA_VERSION,
        "owner_did": owner_did,
        "status": "flat_confirmed",
        "reason": "trusted_mint_checkpoint",
        "as_of_sweep": CHECKPOINT_SWEEP,
        "archive_tip_sweep": CHECKPOINT_SWEEP,
        "cash": "10000",
        "lots": [],
        "position": "0",
        "cumulative_fees": "0",
        "settled_trade_ids": [],
        "void_trades": {},
        "pending_trade_ids": [],
        "pending_trades": {},
        "trade_evidence": {},
        "source_evidence": [
            {
                "kind": "trusted_mint_checkpoint",
                "sweep": CHECKPOINT_SWEEP,
                "cash": "10000",
                "position": "0",
            }
        ],
        "last_reconciled_at": None,
    }


def _fail_closed_ledger(*, owner_did: str, reason: str) -> dict:
    ledger = checkpoint_ledger(owner_did=owner_did)
    ledger.update(
        status="own_state_unreconciled",
        reason=reason,
        cash=None,
        lots=None,
        position=None,
        cumulative_fees=None,
        source_evidence=[],
    )
    return ledger


def _validate_ledger(value: object, *, owner_did: str = OWNER_DID) -> dict:
    if not isinstance(value, dict):
        raise ValueError("close1_account_state_invalid")
    required = {
        "schema_version", "owner_did", "status", "reason", "as_of_sweep",
        "archive_tip_sweep", "cash", "lots", "position", "cumulative_fees",
        "settled_trade_ids", "void_trades", "pending_trade_ids", "pending_trades",
        "trade_evidence", "source_evidence", "last_reconciled_at",
    }
    if set(value) != required or value.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("close1_account_schema_invalid")
    if value.get("owner_did") != owner_did:
        raise ValueError("close1_account_owner_mismatch")
    close_call._did(value["owner_did"], label="owner")
    if value.get("status") not in STATUSES or not isinstance(value.get("reason"), str):
        raise ValueError("close1_account_status_invalid")
    for name in ("as_of_sweep", "archive_tip_sweep"):
        if type(value.get(name)) is not int or value[name] < CHECKPOINT_SWEEP:
            raise ValueError(f"close1_account_{name}_invalid")
    if value["as_of_sweep"] > close_call.LOCK_SWEEP:
        raise ValueError("close1_account_as_of_sweep_invalid")
    if value["archive_tip_sweep"] < value["as_of_sweep"]:
        raise ValueError("close1_account_archive_tip_invalid")

    # A corrupt/unreadable file is represented by an ephemeral fail-closed
    # ledger.  Such a representation is never persisted as an exact account.
    if value["cash"] is None:
        if value["status"] != "own_state_unreconciled" or any(
            value[name] is not None for name in ("lots", "position", "cumulative_fees")
        ):
            raise ValueError("close1_account_unknown_values_invalid")
    else:
        cash = _decimal(value["cash"], label="cash")
        fees = _decimal(value["cumulative_fees"], label="fees")
        if not isinstance(value["lots"], list):
            raise ValueError("close1_account_lots_invalid")
        position = Decimal("0")
        for lot in value["lots"]:
            if not isinstance(lot, list) or len(lot) != 2:
                raise ValueError("close1_account_lot_invalid")
            qty = _decimal(lot[0], label="lot_qty", nonnegative=False)
            px = _decimal(lot[1], label="lot_px")
            if qty == 0 or px <= 0:
                raise ValueError("close1_account_lot_invalid")
            position += qty
        if _decimal(value["position"], label="position", nonnegative=False) != position:
            raise ValueError("close1_account_position_mismatch")
        if cash < 0 or fees < 0:
            raise ValueError("close1_account_balance_invalid")

    settled = value.get("settled_trade_ids")
    if not isinstance(settled, list) or len(set(settled)) != len(settled):
        raise ValueError("close1_account_settled_ids_invalid")
    if any(not isinstance(item, str) or not close_call.TRADE_ID_RE.fullmatch(item) for item in settled):
        raise ValueError("close1_account_settled_ids_invalid")
    for name in ("void_trades", "pending_trades", "trade_evidence"):
        mapping = value.get(name)
        if not isinstance(mapping, dict):
            raise ValueError(f"close1_account_{name}_invalid")
        if any(
            not isinstance(key, str) or not close_call.TRADE_ID_RE.fullmatch(key)
            for key in mapping
        ):
            raise ValueError(f"close1_account_{name}_invalid")
    pending_ids = value.get("pending_trade_ids")
    if (
        not isinstance(pending_ids, list)
        or len(set(pending_ids)) != len(pending_ids)
        or any(
            not isinstance(trade_id, str)
            or not close_call.TRADE_ID_RE.fullmatch(trade_id)
            for trade_id in pending_ids
        )
        or pending_ids != sorted(value["pending_trades"])
    ):
        raise ValueError("close1_account_pending_ids_invalid")
    if any(not isinstance(reason, str) or not reason for reason in value["void_trades"].values()):
        raise ValueError("close1_account_void_trades_invalid")
    if any(not isinstance(item, str) or not HEX64_RE.fullmatch(item) for item in value["trade_evidence"].values()):
        raise ValueError("close1_account_trade_evidence_invalid")
    for item in value["pending_trades"].values():
        if not isinstance(item, dict) or set(item) != {
            "search_start_sweep", "next_search_sweep", "marked_at"
        }:
            raise ValueError("close1_account_pending_invalid")
        if (
            type(item["search_start_sweep"]) is not int
            or not CHECKPOINT_SWEEP < item["search_start_sweep"] <= close_call.LOCK_SWEEP
        ):
            raise ValueError("close1_account_search_start_invalid")
        if (
            type(item["next_search_sweep"]) is not int
            or not item["search_start_sweep"] <= item["next_search_sweep"] <= close_call.LOCK_SWEEP + 1
            or item["next_search_sweep"] <= value["as_of_sweep"]
        ):
            raise ValueError("close1_account_search_cursor_invalid")
        if not isinstance(item["marked_at"], str):
            raise ValueError("close1_account_pending_time_invalid")
    if not isinstance(value["source_evidence"], list) or len(value["source_evidence"]) > close_call.LOCK_SWEEP + 1:
        raise ValueError("close1_account_source_evidence_invalid")
    if value["cash"] is None:
        if value["source_evidence"]:
            raise ValueError("close1_account_unknown_evidence_invalid")
    else:
        checkpoint = {
            "kind": "trusted_mint_checkpoint",
            "sweep": CHECKPOINT_SWEEP,
            "cash": "10000",
            "position": "0",
        }
        if not value["source_evidence"] or value["source_evidence"][0] != checkpoint:
            raise ValueError("close1_account_checkpoint_evidence_invalid")
        for evidence in value["source_evidence"][1:]:
            if not isinstance(evidence, dict) or set(evidence) != {
                "kind", "sweep", "file_sha256", "trade_ids"
            }:
                raise ValueError("close1_account_archive_evidence_invalid")
            if evidence["kind"] != "official_archive_sweep":
                raise ValueError("close1_account_archive_evidence_invalid")
            if type(evidence["sweep"]) is not int or evidence["sweep"] <= CHECKPOINT_SWEEP:
                raise ValueError("close1_account_archive_evidence_invalid")
            if not isinstance(evidence["file_sha256"], str) or not HEX64_RE.fullmatch(evidence["file_sha256"]):
                raise ValueError("close1_account_archive_evidence_invalid")
            if (
                not isinstance(evidence["trade_ids"], list)
                or any(
                    not isinstance(trade_id, str)
                    or not close_call.TRADE_ID_RE.fullmatch(trade_id)
                    for trade_id in evidence["trade_ids"]
                )
            ):
                raise ValueError("close1_account_archive_evidence_invalid")
    if value["last_reconciled_at"] is not None and not isinstance(value["last_reconciled_at"], str):
        raise ValueError("close1_account_reconciled_time_invalid")
    terminal_ids = set(settled) | set(value["void_trades"])
    if set(settled) & set(value["void_trades"]):
        raise ValueError("close1_account_terminal_overlap")
    if terminal_ids & set(value["pending_trades"]):
        raise ValueError("close1_account_pending_terminal_overlap")
    if set(value["trade_evidence"]) != terminal_ids:
        raise ValueError("close1_account_terminal_evidence_mismatch")
    if value["pending_trades"] and value["status"] not in {
        "own_state_pending", "own_state_unreconciled"
    }:
        raise ValueError("close1_account_pending_status_mismatch")
    if not value["pending_trades"] and value["status"] == "own_state_pending":
        raise ValueError("close1_account_pending_status_mismatch")
    if value["status"] == "flat_confirmed" and terminal_ids:
        raise ValueError("close1_account_flat_status_mismatch")
    if value["status"] == "reconciled" and not terminal_ids:
        raise ValueError("close1_account_reconciled_status_mismatch")
    return value


def load_ledger(*, owner_did: str = OWNER_DID) -> dict:
    path = state_path()
    if not path.exists():
        return checkpoint_ledger(owner_did=owner_did)
    try:
        raw = json.loads(path.read_text("utf-8"))
        return _validate_ledger(raw, owner_did=owner_did)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        return _fail_closed_ledger(owner_did=owner_did, reason="ledger_invalid")


def save_ledger(ledger: dict) -> None:
    _validate_ledger(ledger, owner_did=ledger.get("owner_did", OWNER_DID))
    if ledger["cash"] is None:
        raise ValueError("close1_account_unknown_values_not_persistable")
    observer.atomic_json_write(
        state_path(), ledger, compact=True, mode=0o640 if os.name == "posix" else None
    )


def mark_pending(
    trade_id: str,
    *,
    search_start_sweep: int,
    owner_did: str = OWNER_DID,
    now: str | None = None,
) -> dict:
    """Persist the binding before a write; the sweep is a search anchor, not a settlement claim."""
    if not isinstance(trade_id, str) or not close_call.TRADE_ID_RE.fullmatch(trade_id):
        raise ValueError("close1_account_trade_id_invalid")
    if (
        type(search_start_sweep) is not int
        or not CHECKPOINT_SWEEP < search_start_sweep <= close_call.LOCK_SWEEP
    ):
        raise ValueError("close1_account_search_start_invalid")
    ledger = load_ledger(owner_did=owner_did)
    _validate_ledger(ledger, owner_did=owner_did)
    if ledger["status"] == "own_state_unreconciled":
        raise RuntimeError("close1_own_state_unreconciled")
    if trade_id in ledger["settled_trade_ids"] or trade_id in ledger["void_trades"]:
        raise RuntimeError("close1_trade_already_terminal")
    existing = ledger["pending_trades"].get(trade_id)
    if existing is not None:
        return ledger
    cursor = max(search_start_sweep, ledger["as_of_sweep"] + 1)
    if cursor > close_call.LOCK_SWEEP:
        raise ValueError("close1_account_search_start_after_lock")
    marker = {
        "search_start_sweep": cursor,
        "next_search_sweep": cursor,
        "marked_at": now or _now(),
    }
    ledger["pending_trades"][trade_id] = marker
    ledger["pending_trade_ids"] = sorted(ledger["pending_trades"])
    ledger.update(status="own_state_pending", reason="binding_awaiting_archive")
    save_ledger(ledger)
    return ledger


@dataclass
class _Account:
    """Exact Decimal port of frozen official ``close_call_fold.Account``."""

    cash: Decimal
    lots: list[list[Decimal]]
    fees: Decimal

    @property
    def position(self) -> Decimal:
        return sum((lot[0] for lot in self.lots), Decimal("0"))

    def apply(self, side: int, qty: Decimal, px: Decimal, fee: Decimal) -> None:
        self.cash -= fee
        self.fees += fee
        left = qty
        while left > 0 and self.lots and self.lots[0][0] * side < 0:
            lot_qty, lot_px = self.lots[0]
            size = min(left, abs(lot_qty))
            self.cash += size * px if side < 0 else size * (Decimal("2") * lot_px - px)
            left -= size
            if size == abs(lot_qty):
                self.lots.pop(0)
            else:
                self.lots[0][0] = lot_qty + side * size
        if left > 0:
            self.cash -= left * px
            self.lots.append([Decimal(side) * left, px])


def _account_from_ledger(ledger: dict) -> _Account:
    return _Account(
        cash=_decimal(ledger["cash"], label="cash"),
        lots=[
            [
                _decimal(lot[0], label="lot_qty", nonnegative=False),
                _decimal(lot[1], label="lot_px"),
            ]
            for lot in ledger["lots"]
        ],
        fees=_decimal(ledger["cumulative_fees"], label="fees"),
    )


def _store_account(ledger: dict, account: _Account) -> None:
    ledger["cash"] = _text(account.cash)
    ledger["lots"] = [[_text(qty), _text(px)] for qty, px in account.lots]
    ledger["position"] = _text(account.position)
    ledger["cumulative_fees"] = _text(account.fees)


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _entry(entry: object) -> tuple[int, str, str, int | None]:
    if not isinstance(entry, dict):
        raise ValueError("close1_archive_entry_invalid")
    sweep = entry.get("n")
    file_hash = entry.get("file")
    path = entry.get("path")
    status = entry.get("status")
    expected_bytes = entry.get("bytes")
    if type(sweep) is not int or sweep < 0:
        raise ValueError("close1_archive_sweep_invalid")
    if not isinstance(file_hash, str) or not HEX64_RE.fullmatch(file_hash):
        raise ValueError("close1_archive_file_hash_invalid")
    if status == "full":
        match = ARCHIVE_PATH_RE.fullmatch(path or "")
        if match is None or match.group(1) != file_hash:
            raise ValueError("close1_archive_path_invalid")
    elif status == "redacted":
        if not isinstance(path, str) or not path.startswith("redacted/"):
            raise ValueError("close1_archive_redacted_path_invalid")
    else:
        raise ValueError("close1_archive_status_invalid")
    if expected_bytes is not None and (type(expected_bytes) is not int or expected_bytes < 0):
        raise ValueError("close1_archive_bytes_invalid")
    return sweep, file_hash, status, expected_bytes


def _trade_terms(value: object) -> tuple[str, str, str, Decimal, Decimal, str]:
    if not isinstance(value, dict):
        raise ValueError("close1_archive_trade_input_missing")
    trade_id = value.get("id")
    if not isinstance(trade_id, str) or not close_call.TRADE_ID_RE.fullmatch(trade_id):
        raise ValueError("close1_archive_trade_id_invalid")
    maker = close_call._did(value.get("maker"), label="maker")
    countersigner = close_call._did(value.get("countersigner"), label="countersigner")
    side = value.get("side")
    if side not in {"buy", "sell"}:
        raise ValueError("close1_archive_side_invalid")
    qty = close_call._amount(value.get("qty"), label="archive_qty")
    px = close_call._amount(value.get("px"), label="archive_price")
    return trade_id, maker, side, qty, px, countersigner


def _record_payload(entry: dict, raw: bytes) -> tuple[int, dict, dict, str]:
    sweep, file_hash, status, expected_bytes = _entry(entry)
    if sweep > close_call.LOCK_SWEEP:
        raise ValueError("close1_archive_sweep_after_lock")
    if status != "full":
        raise ValueError("close1_archive_relevant_sweep_redacted")
    if len(raw) > SWEEP_MAX_BYTES or (expected_bytes is not None and len(raw) != expected_bytes):
        raise ValueError("close1_archive_size_mismatch")
    if hashlib.sha256(raw).hexdigest() != file_hash:
        raise ValueError("close1_archive_hash_mismatch")
    try:
        record = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("close1_archive_json_invalid") from error
    if not isinstance(record, dict) or set(record) != {"input", "output"}:
        raise ValueError("close1_archive_record_shape_invalid")
    input_value, output_value = record["input"], record["output"]
    if not isinstance(input_value, dict) or not isinstance(output_value, dict):
        raise ValueError("close1_archive_record_shape_invalid")
    if input_value.get("t") != "sweep" or input_value.get("n") != sweep:
        raise ValueError("close1_archive_input_binding_mismatch")
    if output_value.get("sweep") != sweep:
        raise ValueError("close1_archive_output_binding_mismatch")
    if output_value.get("reference") != input_value.get("ref") or output_value.get("close") != input_value.get("close"):
        raise ValueError("close1_archive_output_binding_mismatch")
    return sweep, input_value, output_value, file_hash


def reconcile_records(
    ledger: dict,
    *,
    archive_tip_sweep: int,
    records: list[tuple[dict, bytes]],
    reconciled_at: str | None = None,
) -> dict:
    """Fold verified records atomically; an error preserves balances and fails closed."""
    owner = ledger.get("owner_did", OWNER_DID)
    _validate_ledger(ledger, owner_did=owner)
    if ledger["cash"] is None:
        return ledger
    if type(archive_tip_sweep) is not int or archive_tip_sweep < CHECKPOINT_SWEEP:
        raise ValueError("close1_archive_tip_invalid")
    original = deepcopy(ledger)
    working = deepcopy(ledger)
    account = _account_from_ledger(working)
    try:
        seen_sweeps: set[int] = set()
        for entry, raw in sorted(records, key=lambda item: item[0].get("n", -1)):
            sweep, input_value, output_value, file_hash = _record_payload(entry, raw)
            if sweep in seen_sweeps:
                raise ValueError("close1_archive_duplicate_sweep")
            seen_sweeps.add(sweep)
            inputs, outputs = input_value.get("trades"), output_value.get("trades")
            if not isinstance(inputs, list) or not isinstance(outputs, list) or len(inputs) != len(outputs):
                raise ValueError("close1_archive_trade_alignment_invalid")
            searching_ids = {
                trade_id
                for trade_id, marker in working["pending_trades"].items()
                if marker["next_search_sweep"] == sweep
            }
            if working["pending_trades"]:
                next_cursor = min(
                    marker["next_search_sweep"]
                    for marker in working["pending_trades"].values()
                )
                if sweep != next_cursor:
                    raise ValueError("close1_archive_search_cursor_gap")
            relevant_ids: list[str] = []
            seen_relevant_ids: set[str] = set()
            for terms, outcome in zip(inputs, outputs, strict=True):
                if not isinstance(terms, dict):
                    # A redacted item is only relevant if the exact pending ID
                    # cannot be proven at its expected sweep; checked below.
                    continue
                trade_id = terms.get("id")
                pending = working["pending_trades"].get(trade_id)
                maker = terms.get("maker")
                countersigner = terms.get("countersigner")
                relevant = maker == owner or countersigner == owner or pending is not None
                if not relevant:
                    continue
                parsed_id, maker, side_name, qty, px, countersigner = _trade_terms(terms)
                if parsed_id in seen_relevant_ids:
                    raise ValueError("close1_archive_duplicate_trade_id")
                seen_relevant_ids.add(parsed_id)
                if pending is not None:
                    if sweep < pending["search_start_sweep"]:
                        raise ValueError("close1_pending_trade_before_search_start")
                if owner not in {maker, countersigner}:
                    raise ValueError("close1_pending_owner_binding_mismatch")
                if not isinstance(outcome, dict) or outcome.get("id") != parsed_id:
                    raise ValueError("close1_archive_trade_outcome_missing")
                result = outcome.get("outcome")
                evidence_hash = _canonical_hash(
                    {
                        "sweep": sweep,
                        "file_sha256": file_hash,
                        "input": terms,
                        "output": outcome,
                    }
                )
                previous_hash = working["trade_evidence"].get(parsed_id)
                if previous_hash is not None:
                    if previous_hash != evidence_hash:
                        raise ValueError("close1_archive_trade_evidence_conflict")
                    working["pending_trades"].pop(parsed_id, None)
                    relevant_ids.append(parsed_id)
                    continue
                if sweep <= working["as_of_sweep"]:
                    raise ValueError("close1_archive_historical_owner_trade_untracked")
                if result == "void":
                    reason = outcome.get("reason")
                    if not isinstance(reason, str) or not reason:
                        raise ValueError("close1_archive_void_reason_missing")
                    working["void_trades"][parsed_id] = reason[:200]
                elif result == "settled":
                    maker_fee = _decimal(outcome.get("maker_fee"), label="maker_fee")
                    taker_fee = _decimal(outcome.get("taker_fee"), label="taker_fee")
                    side = 1 if side_name == "buy" else -1
                    if maker == owner and countersigner == owner:
                        # Frozen fold special-case: both account roles pay their
                        # exact fees without creating a position.
                        account.cash -= maker_fee + taker_fee
                        account.fees += maker_fee + taker_fee
                    elif maker == owner:
                        account.apply(side, qty, px, maker_fee)
                    else:
                        account.apply(-side, qty, px, taker_fee)
                    working["settled_trade_ids"].append(parsed_id)
                else:
                    raise ValueError("close1_archive_trade_outcome_invalid")
                working["trade_evidence"][parsed_id] = evidence_hash
                working["pending_trades"].pop(parsed_id, None)
                relevant_ids.append(parsed_id)

            for trade_id in searching_ids:
                marker = working["pending_trades"].get(trade_id)
                if marker is not None:
                    marker["next_search_sweep"] = sweep + 1
            if searching_ids or relevant_ids:
                if not any(
                    evidence.get("sweep") == sweep and evidence.get("file_sha256") == file_hash
                    for evidence in working["source_evidence"]
                    if isinstance(evidence, dict)
                ):
                    working["source_evidence"].append(
                        {
                            "kind": "official_archive_sweep",
                            "sweep": sweep,
                            "file_sha256": file_hash,
                            "trade_ids": sorted(set(relevant_ids)),
                        }
                    )
                working["as_of_sweep"] = max(working["as_of_sweep"], sweep)
        _store_account(working, account)
        working["pending_trade_ids"] = sorted(working["pending_trades"])
        working["archive_tip_sweep"] = max(working["archive_tip_sweep"], archive_tip_sweep)
        working["last_reconciled_at"] = reconciled_at or _now()
        if working["pending_trades"]:
            working.update(status="own_state_pending", reason="binding_awaiting_archive")
        elif working["settled_trade_ids"] or working["void_trades"]:
            working.update(status="reconciled", reason="official_archive_reconciled")
        else:
            working.update(status="flat_confirmed", reason="trusted_mint_checkpoint")
        return _validate_ledger(working, owner_did=owner)
    except (ValueError, TypeError, KeyError) as error:
        original["archive_tip_sweep"] = max(original["archive_tip_sweep"], archive_tip_sweep)
        reason = str(error)
        if not reason.startswith("close1_"):
            reason = "close1_archive_record_invalid"
        original.update(status="own_state_unreconciled", reason=reason)
        return _validate_ledger(original, owner_did=owner)


def _read_bounded(url: str, limit: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "technocore-safe-agent/close1-read-only"})
    with urllib.request.urlopen(request, timeout=20) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError("close1_archive_response_too_large")
    return data


def _index(raw: bytes) -> tuple[int, dict[int, dict]]:
    if len(raw) > INDEX_MAX_BYTES:
        raise ValueError("close1_archive_index_too_large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("close1_archive_index_invalid") from error
    if not isinstance(value, dict) or value.get("contest") != close_call.CONTEST_ID:
        raise ValueError("close1_archive_index_invalid")
    rows = value.get("sweeps")
    if not isinstance(rows, list):
        raise ValueError("close1_archive_index_invalid")
    entries: dict[int, dict] = {}
    for row in rows:
        sweep, _, _, _ = _entry(row)
        if sweep in entries:
            raise ValueError("close1_archive_index_duplicate_sweep")
        entries[sweep] = row
    return max(entries, default=CHECKPOINT_SWEEP), entries


def reconcile_pending(
    *,
    owner_did: str = OWNER_DID,
    fetcher: Callable[[str, int], bytes] | None = None,
    reconciled_at: str | None = None,
) -> dict:
    """Search fixed official archive sweeps incrementally for pending trade IDs."""
    ledger = load_ledger(owner_did=owner_did)
    if ledger["cash"] is None or not ledger["pending_trades"]:
        return ledger
    read = fetcher or _read_bounded
    working = ledger
    try:
        tip, entries = _index(read(INDEX_URL, INDEX_MAX_BYTES))
        processed = 0
        while working["pending_trades"] and processed < MAX_PENDING_SWEEPS_PER_RUN:
            sweep = min(
                marker["next_search_sweep"]
                for marker in working["pending_trades"].values()
            )
            if sweep > close_call.LOCK_SWEEP:
                working.update(
                    status="own_state_unreconciled",
                    reason="close1_archive_pending_trade_not_found",
                )
                save_ledger(working)
                return working
            if tip < sweep:
                working["archive_tip_sweep"] = max(working["archive_tip_sweep"], tip)
                working.update(status="own_state_pending", reason="archive_lag")
                save_ledger(working)
                return working
            entry = entries.get(sweep)
            if entry is None:
                raise ValueError("close1_archive_pending_sweep_missing")
            _, _, status, _ = _entry(entry)
            if status != "full":
                raise ValueError("close1_archive_relevant_sweep_redacted")
            raw = read(ARCHIVE_BASE + entry["path"], SWEEP_MAX_BYTES)
            working = reconcile_records(
                working,
                archive_tip_sweep=tip,
                records=[(entry, raw)],
                reconciled_at=reconciled_at,
            )
            save_ledger(working)
            if working["status"] == "own_state_unreconciled":
                return working
            processed += 1

        if working["pending_trades"]:
            next_sweep = min(
                marker["next_search_sweep"]
                for marker in working["pending_trades"].values()
            )
            reason = "archive_lag" if tip < next_sweep else "bounded_reconciliation_remaining"
            working.update(status="own_state_pending", reason=reason)
        save_ledger(working)
        return working
    except (OSError, ValueError, RuntimeError) as error:
        reason = str(error)
        if isinstance(error, OSError) or not reason.startswith("close1_"):
            reason = "close1_archive_read_failed"
        working.update(status="own_state_unreconciled", reason=reason)
        save_ledger(working)
        return working


def scanner_account(ledger: dict) -> tuple[str, str]:
    """Return exact scanner inputs only for a fully usable owner state."""
    _validate_ledger(ledger, owner_did=ledger.get("owner_did", OWNER_DID))
    if ledger["status"] not in {"flat_confirmed", "reconciled"}:
        raise RuntimeError("close1_own_state_unreconciled")
    cash = _decimal(ledger["cash"], label="cash")
    position = _decimal(ledger["position"], label="position", nonnegative=False)
    return _text(cash), _text(position)
