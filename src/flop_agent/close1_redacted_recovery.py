"""Recover exact Close Call pending trades from verified redacted archive records.

This module never signs or posts. It exists for the narrow case where index.json
marks a pending sweep ``redacted`` because some private-room trades were present,
while this owner's locally pending public trade remains visible in the redacted
record. Recovery is fail-closed: every pending ID for the searched sweep must be
visible, owner-bound, aligned with an exact outcome, and the redacted bytes must
match the archive index SHA-256 before any ledger mutation is saved.
"""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime
from typing import Callable

from . import close1_account_reconciliation as account


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _fail(ledger: dict, *, tip: int, reason: str) -> dict:
    failed = deepcopy(ledger)
    failed["archive_tip_sweep"] = max(failed["archive_tip_sweep"], tip)
    failed.update(status="own_state_unreconciled", reason=reason)
    account.save_ledger(failed)
    return failed


def _redacted_payload(entry: dict, raw: bytes) -> tuple[int, dict, dict, str]:
    sweep, file_hash, status, expected_bytes = account._entry(entry)
    if status != "redacted":
        raise ValueError("close1_redacted_recovery_entry_not_redacted")
    if sweep > account.close_call.LOCK_SWEEP:
        raise ValueError("close1_archive_sweep_after_lock")
    redacted_hash = entry.get("sha256")
    if not isinstance(redacted_hash, str) or not account.HEX64_RE.fullmatch(redacted_hash):
        raise ValueError("close1_redacted_archive_hash_invalid")
    if len(raw) > account.SWEEP_MAX_BYTES:
        raise ValueError("close1_archive_response_too_large")
    if expected_bytes is not None and len(raw) != expected_bytes:
        raise ValueError("close1_archive_size_mismatch")
    if hashlib.sha256(raw).hexdigest() != redacted_hash:
        raise ValueError("close1_redacted_archive_hash_mismatch")
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
    if (
        output_value.get("reference") != input_value.get("ref")
        or output_value.get("close") != input_value.get("close")
    ):
        raise ValueError("close1_archive_output_binding_mismatch")
    return sweep, input_value, output_value, redacted_hash


def recover_pending_redacted(
    *,
    owner_did: str = account.OWNER_DID,
    fetcher: Callable[[str, int], bytes] | None = None,
    reconciled_at: str | None = None,
) -> dict:
    ledger = account.load_ledger(owner_did=owner_did)
    account._validate_ledger(ledger, owner_did=owner_did)
    if not ledger["pending_trades"]:
        return ledger
    if ledger["cash"] is None:
        return ledger

    read = fetcher or account._read_bounded
    try:
        tip, entries = account._index(read(account.INDEX_URL, account.INDEX_MAX_BYTES))
        sweep = min(
            marker["next_search_sweep"] for marker in ledger["pending_trades"].values()
        )
        if tip < sweep:
            return _fail(ledger, tip=tip, reason="archive_lag")
        entry = entries.get(sweep)
        if entry is None:
            return _fail(ledger, tip=tip, reason="close1_archive_pending_sweep_missing")
        _, _, status, _ = account._entry(entry)
        if status != "redacted":
            return account.reconcile_pending(
                owner_did=owner_did,
                fetcher=fetcher,
                reconciled_at=reconciled_at,
            )
        raw = read(account.ARCHIVE_BASE + entry["path"], account.SWEEP_MAX_BYTES)
        sweep, input_value, output_value, redacted_hash = _redacted_payload(entry, raw)
        inputs, outputs = input_value.get("trades"), output_value.get("trades")
        if (
            not isinstance(inputs, list)
            or not isinstance(outputs, list)
            or len(inputs) != len(outputs)
        ):
            raise ValueError("close1_archive_trade_alignment_invalid")

        searching_ids = {
            trade_id
            for trade_id, marker in ledger["pending_trades"].items()
            if marker["next_search_sweep"] == sweep
        }
        known_ids = (
            set(ledger["settled_trade_ids"])
            | set(ledger["void_trades"])
            | set(ledger["pending_trades"])
        )
        owner_rows: dict[str, list[tuple[dict, dict]]] = {}
        for terms, outcome in zip(inputs, outputs, strict=True):
            if not isinstance(terms, dict):
                continue
            trade_id = terms.get("id")
            maker = terms.get("maker")
            countersigner = terms.get("countersigner")
            if owner_did not in {maker, countersigner}:
                continue
            if not isinstance(trade_id, str):
                raise ValueError("close1_archive_trade_id_invalid")
            if trade_id not in known_ids:
                raise ValueError("close1_redacted_untracked_owner_trade")
            if not isinstance(outcome, dict) or outcome.get("id") != trade_id:
                raise ValueError("close1_archive_trade_outcome_missing")
            owner_rows.setdefault(trade_id, []).append((terms, outcome))

        missing = searching_ids - set(owner_rows)
        if missing:
            raise ValueError("close1_redacted_pending_trade_not_visible")
        if any(len(owner_rows[trade_id]) != 1 for trade_id in searching_ids):
            raise ValueError("close1_redacted_pending_trade_ambiguous")

        working = deepcopy(ledger)
        acct = account._account_from_ledger(working)
        relevant_ids: list[str] = []
        for trade_id in sorted(searching_ids):
            terms, outcome = owner_rows[trade_id]
            parsed_id, maker, side_name, qty, px, countersigner = account._trade_terms(terms)
            if parsed_id != trade_id:
                raise ValueError("close1_archive_trade_id_invalid")
            pending = working["pending_trades"].get(trade_id)
            if pending is None or sweep < pending["search_start_sweep"]:
                raise ValueError("close1_pending_trade_before_search_start")
            if owner_did not in {maker, countersigner}:
                raise ValueError("close1_pending_owner_binding_mismatch")

            evidence_hash = account._canonical_hash(
                {
                    "sweep": sweep,
                    "archive_file_sha256": entry["file"],
                    "redacted_sha256": redacted_hash,
                    "input": terms,
                    "output": outcome,
                }
            )
            previous_hash = working["trade_evidence"].get(trade_id)
            if previous_hash is not None:
                if previous_hash != evidence_hash:
                    raise ValueError("close1_archive_trade_evidence_conflict")
                working["pending_trades"].pop(trade_id, None)
                relevant_ids.append(trade_id)
                continue

            result = outcome.get("outcome")
            if result == "void":
                reason = outcome.get("reason")
                if not isinstance(reason, str) or not reason:
                    raise ValueError("close1_archive_void_reason_missing")
                working["void_trades"][trade_id] = reason[:200]
            elif result == "settled":
                maker_fee = account._decimal(outcome.get("maker_fee"), label="maker_fee")
                taker_fee = account._decimal(outcome.get("taker_fee"), label="taker_fee")
                side = 1 if side_name == "buy" else -1
                if maker == owner_did and countersigner == owner_did:
                    acct.cash -= maker_fee + taker_fee
                    acct.fees += maker_fee + taker_fee
                elif maker == owner_did:
                    acct.apply(side, qty, px, maker_fee)
                else:
                    acct.apply(-side, qty, px, taker_fee)
                working["settled_trade_ids"].append(trade_id)
            else:
                raise ValueError("close1_archive_trade_outcome_invalid")

            working["trade_evidence"][trade_id] = evidence_hash
            working["pending_trades"].pop(trade_id, None)
            relevant_ids.append(trade_id)

        account._store_account(working, acct)
        working["pending_trade_ids"] = sorted(working["pending_trades"])
        working["archive_tip_sweep"] = max(working["archive_tip_sweep"], tip)
        working["as_of_sweep"] = max(working["as_of_sweep"], sweep)
        working["last_reconciled_at"] = reconciled_at or _now()
        if not any(
            isinstance(row, dict)
            and row.get("sweep") == sweep
            and row.get("file_sha256") == redacted_hash
            for row in working["source_evidence"]
        ):
            working["source_evidence"].append(
                {
                    "kind": "official_archive_sweep",
                    "sweep": sweep,
                    "file_sha256": redacted_hash,
                    "trade_ids": sorted(relevant_ids),
                }
            )
        if working["pending_trades"]:
            working.update(status="own_state_pending", reason="binding_awaiting_archive")
        else:
            working.update(status="reconciled", reason="official_redacted_archive_reconciled")
        account._validate_ledger(working, owner_did=owner_did)
        account.save_ledger(working)
        return working
    except (OSError, ValueError, RuntimeError, TypeError, KeyError) as error:
        reason = str(error)
        if isinstance(error, OSError) or not reason.startswith("close1_"):
            detail = str(error).replace(" ", "_").replace("'", "")[:120]
            reason = f"close1_redacted_archive_read_failed_{type(error).__name__}_{detail}"
        return _fail(
            ledger,
            tip=locals().get("tip", ledger["archive_tip_sweep"]),
            reason=reason,
        )


def main() -> int:
    result = recover_pending_redacted()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] in {"flat_confirmed", "reconciled"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
