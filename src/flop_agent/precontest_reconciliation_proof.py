"""Machine-generated, non-binding proof for reconciliation fail-closed behavior.

This module exercises the existing Close Call reconciliation code entirely in
memory. It never signs, posts, starts services, changes external state, or
accesses signer/Vault material.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import re
import sys
import textwrap
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

from . import airdrop_challenge
from . import close1_account_reconciliation as account
from . import close1_redacted_recovery as redacted
from . import precontest_readiness

SCHEMA_VERSION = 1
HEX64_RE = re.compile(r"[0-9a-f]{64}")
SWEEP = account.CHECKPOINT_SWEEP + 1
OWNER = account.OWNER_DID
OTHER = "did:key:z6MktVwQqJbSVfLfDUHRVkJShspL49A2d6EbhzKvXV9zPLF5"


class ReconciliationProofError(RuntimeError):
    """Fail-closed reconciliation proof error."""


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _source_sha(function: object) -> str:
    source = textwrap.dedent(inspect.getsource(function))
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _parse_time(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise ReconciliationProofError(f"precontest_reconcile_{label}_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReconciliationProofError(f"precontest_reconcile_{label}_invalid") from error
    if parsed.tzinfo is None:
        raise ReconciliationProofError(f"precontest_reconcile_{label}_invalid")
    return parsed.astimezone(UTC)


def proof_path(challenge_id: str) -> Path:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    return precontest_readiness._root() / challenge_id / "precontest-reconciliation-proof.json"


def _pending(trade_id: str) -> dict:
    ledger = account.checkpoint_ledger()
    ledger["pending_trades"] = {
        trade_id: {
            "search_start_sweep": SWEEP,
            "next_search_sweep": SWEEP,
            "marked_at": "2026-10-05T00:00:00+00:00",
        }
    }
    ledger["pending_trade_ids"] = [trade_id]
    ledger.update(status="own_state_pending", reason="binding_awaiting_archive")
    account._validate_ledger(ledger)
    return ledger


def _record(*, trade_id: str, outcome: dict) -> tuple[dict, bytes]:
    terms = {
        "id": trade_id,
        "maker": OTHER,
        "countersigner": OWNER,
        "side": "buy",
        "qty": "1",
        "px": "100",
    }
    record = {
        "input": {
            "t": "sweep",
            "n": SWEEP,
            "ref": "100",
            "close": "100",
            "trades": [terms],
        },
        "output": {
            "sweep": SWEEP,
            "reference": "100",
            "close": "100",
            "trades": [{"id": trade_id, **outcome}],
        },
    }
    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    file_hash = hashlib.sha256(raw).hexdigest()
    entry = {
        "n": SWEEP,
        "file": file_hash,
        "path": f"sweeps/{file_hash}.json",
        "status": "full",
        "bytes": len(raw),
    }
    return entry, raw


def _settled_probe() -> dict:
    trade_id = "proof-settled"
    entry, raw = _record(
        trade_id=trade_id,
        outcome={"outcome": "settled", "maker_fee": "1", "taker_fee": "1"},
    )
    result = account.reconcile_records(
        _pending(trade_id),
        archive_tip_sweep=SWEEP,
        records=[(entry, raw)],
        reconciled_at="2026-10-05T00:00:01+00:00",
    )
    if result["status"] != "reconciled":
        raise ReconciliationProofError("precontest_reconcile_settled_status_invalid")
    if result["pending_trade_ids"] or trade_id not in result["settled_trade_ids"]:
        raise ReconciliationProofError("precontest_reconcile_settled_terminal_invalid")
    if result["position"] != "-1" or result["cash"] != "9899":
        raise ReconciliationProofError("precontest_reconcile_settled_balance_invalid")
    return {"status": "PASS", "terminal": "settled", "pending": False}


def _void_probe() -> dict:
    trade_id = "proof-void"
    entry, raw = _record(
        trade_id=trade_id,
        outcome={"outcome": "void", "reason": "proof_void"},
    )
    result = account.reconcile_records(
        _pending(trade_id),
        archive_tip_sweep=SWEEP,
        records=[(entry, raw)],
        reconciled_at="2026-10-05T00:00:01+00:00",
    )
    if result["status"] != "reconciled":
        raise ReconciliationProofError("precontest_reconcile_void_status_invalid")
    if result["pending_trade_ids"] or result["void_trades"].get(trade_id) != "proof_void":
        raise ReconciliationProofError("precontest_reconcile_void_terminal_invalid")
    if result["cash"] != "10000" or result["position"] != "0":
        raise ReconciliationProofError("precontest_reconcile_void_balance_invalid")
    return {"status": "PASS", "terminal": "void", "pending": False}


def _ambiguous_probe() -> dict:
    trade_id = "proof-ambiguous"
    entry, raw = _record(
        trade_id=trade_id,
        outcome={"outcome": "unknown-proof-result"},
    )
    result = account.reconcile_records(
        _pending(trade_id),
        archive_tip_sweep=SWEEP,
        records=[(entry, raw)],
        reconciled_at="2026-10-05T00:00:01+00:00",
    )
    if result["status"] != "own_state_unreconciled":
        raise ReconciliationProofError("precontest_reconcile_ambiguous_not_fail_closed")
    if trade_id not in result["pending_trade_ids"]:
        raise ReconciliationProofError("precontest_reconcile_ambiguous_pending_lost")
    if trade_id in result["settled_trade_ids"] or trade_id in result["void_trades"]:
        raise ReconciliationProofError("precontest_reconcile_ambiguous_false_terminal")
    if result["cash"] != "10000" or result["position"] != "0":
        raise ReconciliationProofError("precontest_reconcile_ambiguous_balance_changed")
    return {"status": "PASS", "terminal": None, "pending": True, "fail_closed": True}


def _redacted_probe() -> dict:
    trade_id = "proof-redacted"
    ledger = _pending(trade_id)
    terms = {
        "id": trade_id,
        "maker": OTHER,
        "countersigner": OWNER,
        "side": "buy",
        "qty": "1",
        "px": "100",
    }
    outcome = {"id": trade_id, "outcome": "settled", "maker_fee": "1", "taker_fee": "1"}
    record = {
        "input": {"t": "sweep", "n": SWEEP, "ref": "100", "close": "100", "trades": [terms]},
        "output": {"sweep": SWEEP, "reference": "100", "close": "100", "trades": [outcome]},
    }
    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    redacted_hash = hashlib.sha256(raw).hexdigest()
    archive_file = "a" * 64
    entry = {
        "n": SWEEP,
        "file": archive_file,
        "path": f"redacted/{archive_file}.json",
        "status": "redacted",
        "bytes": len(raw),
        "sha256": redacted_hash,
    }
    index = {"contest": account.close_call.CONTEST_ID, "sweeps": [entry]}
    index_raw = json.dumps(index, sort_keys=True, separators=(",", ":")).encode("utf-8")

    saved: list[dict] = []
    original_load = account.load_ledger
    original_save = account.save_ledger
    try:
        account.load_ledger = lambda owner_did=OWNER: deepcopy(ledger)
        account.save_ledger = lambda value: saved.append(deepcopy(value))

        def fetcher(url: str, limit: int) -> bytes:
            if url == account.INDEX_URL:
                return index_raw
            if url == account.ARCHIVE_BASE + entry["path"]:
                return raw
            raise ReconciliationProofError("precontest_reconcile_unexpected_fetch")

        result = redacted.recover_pending_redacted(
            owner_did=OWNER,
            fetcher=fetcher,
            reconciled_at="2026-10-05T00:00:01+00:00",
        )
    finally:
        account.load_ledger = original_load
        account.save_ledger = original_save

    if result["status"] != "reconciled":
        raise ReconciliationProofError("precontest_reconcile_redacted_status_invalid")
    if result["pending_trade_ids"] or trade_id not in result["settled_trade_ids"]:
        raise ReconciliationProofError("precontest_reconcile_redacted_terminal_invalid")
    if result["position"] != "-1" or result["cash"] != "9899":
        raise ReconciliationProofError("precontest_reconcile_redacted_balance_invalid")
    if not saved or saved[-1] != result:
        raise ReconciliationProofError("precontest_reconcile_redacted_save_invalid")
    return {"status": "PASS", "terminal": "settled", "pending": False, "verified_hash": redacted_hash}


def build_proof(challenge_id: str, *, now: datetime | None = None) -> dict:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_reconcile_now_timezone_required")
    current = current.astimezone(UTC)
    cases = {
        "settled": _settled_probe(),
        "void": _void_probe(),
        "ambiguous": _ambiguous_probe(),
        "redacted": _redacted_probe(),
    }
    value = {
        "schema_version": SCHEMA_VERSION,
        "challenge_id": challenge_id,
        "status": "PASS",
        "non_binding": True,
        "generated_at": current.isoformat(),
        "cases": cases,
        "reconciliation_cases_rehearsed": sorted(cases),
        "reconcile_records_sha256": _source_sha(account.reconcile_records),
        "redacted_recovery_sha256": _source_sha(redacted.recover_pending_redacted),
    }
    value["proof_sha256"] = _sha(value)
    return value


def validate_proof(value: object, *, challenge_id: str, now: datetime) -> dict:
    if not isinstance(value, dict):
        raise ReconciliationProofError("precontest_reconcile_proof_invalid")
    required = {
        "schema_version", "challenge_id", "status", "non_binding", "generated_at",
        "cases", "reconciliation_cases_rehearsed", "reconcile_records_sha256",
        "redacted_recovery_sha256", "proof_sha256",
    }
    if set(value) != required or value.get("schema_version") != SCHEMA_VERSION:
        raise ReconciliationProofError("precontest_reconcile_proof_schema_invalid")
    digest = value.get("proof_sha256")
    if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
        raise ReconciliationProofError("precontest_reconcile_proof_digest_invalid")
    unsigned = dict(value)
    unsigned.pop("proof_sha256")
    if _sha(unsigned) != digest:
        raise ReconciliationProofError("precontest_reconcile_proof_integrity_invalid")
    if value.get("challenge_id") != airdrop_challenge.validate_challenge_id(challenge_id):
        raise ReconciliationProofError("precontest_reconcile_challenge_mismatch")
    if value.get("status") != "PASS" or value.get("non_binding") is not True:
        raise ReconciliationProofError("precontest_reconcile_proof_not_passed")
    generated = _parse_time(value.get("generated_at"), label="generated_at")
    age = now.astimezone(UTC) - generated
    if age > precontest_readiness.MAX_EVIDENCE_AGE or age < -precontest_readiness.MAX_CLOCK_SKEW:
        raise ReconciliationProofError("precontest_reconcile_proof_stale")
    required_cases = sorted(precontest_readiness.REQUIRED_RECONCILIATION_CASES)
    if value.get("reconciliation_cases_rehearsed") != required_cases:
        raise ReconciliationProofError("precontest_reconcile_cases_incomplete")
    cases = value.get("cases")
    if not isinstance(cases, dict) or sorted(cases) != required_cases:
        raise ReconciliationProofError("precontest_reconcile_cases_invalid")
    if any(not isinstance(row, dict) or row.get("status") != "PASS" for row in cases.values()):
        raise ReconciliationProofError("precontest_reconcile_case_failed")
    if cases["ambiguous"].get("fail_closed") is not True or cases["ambiguous"].get("pending") is not True:
        raise ReconciliationProofError("precontest_reconcile_ambiguous_invalid")
    if value.get("reconcile_records_sha256") != _source_sha(account.reconcile_records):
        raise ReconciliationProofError("precontest_reconcile_source_changed")
    if value.get("redacted_recovery_sha256") != _source_sha(redacted.recover_pending_redacted):
        raise ReconciliationProofError("precontest_reconcile_redacted_source_changed")
    return dict(value)


def save_proof(challenge_id: str, *, now: datetime | None = None) -> dict:
    value = build_proof(challenge_id, now=now)
    precontest_readiness._atomic_write(proof_path(challenge_id), value)
    return value


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"status": "blocked", "reason": "challenge_id_required"}))
        return 2
    try:
        result = save_proof(sys.argv[1])
    except Exception as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
