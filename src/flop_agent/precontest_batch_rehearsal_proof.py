"""Machine-generated, non-binding batch execution rehearsal proof.

The proof exercises existing batch aggregate/preflight logic entirely in memory.
It never signs, writes attempt fences, marks pending state, posts, starts
services, or accesses signer/Vault material.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import re
import sys
import textwrap
import time
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from . import airdrop_challenge
from . import close1_batch_trade as batch
from . import precontest_readiness

SCHEMA_VERSION = 1
HEX64_RE = re.compile(r"[0-9a-f]{64}")
CASH = Decimal("10000")
ANCHOR = 500


class BatchRehearsalProofError(RuntimeError):
    """Fail-closed batch rehearsal proof error."""


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _source_sha(function: object) -> str:
    source = textwrap.dedent(inspect.getsource(function))
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _parse_time(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise BatchRehearsalProofError(f"precontest_batch_{label}_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise BatchRehearsalProofError(f"precontest_batch_{label}_invalid") from error
    if parsed.tzinfo is None:
        raise BatchRehearsalProofError(f"precontest_batch_{label}_invalid")
    return parsed.astimezone(UTC)


def proof_path(challenge_id: str) -> Path:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    return precontest_readiness._root() / challenge_id / "precontest-batch-rehearsal-proof.json"


def _leg(trade_id: str, maker: str, *, qty: str = "1", px: str = "100") -> dict:
    return {
        "offer_room": "close1-offers",
        "offer_seq": 1,
        "trade_id": trade_id,
        "maker": maker,
        "maker_side": "sell",
        "taker_side": "buy",
        "qty": qty,
        "px": px,
        "until": 501,
        "maker_sig": "proof-only-not-verified",
    }


def _approval(*legs: dict) -> dict:
    return {
        "schema_version": 1,
        "owner_did": batch.OWNER_DID,
        "legs": list(legs),
        "approved_at": "2026-10-05T00:00:00+00:00",
    }


def _order_probe() -> dict:
    source = textwrap.dedent(inspect.getsource(batch._run_locked))
    tokens = [
        "_preflight_all(",
        "single._sign(",
        "_write_fence(",
        "_post_one(",
    ]
    positions = [source.find(token) for token in tokens]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise BatchRehearsalProofError("precontest_batch_order_invalid")
    return {
        "preflight_before_sign": True,
        "sign_before_fence": True,
        "fence_before_post": True,
    }


def _dynamic_probes() -> tuple[dict, int]:
    maker_a = "did:key:z6MktVwQqJbSVfLfDUHRVkJShspL49A2d6EbhzKvXV9zPLF5"
    maker_b = "did:key:z6MkrPbexuJUmQ6hBt1aajQRyP6WKdveNcY6hLVZ8PMbZpix"
    good = _approval(_leg("proof-batch-a", maker_a), _leg("proof-batch-b", maker_b))
    calls: list[str] = []
    original = batch._preflight_leg
    started = time.monotonic_ns()
    try:
        def same_anchor(leg, approved_at, cash, position_text):
            calls.append(leg["trade_id"])
            return batch._terms(leg), ANCHOR

        batch._preflight_leg = same_anchor
        terms, anchor = batch._preflight_all(good, CASH, "0")
        if anchor != ANCHOR or len(terms) != 2 or calls != ["proof-batch-a", "proof-batch-b"]:
            raise BatchRehearsalProofError("precontest_batch_good_path_invalid")

        calls.clear()
        over_budget = _approval(
            _leg("proof-over-a", maker_a, qty="60", px="100"),
            _leg("proof-over-b", maker_b, qty="60", px="100"),
        )
        try:
            batch._preflight_all(over_budget, CASH, "0")
        except batch.BatchTradeError as error:
            if str(error) != "aggregate_insufficient_cash":
                raise BatchRehearsalProofError("precontest_batch_over_budget_reason_invalid") from error
        else:
            raise BatchRehearsalProofError("precontest_batch_over_budget_not_rejected")
        if calls:
            raise BatchRehearsalProofError("precontest_batch_over_budget_reached_leg_preflight")

        def mixed_anchor(leg, approved_at, cash, position_text):
            anchor_value = ANCHOR if leg["trade_id"].endswith("a") else ANCHOR + 1
            return batch._terms(leg), anchor_value

        batch._preflight_leg = mixed_anchor
        try:
            batch._preflight_all(good, CASH, "0")
        except batch.BatchTradeError as error:
            if str(error) != "batch_sweep_changed":
                raise BatchRehearsalProofError("precontest_batch_mixed_anchor_reason_invalid") from error
        else:
            raise BatchRehearsalProofError("precontest_batch_mixed_anchor_not_rejected")
    finally:
        batch._preflight_leg = original
    elapsed_ms = (time.monotonic_ns() - started + 999_999) // 1_000_000
    if elapsed_ms > precontest_readiness.MAX_CAPTURE_TO_EXECUTOR_MS:
        raise BatchRehearsalProofError("precontest_batch_latency_failed")
    return {
        "two_leg_same_sweep_preflight": True,
        "aggregate_over_budget_rejected": True,
        "mixed_sweep_rejected": True,
        "sign_called": False,
        "fence_written": False,
        "pending_marked": False,
        "post_attempted": False,
    }, int(elapsed_ms)


def build_proof(challenge_id: str, *, now: datetime | None = None) -> dict:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_batch_now_timezone_required")
    current = current.astimezone(UTC)
    probes, elapsed_ms = _dynamic_probes()
    order = _order_probe()
    value = {
        "schema_version": SCHEMA_VERSION,
        "challenge_id": challenge_id,
        "status": "PASS",
        "non_binding": True,
        "generated_at": current.isoformat(),
        "execution_mode": "batch",
        "batch_rehearsal_ms": elapsed_ms,
        "target_capture_to_executor_ms": precontest_readiness.MAX_CAPTURE_TO_EXECUTOR_MS,
        "target_met": elapsed_ms <= precontest_readiness.MAX_CAPTURE_TO_EXECUTOR_MS,
        "probes": probes,
        "order": order,
        "aggregate_required_sha256": _source_sha(batch._aggregate_required),
        "preflight_all_sha256": _source_sha(batch._preflight_all),
        "run_locked_sha256": _source_sha(batch._run_locked),
    }
    value["proof_sha256"] = _sha(value)
    return value


def validate_proof(value: object, *, challenge_id: str, now: datetime) -> dict:
    if not isinstance(value, dict):
        raise BatchRehearsalProofError("precontest_batch_proof_invalid")
    required = {
        "schema_version", "challenge_id", "status", "non_binding", "generated_at",
        "execution_mode", "batch_rehearsal_ms", "target_capture_to_executor_ms",
        "target_met", "probes", "order", "aggregate_required_sha256",
        "preflight_all_sha256", "run_locked_sha256", "proof_sha256",
    }
    if set(value) != required or value.get("schema_version") != SCHEMA_VERSION:
        raise BatchRehearsalProofError("precontest_batch_proof_schema_invalid")
    digest = value.get("proof_sha256")
    if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
        raise BatchRehearsalProofError("precontest_batch_proof_digest_invalid")
    unsigned = dict(value)
    unsigned.pop("proof_sha256")
    if _sha(unsigned) != digest:
        raise BatchRehearsalProofError("precontest_batch_proof_integrity_invalid")
    if value.get("challenge_id") != airdrop_challenge.validate_challenge_id(challenge_id):
        raise BatchRehearsalProofError("precontest_batch_challenge_mismatch")
    if value.get("status") != "PASS" or value.get("non_binding") is not True:
        raise BatchRehearsalProofError("precontest_batch_proof_not_passed")
    if value.get("execution_mode") != "batch":
        raise BatchRehearsalProofError("precontest_batch_mode_invalid")
    generated = _parse_time(value.get("generated_at"), label="generated_at")
    age = now.astimezone(UTC) - generated
    if age > precontest_readiness.MAX_EVIDENCE_AGE or age < -precontest_readiness.MAX_CLOCK_SKEW:
        raise BatchRehearsalProofError("precontest_batch_proof_stale")
    latency = value.get("batch_rehearsal_ms")
    if type(latency) is not int or latency < 0 or latency > precontest_readiness.MAX_CAPTURE_TO_EXECUTOR_MS:
        raise BatchRehearsalProofError("precontest_batch_latency_invalid")
    if value.get("target_capture_to_executor_ms") != precontest_readiness.MAX_CAPTURE_TO_EXECUTOR_MS:
        raise BatchRehearsalProofError("precontest_batch_target_invalid")
    if value.get("target_met") is not True:
        raise BatchRehearsalProofError("precontest_batch_target_failed")
    probes = value.get("probes")
    required_probes = {
        "two_leg_same_sweep_preflight": True,
        "aggregate_over_budget_rejected": True,
        "mixed_sweep_rejected": True,
        "sign_called": False,
        "fence_written": False,
        "pending_marked": False,
        "post_attempted": False,
    }
    if probes != required_probes:
        raise BatchRehearsalProofError("precontest_batch_probes_invalid")
    if value.get("order") != {
        "preflight_before_sign": True,
        "sign_before_fence": True,
        "fence_before_post": True,
    }:
        raise BatchRehearsalProofError("precontest_batch_order_invalid")
    if value.get("aggregate_required_sha256") != _source_sha(batch._aggregate_required):
        raise BatchRehearsalProofError("precontest_batch_source_changed")
    if value.get("preflight_all_sha256") != _source_sha(batch._preflight_all):
        raise BatchRehearsalProofError("precontest_batch_source_changed")
    if value.get("run_locked_sha256") != _source_sha(batch._run_locked):
        raise BatchRehearsalProofError("precontest_batch_source_changed")
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
