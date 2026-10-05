"""Machine-generated, non-binding proof for the bounded active-learning gate.

This module proves that the current Close Call staging policy can select a bounded
first learning leg without requiring perfect leader coverage, while still
rejecting undersized, over-budget, and already-skipped candidates. It never
signs, posts, starts services, or touches signer/Vault state.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import re
import sys
import textwrap
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from . import airdrop_challenge
from . import close1_autonomous_stage as stage
from . import precontest_readiness
from .close1_candidate_scanner import CandidateScan, CandidateView

SCHEMA_VERSION = 1
HEX64_RE = re.compile(r"[0-9a-f]{64}")
CASH = Decimal("10000")
REFERENCE = Decimal("101")


class ActiveLearningProofError(RuntimeError):
    """Fail-closed local active-learning proof error."""


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _source_sha(function: object) -> str:
    source = textwrap.dedent(inspect.getsource(function))
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _parse_time(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise ActiveLearningProofError(f"precontest_active_{label}_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ActiveLearningProofError(f"precontest_active_{label}_invalid") from error
    if parsed.tzinfo is None:
        raise ActiveLearningProofError(f"precontest_active_{label}_invalid")
    return parsed.astimezone(UTC)


def proof_path(challenge_id: str) -> Path:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    return precontest_readiness._root() / challenge_id / "precontest-active-learning-proof.json"


def _candidate(
    *,
    trade_id: str,
    qty: Decimal,
    required_cash: Decimal,
    px: Decimal = Decimal("100"),
    seq: int = 1,
) -> CandidateView:
    return CandidateView(
        room="close1-offers",
        seq=seq,
        trade_id=trade_id,
        taker_side="buy",
        qty=qty,
        px=px,
        until=10,
        base_fee=Decimal("1"),
        required_cash=required_cash,
        dynamic_top3_price=None,
        dynamic_condition=None,
        move_percent_from_mark=None,
        visible_leader_coverage=0,
        visible_leaders=0,
        warning="machine-proof",
        maker="did:key:z6MktVwQqJbSVfLfDUHRVkJShspL49A2d6EbhzKvXV9zPLF5",
    )


def _scan(*candidates: CandidateView, strategy_gate: str) -> CandidateScan:
    return CandidateScan(
        sweep=8,
        reference=REFERENCE,
        reference_age_seconds=1,
        mark=REFERENCE,
        top3_cutoff=None,
        visible_leaders=(),
        verified_offers=len(candidates),
        sampled_trade_ids=len(candidates),
        rejected_offers=0,
        candidates=tuple(candidates),
        strategy_gate=strategy_gate,
    )


def _dynamic_probes() -> dict:
    min_qty = stage.MIN_MATERIAL_QTY
    max_fraction = stage.MAX_CASH_FRACTION
    min_edge = stage.MIN_EDGE_BPS
    if min_qty <= 0:
        raise ActiveLearningProofError("precontest_active_min_qty_invalid")
    if not Decimal("0") < max_fraction < Decimal("1"):
        raise ActiveLearningProofError("precontest_active_cash_fraction_invalid")
    if min_edge < 0:
        raise ActiveLearningProofError("precontest_active_min_edge_invalid")

    good = _candidate(
        trade_id="proof-good",
        qty=min_qty,
        required_cash=CASH * max_fraction / Decimal("2"),
        seq=10,
    )
    chosen = stage._select_candidate(
        _scan(good, strategy_gate="leader_coverage_incomplete"),
        cash=CASH,
        skip_ids=set(),
    )
    if chosen is None or chosen.trade_id != good.trade_id:
        raise ActiveLearningProofError("precontest_active_incomplete_coverage_deadlock")

    too_small = _candidate(
        trade_id="proof-small",
        qty=min_qty / Decimal("2"),
        required_cash=Decimal("100"),
        seq=11,
    )
    if stage._select_candidate(
        _scan(too_small, strategy_gate="leader_coverage_incomplete"),
        cash=CASH,
        skip_ids=set(),
    ) is not None:
        raise ActiveLearningProofError("precontest_active_small_qty_not_rejected")

    over_budget = _candidate(
        trade_id="proof-over-budget",
        qty=min_qty,
        required_cash=CASH * max_fraction + Decimal("0.01"),
        seq=12,
    )
    if stage._select_candidate(
        _scan(over_budget, strategy_gate="leader_coverage_incomplete"),
        cash=CASH,
        skip_ids=set(),
    ) is not None:
        raise ActiveLearningProofError("precontest_active_over_budget_not_rejected")

    skipped = _candidate(
        trade_id="proof-skipped",
        qty=min_qty * Decimal("2"),
        required_cash=Decimal("100"),
        seq=13,
    )
    fallback = _candidate(
        trade_id="proof-fresh",
        qty=min_qty,
        required_cash=Decimal("100"),
        seq=14,
    )
    selected_after_skip = stage._select_candidate(
        _scan(skipped, fallback, strategy_gate="leader_coverage_incomplete"),
        cash=CASH,
        skip_ids={skipped.trade_id},
    )
    if selected_after_skip is None or selected_after_skip.trade_id != fallback.trade_id:
        raise ActiveLearningProofError("precontest_active_skip_not_enforced")

    return {
        "leader_coverage_incomplete_selected": good.trade_id,
        "too_small_rejected": True,
        "over_budget_rejected": True,
        "skipped_id_rejected": True,
        "fresh_fallback_selected": fallback.trade_id,
    }


def build_proof(challenge_id: str, *, now: datetime | None = None) -> dict:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_active_now_timezone_required")
    current = current.astimezone(UTC)

    probes = _dynamic_probes()
    value = {
        "schema_version": SCHEMA_VERSION,
        "challenge_id": challenge_id,
        "status": "PASS",
        "non_binding": True,
        "generated_at": current.isoformat(),
        "runtime": "close1_autonomous_stage",
        "policy": {
            "min_material_qty": format(stage.MIN_MATERIAL_QTY, "f"),
            "max_cash_fraction": format(stage.MAX_CASH_FRACTION, "f"),
            "min_edge_bps": format(stage.MIN_EDGE_BPS, "f"),
        },
        "probes": probes,
        "first_leg_policy_predefined": True,
        "first_leg_risk_bounded": True,
        "zero_trade_deadlock_prevented": True,
        "select_candidate_sha256": _source_sha(stage._select_candidate),
    }
    value["proof_sha256"] = _sha(value)
    return value


def validate_proof(
    value: object,
    *,
    challenge_id: str,
    now: datetime,
) -> dict:
    if not isinstance(value, dict):
        raise ActiveLearningProofError("precontest_active_proof_invalid")
    required = {
        "schema_version", "challenge_id", "status", "non_binding", "generated_at",
        "runtime", "policy", "probes", "first_leg_policy_predefined",
        "first_leg_risk_bounded", "zero_trade_deadlock_prevented",
        "select_candidate_sha256", "proof_sha256",
    }
    if set(value) != required or value.get("schema_version") != SCHEMA_VERSION:
        raise ActiveLearningProofError("precontest_active_proof_schema_invalid")
    digest = value.get("proof_sha256")
    if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
        raise ActiveLearningProofError("precontest_active_proof_digest_invalid")
    unsigned = dict(value)
    unsigned.pop("proof_sha256")
    if _sha(unsigned) != digest:
        raise ActiveLearningProofError("precontest_active_proof_integrity_invalid")
    if value.get("challenge_id") != airdrop_challenge.validate_challenge_id(challenge_id):
        raise ActiveLearningProofError("precontest_active_challenge_mismatch")
    if value.get("status") != "PASS" or value.get("non_binding") is not True:
        raise ActiveLearningProofError("precontest_active_proof_not_passed")
    if value.get("runtime") != "close1_autonomous_stage":
        raise ActiveLearningProofError("precontest_active_runtime_invalid")

    generated = _parse_time(value.get("generated_at"), label="generated_at")
    age = now.astimezone(UTC) - generated
    if age > precontest_readiness.MAX_EVIDENCE_AGE or age < -precontest_readiness.MAX_CLOCK_SKEW:
        raise ActiveLearningProofError("precontest_active_proof_stale")

    expected_policy = {
        "min_material_qty": format(stage.MIN_MATERIAL_QTY, "f"),
        "max_cash_fraction": format(stage.MAX_CASH_FRACTION, "f"),
        "min_edge_bps": format(stage.MIN_EDGE_BPS, "f"),
    }
    if value.get("policy") != expected_policy:
        raise ActiveLearningProofError("precontest_active_policy_changed")
    if value.get("select_candidate_sha256") != _source_sha(stage._select_candidate):
        raise ActiveLearningProofError("precontest_active_source_changed")

    probes = value.get("probes")
    if not isinstance(probes, dict):
        raise ActiveLearningProofError("precontest_active_probes_invalid")
    if probes.get("leader_coverage_incomplete_selected") != "proof-good":
        raise ActiveLearningProofError("precontest_active_incomplete_coverage_deadlock")
    if probes.get("too_small_rejected") is not True:
        raise ActiveLearningProofError("precontest_active_small_qty_invalid")
    if probes.get("over_budget_rejected") is not True:
        raise ActiveLearningProofError("precontest_active_cash_bound_invalid")
    if probes.get("skipped_id_rejected") is not True or probes.get("fresh_fallback_selected") != "proof-fresh":
        raise ActiveLearningProofError("precontest_active_skip_invalid")

    for key in (
        "first_leg_policy_predefined",
        "first_leg_risk_bounded",
        "zero_trade_deadlock_prevented",
    ):
        if value.get(key) is not True:
            raise ActiveLearningProofError("precontest_active_gate_false")
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
