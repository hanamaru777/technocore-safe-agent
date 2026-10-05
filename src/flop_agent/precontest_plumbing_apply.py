"""Apply a validated Production plumbing receipt to saved readiness evidence.

This overlay may change only the three NO_LIVE_PLUMBING evidence fields.  It
never promotes human-independence, control-path, strategy, deadline, settlement,
or execution-mode evidence and never performs a binding action.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from . import airdrop_challenge
from . import precontest_machine_evidence as machine
from . import precontest_plumbing_receipt as plumbing
from . import precontest_readiness

MAX_BYTES = 512 * 1024


class PlumbingApplyError(RuntimeError):
    """Fail-closed plumbing overlay error."""


def _load_receipt(challenge_id: str) -> tuple[dict, str] | None:
    path = plumbing.receipt_path(challenge_id)
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise PlumbingApplyError("precontest_plumbing_receipt_file_invalid")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_BYTES:
        raise PlumbingApplyError("precontest_plumbing_receipt_file_invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PlumbingApplyError("precontest_plumbing_receipt_file_invalid") from error
    if not isinstance(value, dict):
        raise PlumbingApplyError("precontest_plumbing_receipt_file_invalid")
    return value, machine._sha_bytes(raw)


def _update_provenance(challenge_id: str, *, saved: dict, valid: dict, file_sha256: str) -> None:
    path = machine.provenance_path(challenge_id)
    if path.is_symlink() or not path.is_file():
        raise PlumbingApplyError("precontest_plumbing_provenance_missing")
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PlumbingApplyError("precontest_plumbing_provenance_invalid") from error
    if not isinstance(value, dict):
        raise PlumbingApplyError("precontest_plumbing_provenance_invalid")
    digest = value.pop("provenance_sha256", None)
    if not isinstance(digest, str) or machine._sha_value(value) != digest:
        raise PlumbingApplyError("precontest_plumbing_provenance_integrity_invalid")
    sources = value.get("sources")
    unsupported = value.get("unsupported_gates_forced_no_go")
    if not isinstance(sources, dict) or not isinstance(unsupported, list):
        raise PlumbingApplyError("precontest_plumbing_provenance_schema_invalid")
    sources["production_plumbing_receipt"] = {
        "sha256": file_sha256,
        "receipt_sha256": valid["receipt_sha256"],
        "generated_at": valid["generated_at"],
        "deployed_commit": valid["deployed_commit"],
    }
    value["readiness_evidence_sha256"] = saved["evidence_sha256"]
    value["unsupported_gates_forced_no_go"] = [
        item for item in unsupported if item != "NO_LIVE_PLUMBING_GATE"
    ]
    value["provenance_sha256"] = machine._sha_value(value)
    precontest_readiness._atomic_write(path, value)


def apply_if_present(challenge_id: str, *, now: datetime | None = None) -> dict | None:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_plumbing_apply_timezone_required")
    current = current.astimezone(UTC)

    loaded = _load_receipt(challenge_id)
    if loaded is None:
        return None
    value, file_sha256 = loaded
    try:
        valid = plumbing.validate_receipt(
            value,
            challenge_id=challenge_id,
            now=current,
        )
    except plumbing.PlumbingReceiptError as error:
        raise PlumbingApplyError("precontest_plumbing_receipt_invalid") from error

    evidence = precontest_readiness.load_evidence(challenge_id)
    if evidence is None:
        raise PlumbingApplyError("precontest_plumbing_readiness_missing")
    unsigned = dict(evidence)
    unsigned.pop("evidence_sha256", None)

    # The overlay is deliberately narrow.  No other readiness field may change.
    unsigned["execution_plumbing_complete"] = True
    unsigned["production_rehearsal_passed"] = True
    unsigned["live_plumbing_changes_required"] = False
    saved = precontest_readiness.save_evidence(challenge_id, unsigned)
    _update_provenance(
        challenge_id,
        saved=saved,
        valid=valid,
        file_sha256=file_sha256,
    )
    return precontest_readiness.evaluate(
        saved,
        now=current,
        expected_deadline=saved["campaign_deadline"],
    )
