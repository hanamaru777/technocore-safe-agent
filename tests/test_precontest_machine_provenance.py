import json
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import precontest_machine_provenance as provenance
from flop_agent import precontest_readiness


NOW = datetime(2026, 10, 5, 6, 45, tzinfo=UTC)
CHALLENGE = "machine-provenance-test"
EVIDENCE_SHA = "1" * 64


def _value(**patch):
    value = {
        "schema_version": 1,
        "challenge_id": CHALLENGE,
        "collected_at": NOW.isoformat(),
        "collector": "precontest_machine_evidence",
        "non_binding": True,
        "readiness_evidence_sha256": EVIDENCE_SHA,
        "sources": {
            "close1_autonomous_rehearsal": {"sha256": "2" * 64},
        },
        "unsupported_gates_forced_no_go": [],
    }
    value.update(patch)
    value["provenance_sha256"] = provenance._sha(value)
    return value


def test_validate_accepts_exact_fresh_matching_machine_provenance():
    value = _value()

    valid = provenance.validate(
        value,
        challenge_id=CHALLENGE,
        readiness_evidence_sha256=EVIDENCE_SHA,
        now=NOW,
        require_no_unsupported=True,
    )

    assert valid == value


def test_validate_rejects_tamper_and_readiness_digest_mismatch():
    value = _value()
    tampered = json.loads(json.dumps(value))
    tampered["collector"] = "manual"

    with pytest.raises(
        provenance.MachineProvenanceError,
        match="precontest_machine_provenance_integrity_invalid",
    ):
        provenance.validate(
            tampered,
            challenge_id=CHALLENGE,
            readiness_evidence_sha256=EVIDENCE_SHA,
            now=NOW,
            require_no_unsupported=False,
        )

    with pytest.raises(
        provenance.MachineProvenanceError,
        match="precontest_machine_provenance_evidence_mismatch",
    ):
        provenance.validate(
            value,
            challenge_id=CHALLENGE,
            readiness_evidence_sha256="3" * 64,
            now=NOW,
            require_no_unsupported=False,
        )


def test_validate_rejects_stale_and_wrong_collector():
    stale = _value(collected_at=(NOW - precontest_readiness.MAX_EVIDENCE_AGE - timedelta(seconds=1)).isoformat())
    with pytest.raises(
        provenance.MachineProvenanceError,
        match="precontest_machine_provenance_stale",
    ):
        provenance.validate(
            stale,
            challenge_id=CHALLENGE,
            readiness_evidence_sha256=EVIDENCE_SHA,
            now=NOW,
            require_no_unsupported=False,
        )

    wrong = _value(collector="manual_collector")
    with pytest.raises(
        provenance.MachineProvenanceError,
        match="precontest_machine_provenance_collector_invalid",
    ):
        provenance.validate(
            wrong,
            challenge_id=CHALLENGE,
            readiness_evidence_sha256=EVIDENCE_SHA,
            now=NOW,
            require_no_unsupported=False,
        )


def test_go_requires_empty_unsupported_gate_list():
    value = _value(unsupported_gates_forced_no_go=["HUMAN_INDEPENDENCE_GATE"])

    # A NO-GO plan may still retain valid provenance that explains the blocker.
    provenance.validate(
        value,
        challenge_id=CHALLENGE,
        readiness_evidence_sha256=EVIDENCE_SHA,
        now=NOW,
        require_no_unsupported=False,
    )

    with pytest.raises(
        provenance.MachineProvenanceError,
        match="precontest_machine_provenance_unsupported_gates",
    ):
        provenance.validate(
            value,
            challenge_id=CHALLENGE,
            readiness_evidence_sha256=EVIDENCE_SHA,
            now=NOW,
            require_no_unsupported=True,
        )


def test_load_validated_missing_and_symlink_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)

    with pytest.raises(
        provenance.MachineProvenanceError,
        match="precontest_machine_provenance_missing",
    ):
        provenance.load_validated(
            CHALLENGE,
            readiness_evidence_sha256=EVIDENCE_SHA,
            now=NOW,
            require_no_unsupported=False,
        )

    path = provenance.provenance_path(CHALLENGE)
    path.parent.mkdir(parents=True, exist_ok=True)
    target = path.parent / "target.json"
    target.write_text(json.dumps(_value()), encoding="utf-8")
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("symlink unavailable")

    with pytest.raises(
        provenance.MachineProvenanceError,
        match="precontest_machine_provenance_missing",
    ):
        provenance.load_validated(
            CHALLENGE,
            readiness_evidence_sha256=EVIDENCE_SHA,
            now=NOW,
            require_no_unsupported=False,
        )
