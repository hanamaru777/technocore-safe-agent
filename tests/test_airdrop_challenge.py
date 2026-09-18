from __future__ import annotations

import hashlib
import inspect
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from flop_agent import airdrop_challenge, core


OPEN = datetime(2026, 10, 1, 0, 0, tzinfo=UTC)
DEADLINE = datetime(2026, 10, 8, 0, 0, tzinfo=UTC)
COMMIT = "1" * 40
ARTIFACT_BYTES = b"validator bytes\n"
ARTIFACT_SHA = hashlib.sha256(ARTIFACT_BYTES).hexdigest()
ARTIFACT_URL = (
    "https://raw.githubusercontent.com/flop-labs/example-challenge/"
    f"{COMMIT}/validator.py"
)


@pytest.fixture
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(core, "STATE", tmp_path)
    return tmp_path


def make_spec(
    *,
    challenge_id: str = "future-challenge",
    collaboration_required: bool = True,
    registration_required: bool = True,
    artifact_url: str = ARTIFACT_URL,
    artifact_sha: str | None = ARTIFACT_SHA,
) -> dict:
    return {
        "challenge_id": challenge_id,
        "opening": OPEN.isoformat(),
        "deadline": DEADLINE.isoformat(),
        "prize": {"amount": 50_000, "unit": "FLOP"},
        "eligibility": {
            "identity": "officially verified identity",
            "status": "known",
        },
        "submission": {
            "path": "official-submissions",
            "method": "signed_packet",
        },
        "collaboration_required": collaboration_required,
        "registration_required": registration_required,
        "source": {
            "rules_url": (
                "https://raw.githubusercontent.com/flop-labs/example-challenge/"
                f"{COMMIT}/rules.md"
            ),
            "authority_type": "flop_labs_github",
            "authority_id": "official-authority-id",
            "pinned_commit": COMMIT,
            "source_sha256": "2" * 64,
        },
        "required_artifacts": [
            {
                "name": "validator.py",
                "url": artifact_url,
                "sha256": artifact_sha,
                "required": True,
                "kind": "validator",
            }
        ],
        "notes": ["nonbinding planner test"],
    }


def create_ready_base(
    challenge_id: str = "future-challenge",
    *,
    collaboration_required: bool = True,
) -> None:
    spec = make_spec(
        challenge_id=challenge_id,
        collaboration_required=collaboration_required,
    )
    airdrop_challenge.create_challenge(spec, now=OPEN)
    airdrop_challenge.pin_artifact_bytes(
        challenge_id,
        name="validator.py",
        source_url=ARTIFACT_URL,
        data=ARTIFACT_BYTES,
        expected_sha256=ARTIFACT_SHA,
        now=OPEN,
    )
    airdrop_challenge.update_progress(
        challenge_id,
        {
            "rules_authority_pinned": True,
            "identity_proven": True,
            "registration_proven": True,
            "submission_path_proven": True,
        },
        now=OPEN,
    )


def test_date_only_deadline_is_rejected() -> None:
    spec = make_spec()
    spec["deadline"] = "2026-10-08"
    with pytest.raises(ValueError, match="exact_timestamp_required"):
        airdrop_challenge.validate_spec(spec)


def test_untrusted_or_mutable_wrong_github_owner_is_rejected() -> None:
    spec = make_spec()
    spec["source"]["rules_url"] = (
        "https://raw.githubusercontent.com/evil-owner/example/"
        f"{COMMIT}/rules.md"
    )
    with pytest.raises(ValueError, match="untrusted_github_owner"):
        airdrop_challenge.validate_spec(spec)


def test_deadline_gates_are_exact_and_deterministic() -> None:
    spec = airdrop_challenge.validate_spec(make_spec())
    assert airdrop_challenge.deadline_gate(
        spec, now=DEADLINE - timedelta(seconds=86_401)
    )["gate"] == "EARLY"
    assert airdrop_challenge.deadline_gate(
        spec, now=DEADLINE - timedelta(hours=24)
    )["gate"] == "T-24h"
    assert airdrop_challenge.deadline_gate(
        spec, now=DEADLINE - timedelta(hours=12)
    )["gate"] == "T-12h"
    assert airdrop_challenge.deadline_gate(
        spec, now=DEADLINE - timedelta(hours=6)
    )["gate"] == "T-6h"
    assert airdrop_challenge.deadline_gate(
        spec, now=DEADLINE - timedelta(hours=2)
    )["gate"] == "T-2h"
    assert airdrop_challenge.deadline_gate(
        spec, now=DEADLINE - timedelta(minutes=30)
    )["gate"] == "T-30m"
    assert airdrop_challenge.deadline_gate(
        spec, now=DEADLINE - timedelta(minutes=10)
    )["gate"] == "T-10m"
    assert airdrop_challenge.deadline_gate(
        spec, now=DEADLINE + timedelta(seconds=1)
    )["gate"] == "EXPIRED"


def test_t24_focuses_identity_registration_submission_not_team(
    isolated_state: Path,
) -> None:
    create_ready_base()
    plan = airdrop_challenge.build_plan(
        "future-challenge",
        now=DEADLINE - timedelta(hours=24),
    )
    assert plan["deadline_gate"]["gate"] == "T-24h"
    assert "primary_route_missing" not in plan["critical_path"]
    assert "fewer_than_two_ready_alternates" not in plan["critical_path"]
    assert plan["ready_for_execution_path"] is True


def test_t24_blocks_missing_identity_registration_and_submission(
    isolated_state: Path,
) -> None:
    spec = make_spec()
    airdrop_challenge.create_challenge(spec, now=OPEN)
    airdrop_challenge.pin_artifact_bytes(
        "future-challenge",
        name="validator.py",
        source_url=ARTIFACT_URL,
        data=ARTIFACT_BYTES,
        expected_sha256=ARTIFACT_SHA,
        now=OPEN,
    )
    airdrop_challenge.update_progress(
        "future-challenge",
        {"rules_authority_pinned": True},
        now=OPEN,
    )
    plan = airdrop_challenge.build_plan(
        "future-challenge",
        now=DEADLINE - timedelta(hours=24),
    )
    assert "identity_proven" in plan["critical_path"]
    assert "registration_proven" in plan["critical_path"]
    assert "submission_path_proven" in plan["critical_path"]


def test_t12_requires_target_authored_primary_and_two_alternates(
    isolated_state: Path,
) -> None:
    create_ready_base()
    airdrop_challenge.update_progress(
        "future-challenge",
        {
            "primary_route": "primary",
            "alternate_routes": ["alt1", "alt2"],
            "collaborators": {
                "primary": {
                    "availability": True,
                    "target_authored_binding": False,
                    "responsive_proof": True,
                    "current_conflict": False,
                },
                "alt1": {
                    "target_authored_binding": True,
                    "responsive_proof": False,
                    "current_conflict": False,
                },
                "alt2": {
                    "target_authored_binding": True,
                    "responsive_proof": False,
                    "current_conflict": False,
                },
            },
        },
        now=DEADLINE - timedelta(hours=13),
    )
    plan = airdrop_challenge.build_plan(
        "future-challenge",
        now=DEADLINE - timedelta(hours=12),
    )
    assert "primary_not_binding_ready" in plan["critical_path"]
    assert "fewer_than_two_ready_alternates" not in plan["critical_path"]


def test_t6_unbound_primary_must_be_replaced(isolated_state: Path) -> None:
    create_ready_base()
    airdrop_challenge.update_progress(
        "future-challenge",
        {
            "primary_route": "primary",
            "alternate_routes": ["alt1", "alt2"],
            "collaborators": {
                "primary": {
                    "target_authored_binding": False,
                    "responsive_proof": True,
                    "current_conflict": False,
                },
                "alt1": {
                    "target_authored_binding": True,
                    "responsive_proof": True,
                    "current_conflict": False,
                },
                "alt2": {
                    "target_authored_binding": True,
                    "responsive_proof": True,
                    "current_conflict": False,
                },
            },
        },
        now=DEADLINE - timedelta(hours=7),
    )
    plan = airdrop_challenge.build_plan(
        "future-challenge",
        now=DEADLINE - timedelta(hours=6),
    )
    assert "primary_not_binding_ready" in plan["critical_path"]
    assert plan["work_policy"]["nonbinding_coordination"] == "replace_unbound_primary"


def test_t2_requires_binding_and_responsive_proof_for_all_routes(
    isolated_state: Path,
) -> None:
    create_ready_base()
    airdrop_challenge.update_progress(
        "future-challenge",
        {
            "primary_route": "primary",
            "alternate_routes": ["alt1", "alt2"],
            "collaborators": {
                "primary": {
                    "target_authored_binding": True,
                    "responsive_proof": False,
                    "current_conflict": False,
                },
                "alt1": {
                    "target_authored_binding": True,
                    "responsive_proof": True,
                    "current_conflict": False,
                },
                "alt2": {
                    "target_authored_binding": True,
                    "responsive_proof": False,
                    "current_conflict": False,
                },
            },
            "rehearsal_passed": True,
        },
        now=DEADLINE - timedelta(hours=3),
    )
    plan = airdrop_challenge.build_plan(
        "future-challenge",
        now=DEADLINE - timedelta(hours=2),
    )
    assert "primary_not_proven_responsive" in plan["critical_path"]
    assert "fewer_than_two_ready_alternates" in plan["critical_path"]
    assert plan["work_policy"]["new_code"] is False
    assert plan["work_policy"]["nonbinding_coordination"] is False


def test_t30_and_t10_lock_down_work_policy(isolated_state: Path) -> None:
    create_ready_base(collaboration_required=False)
    airdrop_challenge.update_progress(
        "future-challenge",
        {
            "rehearsal_passed": True,
            "execution_path_audited": True,
        },
        now=DEADLINE - timedelta(hours=1),
    )

    t30 = airdrop_challenge.build_plan(
        "future-challenge",
        now=DEADLINE - timedelta(minutes=30),
    )
    assert t30["work_policy"]["new_code"] is False
    assert t30["work_policy"]["ci_wait"] is False
    assert (
        t30["work_policy"]["nonbinding_coordination"]
        == "only_if_directly_unblocks_binding"
    )

    t10 = airdrop_challenge.build_plan(
        "future-challenge",
        now=DEADLINE - timedelta(minutes=10),
    )
    assert t10["work_policy"]["new_code"] is False
    assert t10["work_policy"]["ci_wait"] is False
    assert t10["work_policy"]["execution_only"] is True


def test_expired_challenge_never_reports_execution_ready(isolated_state: Path) -> None:
    create_ready_base(collaboration_required=False)
    airdrop_challenge.update_progress(
        "future-challenge",
        {
            "rehearsal_passed": True,
            "execution_path_audited": True,
        },
        now=DEADLINE - timedelta(hours=1),
    )
    plan = airdrop_challenge.build_plan(
        "future-challenge",
        now=DEADLINE + timedelta(seconds=1),
    )
    assert plan["ready_for_execution_path"] is False
    assert "deadline_expired" in plan["critical_path"]
    assert plan["work_policy"]["participant_actions_open"] is False


def test_artifact_hash_mismatch_writes_nothing(isolated_state: Path) -> None:
    airdrop_challenge.create_challenge(make_spec(), now=OPEN)
    wrong = "f" * 64
    with pytest.raises(RuntimeError, match="artifact_hash_mismatch"):
        airdrop_challenge.pin_artifact_bytes(
            "future-challenge",
            name="validator.py",
            source_url=ARTIFACT_URL,
            data=ARTIFACT_BYTES,
            expected_sha256=wrong,
            now=OPEN,
        )
    assert not (
        isolated_state
        / "airdrop-radar"
        / "challenges"
        / "future-challenge"
        / "artifacts"
        / "validator.py"
    ).exists()


def test_mutable_required_artifact_without_expected_hash_is_not_verified(
    isolated_state: Path,
) -> None:
    mutable = "https://flop.finance/challenge/validator.py"
    spec = make_spec(
        artifact_url=mutable,
        artifact_sha=None,
    )
    airdrop_challenge.create_challenge(spec, now=OPEN)
    airdrop_challenge.pin_artifact_bytes(
        "future-challenge",
        name="validator.py",
        source_url=mutable,
        data=ARTIFACT_BYTES,
        expected_sha256=None,
        now=OPEN,
    )
    status = airdrop_challenge.verify_artifacts("future-challenge")
    assert status["all_required_ok"] is False
    assert status["artifacts"][0]["reason"] == "unanchored_expected_hash_missing"


def test_immutable_commit_url_can_anchor_artifact_without_declared_hash(
    isolated_state: Path,
) -> None:
    spec = make_spec(artifact_sha=None)
    airdrop_challenge.create_challenge(spec, now=OPEN)
    airdrop_challenge.pin_artifact_bytes(
        "future-challenge",
        name="validator.py",
        source_url=ARTIFACT_URL,
        data=ARTIFACT_BYTES,
        expected_sha256=None,
        now=OPEN,
    )
    status = airdrop_challenge.verify_artifacts("future-challenge")
    assert status["all_required_ok"] is True


def test_tampered_pinned_artifact_is_detected(isolated_state: Path) -> None:
    create_ready_base(collaboration_required=False)
    path = (
        isolated_state
        / "airdrop-radar"
        / "challenges"
        / "future-challenge"
        / "artifacts"
        / "validator.py"
    )
    path.write_bytes(b"tampered")
    status = airdrop_challenge.verify_artifacts("future-challenge")
    assert status["all_required_ok"] is False
    assert status["artifacts"][0]["reason"] == "hash_mismatch"


def test_request_idempotency_and_reuse_protection(isolated_state: Path) -> None:
    create_ready_base(collaboration_required=False)
    first = airdrop_challenge.plan_request(
        "future-challenge",
        action="register",
        request_id="register-1",
        payload={"role": "writer"},
        now=OPEN,
    )
    same = airdrop_challenge.plan_request(
        "future-challenge",
        action="register",
        request_id="register-1",
        payload={"role": "writer"},
        now=OPEN + timedelta(seconds=1),
    )
    assert same == first

    with pytest.raises(RuntimeError, match="reuse_with_different_payload"):
        airdrop_challenge.plan_request(
            "future-challenge",
            action="register",
            request_id="register-1",
            payload={"role": "organizer"},
            now=OPEN + timedelta(seconds=2),
        )


def test_ambiguous_request_blocks_replacement_until_reconciled(
    isolated_state: Path,
) -> None:
    create_ready_base(collaboration_required=False)
    airdrop_challenge.plan_request(
        "future-challenge",
        action="register",
        request_id="register-1",
        payload={"role": "writer"},
        now=OPEN,
    )
    airdrop_challenge.mark_request(
        "future-challenge",
        request_id="register-1",
        status="ambiguous",
        now=OPEN + timedelta(seconds=1),
    )

    with pytest.raises(RuntimeError, match="ambiguous_request_reconcile_first"):
        airdrop_challenge.plan_request(
            "future-challenge",
            action="register",
            request_id="register-2",
            payload={"role": "writer"},
            now=OPEN + timedelta(seconds=2),
        )

    plan = airdrop_challenge.build_plan(
        "future-challenge",
        now=DEADLINE - timedelta(days=2),
    )
    assert "ambiguous_request_reconcile_required" in plan["critical_path"]
    assert plan["ambiguous_request_ids"] == ["register-1"]

    airdrop_challenge.mark_request(
        "future-challenge",
        request_id="register-1",
        status="reconciled_not_found",
        now=OPEN + timedelta(seconds=3),
    )
    next_request = airdrop_challenge.plan_request(
        "future-challenge",
        action="register",
        request_id="register-2",
        payload={"role": "writer"},
        now=OPEN + timedelta(seconds=4),
    )
    assert next_request["status"] == "planned"


def test_accepted_or_rejected_request_is_terminal(isolated_state: Path) -> None:
    create_ready_base(collaboration_required=False)
    airdrop_challenge.plan_request(
        "future-challenge",
        action="submit",
        request_id="submit-1",
        payload={"entry": "x"},
        now=OPEN,
    )
    airdrop_challenge.mark_request(
        "future-challenge",
        request_id="submit-1",
        status="accepted",
        receipt_hash="a" * 64,
        now=OPEN + timedelta(seconds=1),
    )
    with pytest.raises(RuntimeError, match="transition_invalid"):
        airdrop_challenge.mark_request(
            "future-challenge",
            request_id="submit-1",
            status="ambiguous",
            now=OPEN + timedelta(seconds=2),
        )


def test_plan_is_nonbinding_and_lists_action_specific_authorizations(
    isolated_state: Path,
) -> None:
    create_ready_base(collaboration_required=False)
    plan = airdrop_challenge.build_plan(
        "future-challenge",
        now=DEADLINE - timedelta(days=2),
    )
    assert plan["non_binding"] is True
    assert "X_post" in plan["authorization_required_for"]
    assert "submission" in plan["authorization_required_for"]
    assert "value_transfer" in plan["authorization_required_for"]


def test_challenge_state_is_isolated_under_airdrop_radar(
    isolated_state: Path,
) -> None:
    create_ready_base(collaboration_required=False)
    expected = (
        isolated_state
        / "airdrop-radar"
        / "challenges"
        / "future-challenge"
    )
    assert expected.is_dir()
    assert (expected / "spec.json").is_file()
    assert (expected / "progress.json").is_file()
    assert (expected / "requests.json").is_file()


def test_interrupted_create_is_completed_idempotently(
    isolated_state: Path,
) -> None:
    spec = make_spec()
    airdrop_challenge.create_challenge(spec, now=OPEN)
    base = (
        isolated_state
        / "airdrop-radar"
        / "challenges"
        / "future-challenge"
    )
    (base / "progress.json").unlink()
    (base / "requests.json").unlink()

    restored = airdrop_challenge.create_challenge(
        spec,
        now=OPEN + timedelta(seconds=1),
    )
    assert restored["challenge_id"] == "future-challenge"
    assert (base / "progress.json").is_file()
    assert (base / "requests.json").is_file()


def test_persisted_artifact_path_is_never_trusted(
    isolated_state: Path,
) -> None:
    create_ready_base(collaboration_required=False)
    base = (
        isolated_state
        / "airdrop-radar"
        / "challenges"
        / "future-challenge"
    )
    index_path = base / "artifacts.json"
    index = json.loads(index_path.read_text("utf-8"))
    index["artifacts"]["validator.py"]["relative_path"] = "../../../../etc/passwd"
    index_path.write_text(json.dumps(index), "utf-8")

    status = airdrop_challenge.verify_artifacts("future-challenge")
    assert status["all_required_ok"] is True
    assert status["artifacts"][0]["reason"] == "ok"


def test_ambiguous_same_request_id_cannot_be_replanned(
    isolated_state: Path,
) -> None:
    create_ready_base(collaboration_required=False)
    payload = {"role": "writer"}
    airdrop_challenge.plan_request(
        "future-challenge",
        action="register",
        request_id="register-1",
        payload=payload,
        now=OPEN,
    )
    airdrop_challenge.mark_request(
        "future-challenge",
        request_id="register-1",
        status="ambiguous",
        now=OPEN + timedelta(seconds=1),
    )
    with pytest.raises(RuntimeError, match="ambiguous_request_reconcile_first"):
        airdrop_challenge.plan_request(
            "future-challenge",
            action="register",
            request_id="register-1",
            payload=payload,
            now=OPEN + timedelta(seconds=2),
        )


def test_accepted_state_requires_receipt_hash(
    isolated_state: Path,
) -> None:
    create_ready_base(collaboration_required=False)
    airdrop_challenge.plan_request(
        "future-challenge",
        action="submit",
        request_id="submit-no-receipt",
        payload={"entry": "x"},
        now=OPEN,
    )
    with pytest.raises(ValueError, match="receipt_hash_required"):
        airdrop_challenge.mark_request(
            "future-challenge",
            request_id="submit-no-receipt",
            status="accepted",
            now=OPEN + timedelta(seconds=1),
        )


def test_primary_cannot_also_be_an_alternate(
    isolated_state: Path,
) -> None:
    create_ready_base()
    with pytest.raises(ValueError, match="primary_also_alternate"):
        airdrop_challenge.update_progress(
            "future-challenge",
            {
                "primary_route": "same",
                "alternate_routes": ["same", "other"],
            },
            now=OPEN,
        )


def test_runner_has_get_only_network_and_no_binding_transport() -> None:
    source = inspect.getsource(airdrop_challenge)
    lowered = source.lower()
    assert 'httpx.stream(' in lowered
    assert '"get"' in lowered
    assert "httpx.post" not in lowered
    assert "httpx.put" not in lowered
    assert "httpx.delete" not in lowered
    assert "requests." not in lowered
    assert "subprocess" not in lowered
    assert "sign_seed" not in lowered
    assert ' / "observer"' not in source
