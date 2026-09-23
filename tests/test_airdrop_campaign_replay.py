from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from flop_agent import airdrop_challenge, airdrop_monitor, airdrop_radar, core


OPEN = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)
DEADLINE = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)


@pytest.fixture
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(core, "STATE", tmp_path)
    return tmp_path


def _spec() -> dict:
    return {
        "challenge_id": "sonnet-replay",
        "opening": OPEN.isoformat(),
        "deadline": DEADLINE.isoformat(),
        "prize": {"amount": 1, "unit": "FLOP"},
        "eligibility": {"role": "writer"},
        "submission": {"path": "official-referee", "method": "signed"},
        "collaboration_required": True,
        "registration_required": True,
        "source": {
            "rules_url": "https://flop.finance/challenge/rules",
            "authority_type": "flop_site",
            "authority_id": "historical-replay",
        },
        "required_artifacts": [],
        "notes": ["sanitized Sonnet-2 failure-class replay"],
    }


def _snapshot(at: datetime) -> dict:
    return {
        "schema_version": airdrop_radar.SCHEMA_VERSION,
        "read_only": True,
        "scanned_at": at.isoformat(),
        "health": "ok",
        "snapshot_id": "campaign-replay-baseline",
        "source_precedence": [],
        "sources": [],
        "resolved_facts": {},
        "deadlines": [],
        "summary": {
            "available_sources": 0,
            "failed_sources": [],
            "conflicts": [],
        },
        "warnings": [],
    }


def test_historical_sonnet_failure_classes_are_fail_closed_and_deadline_visible(
    isolated_state: Path,
) -> None:
    airdrop_challenge.create_challenge(_spec(), now=OPEN)
    airdrop_challenge.update_progress(
        "sonnet-replay",
        {
            "rules_authority_pinned": True,
            "identity_proven": True,
            "submission_path_proven": True,
        },
        now=OPEN,
    )

    # The historical registration receipt was not durably visible during the
    # live contest. The modern planner must surface that at T-24h rather than
    # treating a successful POST/readback as acceptance.
    t24 = airdrop_challenge.build_plan(
        "sonnet-replay",
        now=DEADLINE - timedelta(hours=24),
    )
    assert "registration_proven" in t24["critical_path"]
    assert t24["ready_for_execution_path"] is False

    airdrop_challenge.plan_request(
        "sonnet-replay",
        action="register",
        request_id="writer-registration-1",
        payload={"role": "writer"},
        now=DEADLINE - timedelta(hours=23),
    )
    airdrop_challenge.mark_request(
        "sonnet-replay",
        request_id="writer-registration-1",
        status="ambiguous",
        now=DEADLINE - timedelta(hours=22),
    )

    # Ambiguous writes block replacement request churn until reconciled.
    with pytest.raises(RuntimeError, match="ambiguous_request_reconcile_first"):
        airdrop_challenge.plan_request(
            "sonnet-replay",
            action="register",
            request_id="writer-registration-2",
            payload={"role": "writer"},
            now=DEADLINE - timedelta(hours=21),
        )

    t12_ambiguous = airdrop_challenge.build_plan(
        "sonnet-replay",
        now=DEADLINE - timedelta(hours=12),
    )
    assert "registration_proven" in t12_ambiguous["critical_path"]
    assert "ambiguous_request_reconcile_required" in t12_ambiguous["critical_path"]

    # Later authoritative evidence can reconcile the original request without
    # a blind retry. Only then may registration_proven be advanced.
    airdrop_challenge.mark_request(
        "sonnet-replay",
        request_id="writer-registration-1",
        status="reconciled_accepted",
        receipt_hash="a" * 64,
        now=DEADLINE - timedelta(hours=11),
    )
    airdrop_challenge.update_progress(
        "sonnet-replay",
        {
            "registration_proven": True,
            "primary_route": "primary",
            "alternate_routes": ["alt-a", "alt-b"],
            "collaborators": {
                "primary": {
                    "availability": True,
                    "target_authored_binding": False,
                    "responsive_proof": True,
                    "current_conflict": False,
                },
                "alt-a": {
                    "target_authored_binding": True,
                    "responsive_proof": True,
                    "current_conflict": False,
                },
                "alt-b": {
                    "target_authored_binding": True,
                    "responsive_proof": True,
                    "current_conflict": False,
                },
            },
        },
        now=DEADLINE - timedelta(hours=7),
    )

    t6 = airdrop_challenge.build_plan(
        "sonnet-replay",
        now=DEADLINE - timedelta(hours=6),
    )
    assert "primary_not_binding_ready" in t6["critical_path"]
    assert t6["work_policy"]["nonbinding_coordination"] == "replace_unbound_primary"
    assert t6["ready_for_execution_path"] is False

    # By T-2h every retained route must be both binding and proven responsive.
    airdrop_challenge.update_progress(
        "sonnet-replay",
        {
            "rehearsal_passed": True,
            "primary_route": "primary",
            "alternate_routes": ["alt-a", "alt-b"],
            "collaborators": {
                "primary": {
                    "target_authored_binding": True,
                    "responsive_proof": True,
                    "current_conflict": False,
                },
                "alt-a": {
                    "target_authored_binding": True,
                    "responsive_proof": True,
                    "current_conflict": False,
                },
                "alt-b": {
                    "target_authored_binding": True,
                    "responsive_proof": True,
                    "current_conflict": False,
                },
            },
        },
        now=DEADLINE - timedelta(hours=3),
    )
    t2 = airdrop_challenge.build_plan(
        "sonnet-replay",
        now=DEADLINE - timedelta(hours=2),
    )
    assert t2["critical_path"] == []
    assert t2["ready_for_execution_path"] is True
    assert t2["work_policy"]["new_code"] is False

    # T-30m still requires an already-audited execution path.
    t30 = airdrop_challenge.build_plan(
        "sonnet-replay",
        now=DEADLINE - timedelta(minutes=30),
    )
    assert "execution_path_audited" in t30["critical_path"]
    airdrop_challenge.update_progress(
        "sonnet-replay",
        {"execution_path_audited": True},
        now=DEADLINE - timedelta(minutes=20),
    )

    t10 = airdrop_challenge.build_plan(
        "sonnet-replay",
        now=DEADLINE - timedelta(minutes=10),
    )
    assert t10["critical_path"] == []
    assert t10["work_policy"]["execution_only"] is True

    expired = airdrop_challenge.build_plan(
        "sonnet-replay",
        now=DEADLINE + timedelta(seconds=1),
    )
    assert "deadline_expired" in expired["critical_path"]
    assert expired["ready_for_execution_path"] is False
    assert expired["work_policy"]["participant_actions_open"] is False


def test_progress_updated_at_is_not_treated_as_service_liveness_clock(
    isolated_state: Path,
) -> None:
    airdrop_challenge.create_challenge(_spec(), now=OPEN)
    airdrop_challenge.update_progress(
        "sonnet-replay",
        {
            "rules_authority_pinned": True,
            "identity_proven": True,
            "registration_proven": True,
            "submission_path_proven": True,
        },
        now=OPEN,
    )

    # The state may be old simply because nothing changed. Its timestamp must
    # not become a synthetic service-health blocker.
    plan = airdrop_challenge.build_plan(
        "sonnet-replay",
        now=DEADLINE - timedelta(hours=24),
    )
    assert all("stale" not in blocker for blocker in plan["critical_path"])
    assert all("liveness" not in blocker for blocker in plan["critical_path"])


def test_challenge_runner_has_no_bounded_room_window_continuity_assumption() -> None:
    # Sonnet-2 had a helper that incorrectly required first_seq == prior+1 on a
    # bounded latest-window endpoint. The reusable runner must not reintroduce
    # room-ring continuity semantics into campaign planning.
    source = inspect.getsource(airdrop_challenge)
    assert "first_seq" not in source
    assert "last_seq" not in source
    assert "target_dids" not in source


class _Response:
    status_code = 200
    url = "https://flop.finance/challenge/validator.py"
    headers = {"content-length": "3"}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def raise_for_status(self) -> None:
        return None

    def iter_bytes(self):
        yield b"abc"


class _RetryClient:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def stream(self, method: str, url: str):
        assert method == "GET"
        self.calls.append(url)
        if len(self.calls) == 1:
            raise httpx.ReadTimeout("transient read timeout")
        return _Response()


def test_challenge_artifact_transient_read_timeout_is_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        airdrop_challenge.httpx,
        "Client",
        lambda **_kwargs: _RetryClient(calls),
    )

    body = airdrop_challenge._read_official_bytes(
        "https://flop.finance/challenge/validator.py",
        sleeper=lambda _seconds: None,
    )
    assert body == b"abc"
    assert calls == [
        "https://flop.finance/challenge/validator.py",
        "https://flop.finance/challenge/validator.py",
    ]


def test_monitor_cycle_survives_read_timeout_and_records_next_cycle(
    isolated_state: Path,
) -> None:
    def timeout_scan() -> dict:
        raise httpx.ReadTimeout("transient monitor timeout")

    first = airdrop_monitor.run_once(scanner=timeout_scan, now=OPEN)
    assert first["outcome"] == "scan_failed"
    assert first["recorded"] is False

    second_at = OPEN + timedelta(minutes=15)
    second = airdrop_monitor.run_once(
        scanner=lambda: _snapshot(second_at),
        now=second_at,
    )
    assert second["outcome"] == "recorded"
    assert second["recorded"] is True

    status = airdrop_monitor.monitor_status(now=second_at + timedelta(seconds=1))
    assert status["outcome"] == "recorded"
    assert status["heartbeat_stale"] is False
    assert status["ledger_integrity_valid"] is True
