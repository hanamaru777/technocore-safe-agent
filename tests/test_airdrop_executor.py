from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from flop_agent import (
    airdrop_action_stager,
    airdrop_approval,
    airdrop_executor,
    airdrop_ledger,
    core,
)


T0 = datetime(2026, 9, 19, 0, 0, tzinfo=UTC)
GIT_SHA = "a" * 40


@pytest.fixture
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setattr(airdrop_approval, "_FAILURE_NOTIFIED", False)
    monkeypatch.setattr(airdrop_executor, "_ADAPTERS", {})
    return tmp_path


def durable(
    *,
    action_class: str = "registration",
    expires_at: datetime | None = None,
) -> dict:
    key = {
        "registration": "registration_status",
        "faucet": "faucet_status",
        "claim": "claim_status",
    }[action_class]
    event_id = hashlib.sha256(f"{action_class}:{key}".encode()).hexdigest()[:24]
    event = {
        "event_id": event_id,
        "type": "CHANGED",
        "key": key,
        "severity": "ACTION_NOW",
        "before": {"value": "closed"},
        "after": {"value": "open"},
        "action_candidate": {
            "schema_version": 1,
            "action_class": action_class,
            "payload": {
                "action": action_class,
                "subject": "did:flop:maru",
                "url": f"https://flop.finance/{action_class}",
            },
            "summary": f"Execute exact {action_class} action.",
            "cost_note": "0 FLOP / no real-value spend",
            "reversible": False,
            "expires_at": (expires_at or T0 + timedelta(hours=2)).isoformat(),
        },
    }
    row = {
        "schema_version": 1,
        "sequence": 1,
        "record_type": "material_event",
        "event_id": event_id,
        "first_seen": T0.isoformat(),
        "last_seen": T0.isoformat(),
        "observed_at": T0.isoformat(),
        "previous_hash": "",
        "event": event,
        "source_evidence": [
            {
                "observation": "current",
                "name": "home",
                "url": "https://flop.finance/",
                "final_url": "https://flop.finance/",
                "tier": 1,
                "authority": "official",
                "status": "ok",
                "content_sha256": "b" * 64,
            }
        ],
    }
    basis = {k: v for k, v in row.items() if k != "hash"}
    row["hash"] = hashlib.sha256(
        json.dumps(
            basis,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return row


def patch_ledger(monkeypatch: pytest.MonkeyPatch, rows: list[dict]) -> None:
    monkeypatch.setattr(
        airdrop_ledger,
        "verify_ledger",
        lambda: {
            "valid": True,
            "count": len(rows),
            "tip_hash": rows[-1]["hash"] if rows else "",
            "records": rows,
        },
    )


def approved_request(
    monkeypatch: pytest.MonkeyPatch,
    *,
    action_class: str = "registration",
    expires_at: datetime | None = None,
) -> tuple[dict, dict]:
    row = durable(action_class=action_class, expires_at=expires_at)
    patch_ledger(monkeypatch, [row])
    staged = airdrop_action_stager.stage_new_events(
        [row["event_id"]],
        {row["event_id"]: row},
        now=T0,
    )["staged"][0]
    approved = airdrop_approval.decide(
        staged["request_id"],
        staged["approval_digest"],
        decision="approved",
        actor_id="42",
        now=T0 + timedelta(minutes=1),
    )
    return row, approved


class SuccessAdapter:
    adapter_id = "test.success"
    version = "1"
    action_classes = frozenset({"registration"})

    def __init__(self) -> None:
        self.execute_calls = 0
        self.reconcile_calls = 0

    def execute(self, plan: dict) -> object:
        self.execute_calls += 1
        # This is the critical ordering assertion: attempting is durable before
        # any adapter write-capable method is entered.
        journal = airdrop_executor.get_execution(plan["request_id"])
        assert journal["status"] == "attempting"
        assert journal["attempting_at"] is not None
        return {"receipt": "receipt:registration:123"}

    def verify_receipt(self, plan: dict, result: object) -> str:
        assert isinstance(result, dict)
        return str(result["receipt"])

    def reconcile(self, plan: dict, journal: dict) -> object | None:
        self.reconcile_calls += 1
        return None


class BeforeWriteAdapter(SuccessAdapter):
    adapter_id = "test.before-write"

    def execute(self, plan: dict) -> object:
        self.execute_calls += 1
        assert airdrop_executor.get_execution(plan["request_id"])["status"] == "attempting"
        raise airdrop_executor.AdapterBeforeWriteError("precondition_failed")


class AmbiguousAdapter(SuccessAdapter):
    adapter_id = "test.ambiguous"

    def __init__(self) -> None:
        super().__init__()
        self.reconcile_result: object | None = None

    def execute(self, plan: dict) -> object:
        self.execute_calls += 1
        assert airdrop_executor.get_execution(plan["request_id"])["status"] == "attempting"
        raise RuntimeError("transport outcome unknown")

    def reconcile(self, plan: dict, journal: dict) -> object | None:
        self.reconcile_calls += 1
        assert journal["status"] in {"attempting", "ambiguous"}
        return self.reconcile_result


class BadReceiptAdapter(SuccessAdapter):
    adapter_id = "test.bad-receipt"

    def verify_receipt(self, plan: dict, result: object) -> str:
        return "receipt with spaces is not allowed"


def install_adapter(monkeypatch: pytest.MonkeyPatch, adapter) -> None:
    monkeypatch.setattr(
        airdrop_executor,
        "_ADAPTERS",
        {adapter.adapter_id: adapter},
    )


def test_production_registry_is_empty_by_default() -> None:
    source = (
        core.ROOT / "src" / "flop_agent" / "airdrop_executor.py"
    ).read_text("utf-8")
    assert "_ADAPTERS: dict[str, ExecutionAdapter] = {}" in source


def test_preflight_is_read_only_and_exactly_bound(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row, approved = approved_request(monkeypatch)
    adapter = SuccessAdapter()
    install_adapter(monkeypatch, adapter)

    plan = airdrop_executor.preflight(
        approved["request_id"],
        adapter_id=adapter.adapter_id,
        git_sha=GIT_SHA,
        now=T0 + timedelta(minutes=2),
    )

    candidate = airdrop_action_stager.get_candidate_for_request(
        approved["request_id"]
    )
    assert plan["approval_digest"] == approved["approval_digest"]
    assert plan["payload_sha256"] == approved["payload_sha256"]
    assert plan["payload"] == candidate["payload"]
    assert plan["candidate_id"] == candidate["candidate_id"]
    assert plan["source_event_id"] == row["event_id"]
    assert plan["source_ledger_hash"] == row["hash"]
    assert plan["decision_actor"] == "42"
    assert plan["adapter_id"] == "test.success"
    assert plan["adapter_version"] == "1"
    assert plan["git_sha"] == GIT_SHA
    assert not airdrop_executor.state_path().exists()
    assert airdrop_approval.get_request(
        approved["request_id"],
        now=T0 + timedelta(minutes=2),
    )["status"] == "approved"


def test_empty_registry_blocks_without_journal_or_consumption(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _row, approved = approved_request(monkeypatch)

    with pytest.raises(
        airdrop_executor.AirdropExecutorError,
        match="adapter_unavailable",
    ):
        airdrop_executor.prepare_execution(
            approved["request_id"],
            adapter_id="real.registration",
            git_sha=GIT_SHA,
            now=T0 + timedelta(minutes=2),
        )

    assert not airdrop_executor.state_path().exists()
    assert airdrop_approval.get_request(
        approved["request_id"],
        now=T0 + timedelta(minutes=2),
    )["status"] == "approved"


def test_prepare_is_durable_idempotent_and_mode_640(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _row, approved = approved_request(monkeypatch)
    adapter = SuccessAdapter()
    install_adapter(monkeypatch, adapter)

    first = airdrop_executor.prepare_execution(
        approved["request_id"],
        adapter_id=adapter.adapter_id,
        git_sha=GIT_SHA,
        now=T0 + timedelta(minutes=2),
    )
    second = airdrop_executor.prepare_execution(
        approved["request_id"],
        adapter_id=adapter.adapter_id,
        git_sha=GIT_SHA,
        now=T0 + timedelta(minutes=3),
    )

    assert first == second
    assert first["status"] == "execution_prepared"
    assert len(first["plan_digest"]) == 64
    assert airdrop_executor.state_path().stat().st_mode & 0o777 == 0o640


def test_success_attempts_once_then_consumes_only_verified_receipt(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _row, approved = approved_request(monkeypatch)
    adapter = SuccessAdapter()
    install_adapter(monkeypatch, adapter)

    airdrop_executor.prepare_execution(
        approved["request_id"],
        adapter_id=adapter.adapter_id,
        git_sha=GIT_SHA,
        now=T0 + timedelta(minutes=2),
    )
    result = airdrop_executor.execute_prepared(
        approved["request_id"],
        now=T0 + timedelta(minutes=3),
    )

    assert adapter.execute_calls == 1
    assert result["status"] == "succeeded"
    assert result["receipt"] == "receipt:registration:123"
    approval = airdrop_approval.get_request(
        approved["request_id"],
        now=T0 + timedelta(minutes=4),
    )
    assert approval["status"] == "consumed"
    assert approval["consumption_receipt"] == result["receipt"]

    # A second call performs only local finalization/idempotency, never adapter.execute.
    again = airdrop_executor.execute_prepared(
        approved["request_id"],
        now=T0 + timedelta(minutes=5),
    )
    assert again["status"] == "succeeded"
    assert adapter.execute_calls == 1


def test_before_write_failure_is_terminal_and_does_not_consume(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _row, approved = approved_request(monkeypatch)
    adapter = BeforeWriteAdapter()
    install_adapter(monkeypatch, adapter)

    airdrop_executor.prepare_execution(
        approved["request_id"],
        adapter_id=adapter.adapter_id,
        git_sha=GIT_SHA,
        now=T0 + timedelta(minutes=2),
    )
    result = airdrop_executor.execute_prepared(
        approved["request_id"],
        now=T0 + timedelta(minutes=3),
    )

    assert result["status"] == "failed_before_write"
    assert result["error_code"] == "precondition_failed"
    assert adapter.execute_calls == 1
    assert airdrop_approval.get_request(
        approved["request_id"],
        now=T0 + timedelta(minutes=4),
    )["status"] == "approved"

    with pytest.raises(
        airdrop_executor.AirdropExecutorError,
        match="not_executable:failed_before_write",
    ):
        airdrop_executor.execute_prepared(
            approved["request_id"],
            now=T0 + timedelta(minutes=5),
        )
    assert adapter.execute_calls == 1


def test_unknown_exception_becomes_ambiguous_and_never_blind_retries(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _row, approved = approved_request(monkeypatch)
    adapter = AmbiguousAdapter()
    install_adapter(monkeypatch, adapter)

    airdrop_executor.prepare_execution(
        approved["request_id"],
        adapter_id=adapter.adapter_id,
        git_sha=GIT_SHA,
        now=T0 + timedelta(minutes=2),
    )
    with pytest.raises(
        airdrop_executor.AirdropExecutorError,
        match="airdrop_executor_ambiguous",
    ):
        airdrop_executor.execute_prepared(
            approved["request_id"],
            now=T0 + timedelta(minutes=3),
        )

    journal = airdrop_executor.get_execution(approved["request_id"])
    assert journal["status"] == "ambiguous"
    assert adapter.execute_calls == 1
    assert airdrop_approval.get_request(
        approved["request_id"],
        now=T0 + timedelta(minutes=4),
    )["status"] == "approved"

    with pytest.raises(
        airdrop_executor.AirdropExecutorError,
        match="reconciliation_required",
    ):
        airdrop_executor.execute_prepared(
            approved["request_id"],
            now=T0 + timedelta(minutes=5),
        )
    assert adapter.execute_calls == 1

    unresolved = airdrop_executor.reconcile_execution(
        approved["request_id"],
        now=T0 + timedelta(minutes=6),
    )
    assert unresolved["status"] == "ambiguous"
    assert unresolved["reconcile_count"] == 1
    assert adapter.reconcile_calls == 1
    assert adapter.execute_calls == 1


def test_read_only_reconcile_success_consumes_without_second_execute(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expires = T0 + timedelta(minutes=5)
    _row, approved = approved_request(monkeypatch, expires_at=expires)
    adapter = AmbiguousAdapter()
    install_adapter(monkeypatch, adapter)

    airdrop_executor.prepare_execution(
        approved["request_id"],
        adapter_id=adapter.adapter_id,
        git_sha=GIT_SHA,
        now=T0 + timedelta(minutes=2),
    )
    with pytest.raises(airdrop_executor.AirdropExecutorError):
        airdrop_executor.execute_prepared(
            approved["request_id"],
            now=T0 + timedelta(minutes=3),
        )

    # The approval expires after the attempt. A later read-only reconciliation may
    # still finalize that already-started attempt, but may never perform a new write.
    adapter.reconcile_result = {"receipt": "receipt:registration:late"}
    result = airdrop_executor.reconcile_execution(
        approved["request_id"],
        now=T0 + timedelta(minutes=10),
    )

    assert result["status"] == "succeeded"
    assert result["receipt"] == "receipt:registration:late"
    assert adapter.execute_calls == 1
    assert adapter.reconcile_calls == 1
    approval = airdrop_approval.get_request(
        approved["request_id"],
        now=T0 + timedelta(minutes=10),
    )
    assert approval["status"] == "consumed"
    assert approval["consumption_receipt"] == result["receipt"]


def test_unverified_receipt_is_ambiguous_and_unconsumed(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _row, approved = approved_request(monkeypatch)
    adapter = BadReceiptAdapter()
    install_adapter(monkeypatch, adapter)

    airdrop_executor.prepare_execution(
        approved["request_id"],
        adapter_id=adapter.adapter_id,
        git_sha=GIT_SHA,
        now=T0 + timedelta(minutes=2),
    )
    with pytest.raises(
        airdrop_executor.AirdropExecutorError,
        match="airdrop_executor_ambiguous",
    ):
        airdrop_executor.execute_prepared(
            approved["request_id"],
            now=T0 + timedelta(minutes=3),
        )

    assert airdrop_executor.get_execution(
        approved["request_id"]
    )["status"] == "ambiguous"
    assert airdrop_approval.get_request(
        approved["request_id"],
        now=T0 + timedelta(minutes=4),
    )["status"] == "approved"


def test_concurrent_second_execute_observes_attempting_not_a_second_write(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _row, approved = approved_request(monkeypatch)

    class ReentrantAdapter(SuccessAdapter):
        adapter_id = "test.reentrant"

        def execute(self, plan: dict) -> object:
            self.execute_calls += 1
            assert airdrop_executor.get_execution(plan["request_id"])["status"] == "attempting"
            with pytest.raises(
                airdrop_executor.AirdropExecutorError,
                match="reconciliation_required",
            ):
                airdrop_executor.execute_prepared(
                    plan["request_id"],
                    now=T0 + timedelta(minutes=3),
                )
            return {"receipt": "receipt:registration:single"}

    adapter = ReentrantAdapter()
    install_adapter(monkeypatch, adapter)
    airdrop_executor.prepare_execution(
        approved["request_id"],
        adapter_id=adapter.adapter_id,
        git_sha=GIT_SHA,
        now=T0 + timedelta(minutes=2),
    )

    result = airdrop_executor.execute_prepared(
        approved["request_id"],
        now=T0 + timedelta(minutes=3),
    )
    assert result["status"] == "succeeded"
    assert adapter.execute_calls == 1


def test_candidate_tamper_blocks_before_adapter_call(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _row, approved = approved_request(monkeypatch)
    adapter = SuccessAdapter()
    install_adapter(monkeypatch, adapter)
    airdrop_executor.prepare_execution(
        approved["request_id"],
        adapter_id=adapter.adapter_id,
        git_sha=GIT_SHA,
        now=T0 + timedelta(minutes=2),
    )

    store_path = airdrop_action_stager.store_path()
    store = json.loads(store_path.read_text("utf-8"))
    candidate = next(iter(store["candidates"].values()))
    candidate["payload"]["subject"] = "did:flop:tampered"
    store_path.write_text(json.dumps(store), encoding="utf-8")

    with pytest.raises(airdrop_executor.AirdropExecutorError):
        airdrop_executor.execute_prepared(
            approved["request_id"],
            now=T0 + timedelta(minutes=3),
        )

    journal = airdrop_executor.get_execution(approved["request_id"])
    assert journal["status"] == "blocked"
    assert adapter.execute_calls == 0
    assert airdrop_approval.get_request(
        approved["request_id"],
        now=T0 + timedelta(minutes=4),
    )["status"] == "approved"


def test_ledger_hash_mismatch_blocks_preflight_without_journal(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row, approved = approved_request(monkeypatch)
    adapter = SuccessAdapter()
    install_adapter(monkeypatch, adapter)

    altered = json.loads(json.dumps(row))
    altered["hash"] = "f" * 64
    patch_ledger(monkeypatch, [altered])

    with pytest.raises(
        airdrop_executor.AirdropExecutorError,
        match="ledger_binding_mismatch",
    ):
        airdrop_executor.prepare_execution(
            approved["request_id"],
            adapter_id=adapter.adapter_id,
            git_sha=GIT_SHA,
            now=T0 + timedelta(minutes=2),
        )
    assert not airdrop_executor.state_path().exists()


def test_pending_rejected_expired_and_consumed_requests_do_not_prepare(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = SuccessAdapter()
    install_adapter(monkeypatch, adapter)

    row = durable()
    patch_ledger(monkeypatch, [row])
    staged = airdrop_action_stager.stage_new_events(
        [row["event_id"]],
        {row["event_id"]: row},
        now=T0,
    )["staged"][0]

    with pytest.raises(
        airdrop_executor.AirdropExecutorError,
        match="request_not_approved:pending",
    ):
        airdrop_executor.prepare_execution(
            staged["request_id"],
            adapter_id=adapter.adapter_id,
            git_sha=GIT_SHA,
            now=T0 + timedelta(minutes=1),
        )

    airdrop_approval.decide(
        staged["request_id"],
        staged["approval_digest"],
        decision="rejected",
        actor_id="42",
        now=T0 + timedelta(minutes=2),
    )
    with pytest.raises(
        airdrop_executor.AirdropExecutorError,
        match="request_not_approved:rejected",
    ):
        airdrop_executor.prepare_execution(
            staged["request_id"],
            adapter_id=adapter.adapter_id,
            git_sha=GIT_SHA,
            now=T0 + timedelta(minutes=3),
        )


def test_expired_and_consumed_requests_do_not_prepare(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = SuccessAdapter()
    install_adapter(monkeypatch, adapter)

    _row, approved = approved_request(
        monkeypatch,
        expires_at=T0 + timedelta(minutes=5),
    )
    expired = airdrop_approval.get_request(
        approved["request_id"],
        now=T0 + timedelta(minutes=10),
    )
    assert expired["status"] == "expired"

    with pytest.raises(
        airdrop_executor.AirdropExecutorError,
        match="request_not_approved:expired",
    ):
        airdrop_executor.prepare_execution(
            approved["request_id"],
            adapter_id=adapter.adapter_id,
            git_sha=GIT_SHA,
            now=T0 + timedelta(minutes=10),
        )

    # A separate request is consumed through the normal local-only API.
    row2 = durable(action_class="claim")
    patch_ledger(monkeypatch, [row2])
    staged2 = airdrop_action_stager.stage_new_events(
        [row2["event_id"]],
        {row2["event_id"]: row2},
        now=T0,
    )["staged"][0]
    approved2 = airdrop_approval.decide(
        staged2["request_id"],
        staged2["approval_digest"],
        decision="approved",
        actor_id="42",
        now=T0 + timedelta(minutes=1),
    )
    airdrop_approval.consume(
        approved2["request_id"],
        approved2["approval_digest"],
        receipt="receipt:already:consumed",
        now=T0 + timedelta(minutes=2),
    )

    class ClaimAdapter(SuccessAdapter):
        adapter_id = "test.claim"
        action_classes = frozenset({"claim"})

    claim_adapter = ClaimAdapter()
    install_adapter(monkeypatch, claim_adapter)
    with pytest.raises(
        airdrop_executor.AirdropExecutorError,
        match="request_not_approved:consumed",
    ):
        airdrop_executor.prepare_execution(
            approved2["request_id"],
            adapter_id=claim_adapter.adapter_id,
            git_sha=GIT_SHA,
            now=T0 + timedelta(minutes=3),
        )


def test_success_journal_persists_before_local_consumption_retry(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _row, approved = approved_request(monkeypatch)
    adapter = SuccessAdapter()
    install_adapter(monkeypatch, adapter)

    airdrop_executor.prepare_execution(
        approved["request_id"],
        adapter_id=adapter.adapter_id,
        git_sha=GIT_SHA,
        now=T0 + timedelta(minutes=2),
    )

    original = airdrop_approval.consume_verified_execution
    calls = {"count": 0}

    def fail_once(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise airdrop_approval.ApprovalInboxError("simulated_local_persist_failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(
        airdrop_approval,
        "consume_verified_execution",
        fail_once,
    )

    with pytest.raises(
        airdrop_executor.AirdropExecutorError,
        match="success_recorded_consumption_pending",
    ):
        airdrop_executor.execute_prepared(
            approved["request_id"],
            now=T0 + timedelta(minutes=3),
        )

    journal = airdrop_executor.get_execution(approved["request_id"])
    assert journal["status"] == "succeeded"
    assert journal["receipt"] == "receipt:registration:123"
    assert adapter.execute_calls == 1
    assert airdrop_approval.get_request(
        approved["request_id"],
        now=T0 + timedelta(minutes=4),
    )["status"] == "approved"

    repaired = airdrop_executor.finalize_success(
        approved["request_id"],
        now=T0 + timedelta(minutes=5),
    )
    assert repaired["status"] == "succeeded"
    assert adapter.execute_calls == 1
    assert airdrop_approval.get_request(
        approved["request_id"],
        now=T0 + timedelta(minutes=5),
    )["status"] == "consumed"


def test_adapter_version_drift_blocks_before_write(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _row, approved = approved_request(monkeypatch)
    adapter = SuccessAdapter()
    install_adapter(monkeypatch, adapter)

    airdrop_executor.prepare_execution(
        approved["request_id"],
        adapter_id=adapter.adapter_id,
        git_sha=GIT_SHA,
        now=T0 + timedelta(minutes=2),
    )
    adapter.version = "2"

    with pytest.raises(airdrop_executor.AirdropExecutorError):
        airdrop_executor.execute_prepared(
            approved["request_id"],
            now=T0 + timedelta(minutes=3),
        )

    journal = airdrop_executor.get_execution(approved["request_id"])
    assert journal["status"] == "blocked"
    assert adapter.execute_calls == 0


def test_ambiguous_reconcile_refuses_external_consumption_mismatch(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _row, approved = approved_request(monkeypatch)
    adapter = AmbiguousAdapter()
    install_adapter(monkeypatch, adapter)

    airdrop_executor.prepare_execution(
        approved["request_id"],
        adapter_id=adapter.adapter_id,
        git_sha=GIT_SHA,
        now=T0 + timedelta(minutes=2),
    )
    with pytest.raises(airdrop_executor.AirdropExecutorError):
        airdrop_executor.execute_prepared(
            approved["request_id"],
            now=T0 + timedelta(minutes=3),
        )

    # Local consumption from any other path invalidates this ambiguous journal.
    airdrop_approval.consume(
        approved["request_id"],
        approved["approval_digest"],
        receipt="receipt:other:path",
        now=T0 + timedelta(minutes=4),
    )
    with pytest.raises(
        airdrop_executor.AirdropExecutorError,
        match="request_not_reconcilable:consumed",
    ):
        airdrop_executor.reconcile_execution(
            approved["request_id"],
            now=T0 + timedelta(minutes=5),
        )
    assert adapter.reconcile_calls == 0
    assert adapter.execute_calls == 1


def test_approval_verified_execution_consumption_requires_attempt_inside_window(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _row, approved = approved_request(
        monkeypatch,
        expires_at=T0 + timedelta(minutes=5),
    )
    # Force normal approved -> expired transition first.
    assert airdrop_approval.get_request(
        approved["request_id"],
        now=T0 + timedelta(minutes=10),
    )["status"] == "expired"

    with pytest.raises(
        airdrop_approval.ApprovalInboxError,
        match="attempt_outside_approval_window",
    ):
        airdrop_approval.consume_verified_execution(
            approved["request_id"],
            approved["approval_digest"],
            receipt="receipt:test:late-start",
            attempted_at=(T0 + timedelta(minutes=6)).isoformat(),
            now=T0 + timedelta(minutes=10),
        )

    consumed = airdrop_approval.consume_verified_execution(
        approved["request_id"],
        approved["approval_digest"],
        receipt="receipt:test:valid-start",
        attempted_at=(T0 + timedelta(minutes=3)).isoformat(),
        now=T0 + timedelta(minutes=10),
    )
    assert consumed["status"] == "consumed"


def test_generic_gate_has_no_transport_signer_shell_or_socket_capability() -> None:
    source = (
        core.ROOT / "src" / "flop_agent" / "airdrop_executor.py"
    ).read_text("utf-8").lower()
    for forbidden in (
        "httpx",
        "requests",
        "urllib.request",
        "oracle_signer",
        "technocore_signing_key",
        "discord_bot_token",
        "subprocess",
        "socket",
        "client.post",
        "client.put",
        "client.patch",
        "client.delete",
    ):
        assert forbidden not in source


def test_manual_nonstaged_action_classes_cannot_use_generic_gate(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manual = airdrop_approval.stage_request(
        action_class="x_post",
        payload_sha256="c" * 64,
        source_event_id="manual-x",
        summary="Manual X post.",
        cost_note="No execution.",
        reversible=False,
        expires_at=T0 + timedelta(hours=1),
        now=T0,
    )
    approved = airdrop_approval.decide(
        manual["request_id"],
        manual["approval_digest"],
        decision="approved",
        actor_id="42",
        now=T0 + timedelta(minutes=1),
    )

    class XAdapter(SuccessAdapter):
        adapter_id = "test.x"
        action_classes = frozenset({"x_post"})

    monkeypatch.setattr(
        airdrop_executor,
        "_ADAPTERS",
        {XAdapter.adapter_id: XAdapter()},
    )
    with pytest.raises(
        airdrop_executor.AirdropExecutorError,
        match="adapter_contract_invalid|action_class_not_preparable",
    ):
        airdrop_executor.prepare_execution(
            approved["request_id"],
            adapter_id=XAdapter.adapter_id,
            git_sha=GIT_SHA,
            now=T0 + timedelta(minutes=2),
        )
