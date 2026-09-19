"""Fail-closed local execution gate for approved FLOP Airdrop actions.

The generic gate has no network transport, signer, Discord credential, process-spawn,
or action-specific credential capability. Production adapter registry is intentionally
empty in v1. Future adapters must be separately audited.

Safety model:
- one durable execution journal per approval request;
- exact Action Inbox + Staging candidate + Evidence Ledger binding;
- execution_prepared is persisted before any adapter is eligible to run;
- attempting is persisted before adapter.execute() is called;
- any unknown adapter exception becomes ambiguous and is never blindly retried;
- ambiguous/attempting states may only use adapter.reconcile(), which is required
  by contract to be read-only;
- Action Inbox is consumed only after a receipt has been verified and persisted.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from . import airdrop_action_stager, airdrop_approval, airdrop_ledger, core

SCHEMA_VERSION = 1
STATE_NAME = "action-executions.json"
LOCK_NAME = "action-executions.lock"
MAX_EXECUTIONS = 256

STATUSES = frozenset(
    {
        "execution_prepared",
        "attempting",
        "succeeded",
        "ambiguous",
        "failed_before_write",
        "blocked",
    }
)
PREPARABLE_CLASSES = frozenset(airdrop_action_stager.AUTO_STAGE_KEYS)
HEX24 = re.compile(r"^[0-9a-f]{24}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ADAPTER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,31}$")
RECEIPT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#=-]{0,239}$")


class AirdropExecutorError(RuntimeError):
    """Stable fail-closed executor error."""


class AdapterBeforeWriteError(RuntimeError):
    """Adapter explicitly proves no external write was attempted."""


class ExecutionAdapter(Protocol):
    adapter_id: str
    version: str
    action_classes: frozenset[str]

    def execute(self, plan: dict) -> object:
        """Perform one action attempt. Future real adapters are separately audited."""

    def verify_receipt(self, plan: dict, result: object) -> str:
        """Return one bounded verified receipt or raise."""

    def reconcile(self, plan: dict, journal: dict) -> object | None:
        """Read-only reconciliation. Return receipt material or None if unresolved."""


# Intentionally empty in v1. There is no public registration function.
# Tests may monkeypatch this private registry with fake adapters.
_ADAPTERS: dict[str, ExecutionAdapter] = {}


def executor_dir() -> Path:
    return core.STATE / "airdrop-radar"


def state_path() -> Path:
    return executor_dir() / STATE_NAME


@contextmanager
def _state_lock():
    directory = executor_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / LOCK_NAME
        with path.open("a+", encoding="utf-8") as handle:
            os.chmod(path, 0o640)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError as error:
        raise AirdropExecutorError("airdrop_executor_lock_failed") from error


def _utc(value: datetime | None = None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise AirdropExecutorError("airdrop_executor_timestamp_timezone_required")
    return current.astimezone(UTC).isoformat()


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise AirdropExecutorError("airdrop_executor_timestamp_invalid") from error
    if parsed.tzinfo is None:
        raise AirdropExecutorError("airdrop_executor_timestamp_timezone_required")
    return parsed.astimezone(UTC)


def _canonical(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise AirdropExecutorError("airdrop_executor_noncanonical_value") from error


def _default_state() -> dict:
    return {"schema_version": SCHEMA_VERSION, "executions": {}}


def _binding(record: dict) -> dict:
    return {
        "request_id": record["request_id"],
        "approval_digest": record["approval_digest"],
        "action_class": record["action_class"],
        "payload_sha256": record["payload_sha256"],
        "payload": record["payload"],
        "candidate_id": record["candidate_id"],
        "source_event_id": record["source_event_id"],
        "source_ledger_hash": record["source_ledger_hash"],
        "decision_actor": record["decision_actor"],
        "decision_at": record["decision_at"],
        "adapter_id": record["adapter_id"],
        "adapter_version": record["adapter_version"],
        "git_sha": record["git_sha"],
    }


def _plan_digest(binding: dict) -> str:
    return hashlib.sha256(_canonical(binding).encode("utf-8")).hexdigest()


def _validate_receipt(value: object) -> str:
    if not isinstance(value, str) or not RECEIPT_RE.fullmatch(value):
        raise AirdropExecutorError("airdrop_executor_receipt_invalid")
    return value


def _validate_record(request_id: str, record: object) -> dict:
    keys = {
        "request_id",
        "approval_digest",
        "action_class",
        "payload_sha256",
        "payload",
        "candidate_id",
        "source_event_id",
        "source_ledger_hash",
        "decision_actor",
        "decision_at",
        "adapter_id",
        "adapter_version",
        "git_sha",
        "plan_digest",
        "status",
        "prepared_at",
        "attempting_at",
        "terminal_at",
        "receipt",
        "error_code",
        "reconcile_count",
        "last_reconciled_at",
    }
    if not isinstance(record, dict) or set(record) != keys:
        raise AirdropExecutorError("airdrop_executor_record_invalid")
    if record.get("request_id") != request_id or not HEX32.fullmatch(request_id):
        raise AirdropExecutorError("airdrop_executor_record_invalid")
    if not isinstance(record.get("approval_digest"), str) or not HEX64.fullmatch(
        record["approval_digest"]
    ):
        raise AirdropExecutorError("airdrop_executor_record_invalid")
    if record.get("action_class") not in PREPARABLE_CLASSES:
        raise AirdropExecutorError("airdrop_executor_record_invalid")
    if not isinstance(record.get("payload_sha256"), str) or not HEX64.fullmatch(
        record["payload_sha256"]
    ):
        raise AirdropExecutorError("airdrop_executor_record_invalid")
    # Re-use the Staging Bridge validator for the exact secret-free payload rules.
    if airdrop_action_stager._payload_digest(record.get("payload")) != record["payload_sha256"]:
        raise AirdropExecutorError("airdrop_executor_payload_binding_mismatch")
    if not isinstance(record.get("candidate_id"), str) or not HEX32.fullmatch(
        record["candidate_id"]
    ):
        raise AirdropExecutorError("airdrop_executor_record_invalid")
    if not isinstance(record.get("source_event_id"), str) or not HEX24.fullmatch(
        record["source_event_id"]
    ):
        raise AirdropExecutorError("airdrop_executor_record_invalid")
    if not isinstance(record.get("source_ledger_hash"), str) or not HEX64.fullmatch(
        record["source_ledger_hash"]
    ):
        raise AirdropExecutorError("airdrop_executor_record_invalid")
    if not isinstance(record.get("decision_actor"), str) or not record[
        "decision_actor"
    ].isdecimal():
        raise AirdropExecutorError("airdrop_executor_record_invalid")
    _parse_utc(record["decision_at"])
    if not isinstance(record.get("adapter_id"), str) or not ADAPTER_ID_RE.fullmatch(
        record["adapter_id"]
    ):
        raise AirdropExecutorError("airdrop_executor_record_invalid")
    if not isinstance(record.get("adapter_version"), str) or not VERSION_RE.fullmatch(
        record["adapter_version"]
    ):
        raise AirdropExecutorError("airdrop_executor_record_invalid")
    if not isinstance(record.get("git_sha"), str) or not HEX40.fullmatch(
        record["git_sha"]
    ):
        raise AirdropExecutorError("airdrop_executor_record_invalid")
    if not isinstance(record.get("plan_digest"), str) or not HEX64.fullmatch(
        record["plan_digest"]
    ):
        raise AirdropExecutorError("airdrop_executor_record_invalid")
    if _plan_digest(_binding(record)) != record["plan_digest"]:
        raise AirdropExecutorError("airdrop_executor_plan_digest_mismatch")
    if record.get("status") not in STATUSES:
        raise AirdropExecutorError("airdrop_executor_record_invalid")
    _parse_utc(record["prepared_at"])
    for key in ("attempting_at", "terminal_at", "last_reconciled_at"):
        value = record.get(key)
        if value is not None:
            if not isinstance(value, str):
                raise AirdropExecutorError("airdrop_executor_record_invalid")
            _parse_utc(value)
    receipt = record.get("receipt")
    if receipt is not None:
        _validate_receipt(receipt)
    error_code = record.get("error_code")
    if error_code is not None and (
        not isinstance(error_code, str)
        or not 1 <= len(error_code) <= 120
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in error_code)
    ):
        raise AirdropExecutorError("airdrop_executor_record_invalid")
    if not isinstance(record.get("reconcile_count"), int) or not 0 <= record[
        "reconcile_count"
    ] <= 10_000:
        raise AirdropExecutorError("airdrop_executor_record_invalid")

    status = record["status"]
    attempting_at = record["attempting_at"]
    terminal_at = record["terminal_at"]
    if status == "execution_prepared":
        if any(
            value is not None
            for value in (
                attempting_at,
                terminal_at,
                receipt,
                error_code,
                record["last_reconciled_at"],
            )
        ) or record["reconcile_count"] != 0:
            raise AirdropExecutorError("airdrop_executor_record_invalid")
    elif status == "attempting":
        if attempting_at is None or terminal_at is not None or receipt is not None:
            raise AirdropExecutorError("airdrop_executor_record_invalid")
    elif status == "succeeded":
        if (
            attempting_at is None
            or terminal_at is None
            or receipt is None
            or error_code is not None
        ):
            raise AirdropExecutorError("airdrop_executor_record_invalid")
    elif status == "ambiguous":
        if attempting_at is None or terminal_at is not None or receipt is not None:
            raise AirdropExecutorError("airdrop_executor_record_invalid")
        if not error_code:
            raise AirdropExecutorError("airdrop_executor_record_invalid")
    elif status == "failed_before_write":
        if (
            attempting_at is None
            or terminal_at is None
            or receipt is not None
            or not error_code
        ):
            raise AirdropExecutorError("airdrop_executor_record_invalid")
    elif status == "blocked":
        if terminal_at is None or receipt is not None or not error_code:
            raise AirdropExecutorError("airdrop_executor_record_invalid")
    return record


def _atomic_write(value: dict) -> None:
    path = state_path()
    handle = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
            newline="\n",
        )
        with handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(handle.name, 0o640)
        os.replace(handle.name, path)
    except OSError as error:
        raise AirdropExecutorError("airdrop_executor_state_write_failed") from error
    finally:
        if handle is not None and os.path.exists(handle.name):
            try:
                os.unlink(handle.name)
            except OSError:
                pass


def _load_state() -> dict:
    path = state_path()
    if not path.exists():
        return _default_state()
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AirdropExecutorError("airdrop_executor_state_unreadable") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "executions"}
        or value.get("schema_version") != SCHEMA_VERSION
        or not isinstance(value.get("executions"), dict)
        or len(value["executions"]) > MAX_EXECUTIONS
    ):
        raise AirdropExecutorError("airdrop_executor_state_invalid")
    for request_id, record in value["executions"].items():
        _validate_record(request_id, record)
    return value


def _adapter(adapter_id: str) -> ExecutionAdapter:
    if not isinstance(adapter_id, str) or not ADAPTER_ID_RE.fullmatch(adapter_id):
        raise AirdropExecutorError("airdrop_executor_adapter_id_invalid")
    adapter = _ADAPTERS.get(adapter_id)
    if adapter is None:
        raise AirdropExecutorError("airdrop_executor_adapter_unavailable")
    if (
        getattr(adapter, "adapter_id", None) != adapter_id
        or not isinstance(getattr(adapter, "version", None), str)
        or not VERSION_RE.fullmatch(adapter.version)
        or not isinstance(getattr(adapter, "action_classes", None), frozenset)
        or not adapter.action_classes
        or not adapter.action_classes.issubset(PREPARABLE_CLASSES)
    ):
        raise AirdropExecutorError("airdrop_executor_adapter_contract_invalid")
    for method in ("execute", "verify_receipt", "reconcile"):
        if not callable(getattr(adapter, method, None)):
            raise AirdropExecutorError("airdrop_executor_adapter_contract_invalid")
    return adapter


def _canonical_ledger_record(event_id: str, ledger_hash: str) -> dict:
    verified = airdrop_ledger.verify_ledger()
    matches = [
        row
        for row in verified.get("records", [])
        if isinstance(row, dict) and row.get("event_id") == event_id
    ]
    if len(matches) != 1 or matches[0].get("hash") != ledger_hash:
        raise AirdropExecutorError("airdrop_executor_ledger_binding_mismatch")
    return matches[0]


def _source_binding(
    request_id: str,
    *,
    current: datetime,
    attempt_time: datetime | None = None,
) -> tuple[dict, dict, dict]:
    try:
        request = airdrop_approval.get_request(request_id, now=current)
    except airdrop_approval.ApprovalInboxError as error:
        raise AirdropExecutorError(str(error)) from error

    if request["action_class"] not in PREPARABLE_CLASSES:
        raise AirdropExecutorError("airdrop_executor_action_class_not_preparable")

    if attempt_time is None:
        if request["status"] != "approved":
            raise AirdropExecutorError(
                f"airdrop_executor_request_not_approved:{request['status']}"
            )
        validation_time = current
    else:
        validation_time = attempt_time
        if request["status"] not in {"approved", "expired"}:
            raise AirdropExecutorError(
                f"airdrop_executor_request_not_reconcilable:{request['status']}"
            )
        if request.get("decision_at") is None or request.get("decision_actor") is None:
            raise AirdropExecutorError("airdrop_executor_request_not_preapproved")
        decision_at = _parse_utc(request["decision_at"])
        expires_at = _parse_utc(request["expires_at"])
        if not decision_at <= attempt_time < expires_at:
            raise AirdropExecutorError(
                "airdrop_executor_attempt_outside_approval_window"
            )

    try:
        candidate = airdrop_action_stager.get_candidate_for_request(request_id)
    except airdrop_action_stager.StagingBridgeError as error:
        raise AirdropExecutorError(str(error)) from error

    expected_pairs = {
        "request_id": request["request_id"],
        "approval_digest": request["approval_digest"],
        "action_class": request["action_class"],
        "payload_sha256": request["payload_sha256"],
        "source_event_id": request["source_event_id"],
        "summary": request["summary"],
        "cost_note": request["cost_note"],
        "reversible": request["reversible"],
        "expires_at": request["expires_at"],
    }
    for key, expected in expected_pairs.items():
        if candidate.get(key) != expected:
            raise AirdropExecutorError(
                f"airdrop_executor_candidate_request_mismatch:{key}"
            )

    durable = _canonical_ledger_record(
        candidate["source_event_id"],
        candidate["source_ledger_hash"],
    )
    event = durable.get("event")
    raw = event.get("action_candidate") if isinstance(event, dict) else None
    try:
        normalized = airdrop_action_stager._validate_candidate(
            durable,
            raw,
            validation_time,
        )
    except airdrop_action_stager.StagingBridgeError as error:
        raise AirdropExecutorError(str(error)) from error

    for key in (
        "source_event_id",
        "source_ledger_hash",
        "action_class",
        "payload",
        "payload_sha256",
        "summary",
        "cost_note",
        "reversible",
        "expires_at",
    ):
        if normalized.get(key) != candidate.get(key):
            raise AirdropExecutorError(
                f"airdrop_executor_candidate_ledger_mismatch:{key}"
            )
    return request, candidate, durable


def preflight(
    request_id: str,
    *,
    adapter_id: str,
    git_sha: str,
    now: datetime | None = None,
) -> dict:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise AirdropExecutorError("airdrop_executor_timestamp_timezone_required")
    current = current.astimezone(UTC)
    if not isinstance(request_id, str) or not HEX32.fullmatch(request_id):
        raise AirdropExecutorError("airdrop_executor_request_id_invalid")
    if not isinstance(git_sha, str) or not HEX40.fullmatch(git_sha):
        raise AirdropExecutorError("airdrop_executor_git_sha_invalid")
    adapter = _adapter(adapter_id)
    request, candidate, _durable = _source_binding(
        request_id,
        current=current,
    )
    if request["action_class"] not in adapter.action_classes:
        raise AirdropExecutorError("airdrop_executor_adapter_action_mismatch")

    binding = {
        "request_id": request["request_id"],
        "approval_digest": request["approval_digest"],
        "action_class": request["action_class"],
        "payload_sha256": request["payload_sha256"],
        "payload": candidate["payload"],
        "candidate_id": candidate["candidate_id"],
        "source_event_id": candidate["source_event_id"],
        "source_ledger_hash": candidate["source_ledger_hash"],
        "decision_actor": request["decision_actor"],
        "decision_at": request["decision_at"],
        "adapter_id": adapter.adapter_id,
        "adapter_version": adapter.version,
        "git_sha": git_sha,
    }
    return {**binding, "plan_digest": _plan_digest(binding)}


def prepare_execution(
    request_id: str,
    *,
    adapter_id: str,
    git_sha: str,
    now: datetime | None = None,
) -> dict:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise AirdropExecutorError("airdrop_executor_timestamp_timezone_required")
    current = current.astimezone(UTC)
    plan = preflight(
        request_id,
        adapter_id=adapter_id,
        git_sha=git_sha,
        now=current,
    )
    record = {
        **plan,
        "status": "execution_prepared",
        "prepared_at": current.isoformat(),
        "attempting_at": None,
        "terminal_at": None,
        "receipt": None,
        "error_code": None,
        "reconcile_count": 0,
        "last_reconciled_at": None,
    }
    _validate_record(request_id, record)

    with _state_lock():
        state = _load_state()
        known = state["executions"].get(request_id)
        if known is not None:
            if known["plan_digest"] != record["plan_digest"]:
                raise AirdropExecutorError(
                    "airdrop_executor_existing_plan_binding_mismatch"
                )
            return json.loads(json.dumps(known))
        if len(state["executions"]) >= MAX_EXECUTIONS:
            raise AirdropExecutorError("airdrop_executor_capacity_exceeded")
        state["executions"][request_id] = record
        _atomic_write(state)
        return json.loads(json.dumps(record))


def get_execution(request_id: str) -> dict:
    if not isinstance(request_id, str) or not HEX32.fullmatch(request_id):
        raise AirdropExecutorError("airdrop_executor_request_id_invalid")
    with _state_lock():
        state = _load_state()
        record = state["executions"].get(request_id)
        if record is None:
            raise AirdropExecutorError("airdrop_executor_execution_not_found")
        return json.loads(json.dumps(record))


def _transition(
    request_id: str,
    *,
    expected_status: str,
    updates: dict,
) -> dict:
    with _state_lock():
        state = _load_state()
        record = state["executions"].get(request_id)
        if record is None:
            raise AirdropExecutorError("airdrop_executor_execution_not_found")
        if record["status"] != expected_status:
            raise AirdropExecutorError(
                f"airdrop_executor_state_conflict:{record['status']}"
            )
        for key, value in updates.items():
            record[key] = value
        _validate_record(request_id, record)
        _atomic_write(state)
        return json.loads(json.dumps(record))


def _block_prepared(request_id: str, error_code: str, current: datetime) -> dict:
    code = str(error_code)[:120] or "revalidation_failed"
    return _transition(
        request_id,
        expected_status="execution_prepared",
        updates={
            "status": "blocked",
            "terminal_at": current.isoformat(),
            "error_code": code,
        },
    )


def _plan_from_record(record: dict) -> dict:
    return {**_binding(record), "plan_digest": record["plan_digest"]}


def _ensure_consumed(record: dict, *, now: datetime) -> dict:
    if record["status"] != "succeeded" or record.get("receipt") is None:
        raise AirdropExecutorError("airdrop_executor_success_receipt_missing")
    try:
        airdrop_approval.consume_verified_execution(
            record["request_id"],
            record["approval_digest"],
            receipt=record["receipt"],
            attempted_at=record["attempting_at"],
            now=now,
        )
    except airdrop_approval.ApprovalInboxError as error:
        raise AirdropExecutorError(
            "airdrop_executor_success_recorded_consumption_pending"
        ) from error
    return record


def finalize_success(
    request_id: str,
    *,
    now: datetime | None = None,
) -> dict:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise AirdropExecutorError("airdrop_executor_timestamp_timezone_required")
    current = current.astimezone(UTC)
    record = get_execution(request_id)
    return _ensure_consumed(record, now=current)


def execute_prepared(
    request_id: str,
    *,
    now: datetime | None = None,
) -> dict:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise AirdropExecutorError("airdrop_executor_timestamp_timezone_required")
    current = current.astimezone(UTC)
    record = get_execution(request_id)

    if record["status"] == "succeeded":
        return _ensure_consumed(record, now=current)
    if record["status"] in {"attempting", "ambiguous"}:
        raise AirdropExecutorError("airdrop_executor_reconciliation_required")
    if record["status"] != "execution_prepared":
        raise AirdropExecutorError(
            f"airdrop_executor_not_executable:{record['status']}"
        )

    try:
        plan = preflight(
            request_id,
            adapter_id=record["adapter_id"],
            git_sha=record["git_sha"],
            now=current,
        )
        if plan["plan_digest"] != record["plan_digest"]:
            raise AirdropExecutorError(
                "airdrop_executor_prepared_plan_binding_mismatch"
            )
        adapter = _adapter(record["adapter_id"])
        if adapter.version != record["adapter_version"]:
            raise AirdropExecutorError(
                "airdrop_executor_adapter_version_changed"
            )
    except AirdropExecutorError as error:
        _block_prepared(request_id, str(error), current)
        raise

    attempting = _transition(
        request_id,
        expected_status="execution_prepared",
        updates={
            "status": "attempting",
            "attempting_at": current.isoformat(),
        },
    )
    plan = _plan_from_record(attempting)

    try:
        result = adapter.execute(json.loads(json.dumps(plan)))
    except AdapterBeforeWriteError as error:
        code = str(error)[:120] or "adapter_failed_before_write"
        return _transition(
            request_id,
            expected_status="attempting",
            updates={
                "status": "failed_before_write",
                "terminal_at": _utc(),
                "error_code": code,
            },
        )
    except Exception:
        _transition(
            request_id,
            expected_status="attempting",
            updates={
                "status": "ambiguous",
                "error_code": "adapter_exception_after_attempting",
            },
        )
        raise AirdropExecutorError("airdrop_executor_ambiguous") from None

    try:
        receipt = _validate_receipt(adapter.verify_receipt(plan, result))
    except Exception:
        _transition(
            request_id,
            expected_status="attempting",
            updates={
                "status": "ambiguous",
                "error_code": "receipt_unverified",
            },
        )
        raise AirdropExecutorError("airdrop_executor_ambiguous") from None

    succeeded = _transition(
        request_id,
        expected_status="attempting",
        updates={
            "status": "succeeded",
            "terminal_at": _utc(),
            "receipt": receipt,
            "error_code": None,
        },
    )
    return _ensure_consumed(succeeded, now=datetime.now(UTC))


def reconcile_execution(
    request_id: str,
    *,
    now: datetime | None = None,
) -> dict:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise AirdropExecutorError("airdrop_executor_timestamp_timezone_required")
    current = current.astimezone(UTC)
    record = get_execution(request_id)

    if record["status"] == "succeeded":
        return _ensure_consumed(record, now=current)
    if record["status"] not in {"attempting", "ambiguous"}:
        raise AirdropExecutorError(
            f"airdrop_executor_not_reconcilable:{record['status']}"
        )

    attempt_time = _parse_utc(record["attempting_at"])
    request, candidate, _durable = _source_binding(
        request_id,
        current=current,
        attempt_time=attempt_time,
    )
    plan = _plan_from_record(record)
    if (
        request["approval_digest"] != record["approval_digest"]
        or candidate["candidate_id"] != record["candidate_id"]
        or candidate["payload"] != record["payload"]
    ):
        raise AirdropExecutorError("airdrop_executor_reconcile_binding_mismatch")

    adapter = _adapter(record["adapter_id"])
    if (
        adapter.version != record["adapter_version"]
        or request["action_class"] not in adapter.action_classes
    ):
        raise AirdropExecutorError("airdrop_executor_reconcile_adapter_mismatch")

    try:
        result = adapter.reconcile(
            json.loads(json.dumps(plan)),
            json.loads(json.dumps(record)),
        )
    except Exception:
        result = None

    with _state_lock():
        state = _load_state()
        latest = state["executions"].get(request_id)
        if latest is None:
            raise AirdropExecutorError("airdrop_executor_execution_not_found")
        if latest["status"] not in {"attempting", "ambiguous"}:
            raise AirdropExecutorError(
                f"airdrop_executor_state_conflict:{latest['status']}"
            )
        latest["reconcile_count"] += 1
        latest["last_reconciled_at"] = current.isoformat()

        if result is None:
            latest["status"] = "ambiguous"
            latest["error_code"] = "reconcile_pending"
            _validate_record(request_id, latest)
            _atomic_write(state)
            return json.loads(json.dumps(latest))

    try:
        receipt = _validate_receipt(adapter.verify_receipt(plan, result))
    except Exception:
        with _state_lock():
            state = _load_state()
            latest = state["executions"].get(request_id)
            if latest is None or latest["status"] not in {"attempting", "ambiguous"}:
                raise AirdropExecutorError("airdrop_executor_state_conflict")
            latest["reconcile_count"] += 1
            latest["last_reconciled_at"] = current.isoformat()
            latest["status"] = "ambiguous"
            latest["error_code"] = "reconcile_receipt_unverified"
            _validate_record(request_id, latest)
            _atomic_write(state)
            return json.loads(json.dumps(latest))

    with _state_lock():
        state = _load_state()
        latest = state["executions"].get(request_id)
        if latest is None or latest["status"] not in {"attempting", "ambiguous"}:
            raise AirdropExecutorError("airdrop_executor_state_conflict")
        latest["reconcile_count"] += 1
        latest["last_reconciled_at"] = current.isoformat()
        latest["status"] = "succeeded"
        latest["terminal_at"] = current.isoformat()
        latest["receipt"] = receipt
        latest["error_code"] = None
        _validate_record(request_id, latest)
        _atomic_write(state)
        succeeded = json.loads(json.dumps(latest))
    return _ensure_consumed(succeeded, now=current)


def list_executions() -> list[dict]:
    with _state_lock():
        state = _load_state()
        rows = [
            json.loads(json.dumps(record))
            for record in state["executions"].values()
        ]
    rows.sort(key=lambda row: (row["prepared_at"], row["request_id"]))
    return rows
