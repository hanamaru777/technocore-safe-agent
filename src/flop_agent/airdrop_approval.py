"""Durable, local-only approval inbox for exact FLOP Airdrop actions.

An approval recorded here is not an external action. The inbox has no signer,
FLOP/Technocore/X transport, or value-moving capability. Future executors must
separately consume one exact approved request with the same payload digest.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from . import core

SCHEMA_VERSION = 1
STATE_NAME = "action-inbox.json"
MAX_REQUESTS = 256
NOTICE_LIMIT = 3
ACTION_CLASSES = frozenset(
    {"faucet", "registration", "challenge_submit", "x_post", "claim", "spend"}
)
STATUSES = frozenset({"pending", "approved", "rejected", "expired", "consumed"})
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_FAILURE_NOTIFIED = False


class ApprovalInboxError(RuntimeError):
    """Stable fail-closed approval-inbox error."""


def inbox_dir() -> Path:
    return core.STATE / "airdrop-radar"


def state_path() -> Path:
    return inbox_dir() / STATE_NAME


def _utc(value: datetime | None = None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("airdrop_approval_timestamp_timezone_required")
    return current.astimezone(UTC).isoformat()


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise ApprovalInboxError("airdrop_approval_timestamp_invalid") from error
    if parsed.tzinfo is None:
        raise ApprovalInboxError("airdrop_approval_timestamp_timezone_required")
    return parsed.astimezone(UTC)


def _safe_text(value: object, limit: int) -> str:
    text = CONTROL_RE.sub("", str(value if value is not None else ""))
    text = text.replace("@", "＠")
    text = " ".join(text.split()).strip()
    return text[:limit]


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _request_binding(
    *,
    action_class: str,
    payload_sha256: str,
    source_event_id: str,
    summary: str,
    cost_note: str,
    reversible: bool,
    expires_at: str,
) -> dict:
    return {
        "action_class": action_class,
        "payload_sha256": payload_sha256,
        "source_event_id": source_event_id,
        "summary": summary,
        "cost_note": cost_note,
        "reversible": reversible,
        "expires_at": expires_at,
    }


def _request_id(binding: dict) -> str:
    narrow = {
        key: binding[key]
        for key in ("action_class", "payload_sha256", "source_event_id", "expires_at")
    }
    return hashlib.sha256(_canonical(narrow).encode("utf-8")).hexdigest()[:32]


def _approval_digest(request_id: str, binding: dict) -> str:
    return hashlib.sha256(
        _canonical({"request_id": request_id, **binding}).encode("utf-8")
    ).hexdigest()


def _default_state() -> dict:
    return {"schema_version": SCHEMA_VERSION, "requests": {}}


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
        raise ApprovalInboxError("airdrop_approval_state_write_failed") from error
    finally:
        if handle is not None and os.path.exists(handle.name):
            try:
                os.unlink(handle.name)
            except OSError:
                pass


def _binding_from_record(record: dict) -> dict:
    return _request_binding(
        action_class=record["action_class"],
        payload_sha256=record["payload_sha256"],
        source_event_id=record["source_event_id"],
        summary=record["summary"],
        cost_note=record["cost_note"],
        reversible=record["reversible"],
        expires_at=record["expires_at"],
    )


def _validate_record(request_id: str, record: object) -> dict:
    keys = {
        "request_id",
        "action_class",
        "payload_sha256",
        "source_event_id",
        "summary",
        "cost_note",
        "reversible",
        "created_at",
        "expires_at",
        "approval_digest",
        "status",
        "notified_at",
        "decision_at",
        "decision_actor",
        "consumed_at",
        "consumption_receipt",
    }
    if not isinstance(record, dict) or set(record) != keys:
        raise ApprovalInboxError("airdrop_approval_record_invalid")
    if (
        record.get("request_id") != request_id
        or not HEX32.fullmatch(request_id)
        or record.get("action_class") not in ACTION_CLASSES
        or not isinstance(record.get("payload_sha256"), str)
        or not HEX64.fullmatch(record["payload_sha256"])
        or not isinstance(record.get("source_event_id"), str)
        or len(record["source_event_id"]) > 120
        or not isinstance(record.get("summary"), str)
        or not 1 <= len(record["summary"]) <= 500
        or not isinstance(record.get("cost_note"), str)
        or not 1 <= len(record["cost_note"]) <= 240
        or not isinstance(record.get("reversible"), bool)
        or record.get("status") not in STATUSES
        or not isinstance(record.get("approval_digest"), str)
        or not HEX64.fullmatch(record["approval_digest"])
    ):
        raise ApprovalInboxError("airdrop_approval_record_invalid")
    _parse_utc(record["created_at"])
    _parse_utc(record["expires_at"])
    for key in ("notified_at", "decision_at", "consumed_at"):
        value = record.get(key)
        if value is not None:
            if not isinstance(value, str):
                raise ApprovalInboxError("airdrop_approval_record_invalid")
            _parse_utc(value)
    actor = record.get("decision_actor")
    if actor is not None and (not isinstance(actor, str) or not actor.isdecimal()):
        raise ApprovalInboxError("airdrop_approval_record_invalid")
    receipt = record.get("consumption_receipt")
    if receipt is not None and (
        not isinstance(receipt, str) or not 1 <= len(receipt) <= 240
    ):
        raise ApprovalInboxError("airdrop_approval_record_invalid")

    binding = _binding_from_record(record)
    if _request_id(binding) != request_id:
        raise ApprovalInboxError("airdrop_approval_request_id_mismatch")
    if _approval_digest(request_id, binding) != record["approval_digest"]:
        raise ApprovalInboxError("airdrop_approval_digest_mismatch")
    return record


def _load_state() -> dict:
    path = state_path()
    if not path.exists():
        return _default_state()
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ApprovalInboxError("airdrop_approval_state_unreadable") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "requests"}
        or value.get("schema_version") != SCHEMA_VERSION
        or not isinstance(value.get("requests"), dict)
        or len(value["requests"]) > MAX_REQUESTS
    ):
        raise ApprovalInboxError("airdrop_approval_state_invalid")
    for request_id, record in value["requests"].items():
        _validate_record(request_id, record)
    return value


def _refresh_expired(state: dict, current: datetime) -> bool:
    changed = False
    for record in state["requests"].values():
        if record["status"] not in {"pending", "approved"}:
            continue
        if _parse_utc(record["expires_at"]) <= current:
            record["status"] = "expired"
            changed = True
    return changed


def stage_request(
    *,
    action_class: str,
    payload_sha256: str,
    source_event_id: str,
    summary: str,
    cost_note: str,
    reversible: bool,
    expires_at: datetime,
    now: datetime | None = None,
) -> dict:
    current = now or datetime.now(UTC)
    if current.tzinfo is None or expires_at.tzinfo is None:
        raise ValueError("airdrop_approval_timestamp_timezone_required")
    current = current.astimezone(UTC)
    expires_at = expires_at.astimezone(UTC)
    if action_class not in ACTION_CLASSES:
        raise ApprovalInboxError("airdrop_approval_action_class_invalid")
    if not isinstance(payload_sha256, str) or not HEX64.fullmatch(payload_sha256):
        raise ApprovalInboxError("airdrop_approval_payload_digest_invalid")
    source = _safe_text(source_event_id, 120)
    rendered_summary = _safe_text(summary, 500)
    rendered_cost = _safe_text(cost_note, 240)
    if not rendered_summary or not rendered_cost:
        raise ApprovalInboxError("airdrop_approval_presentation_invalid")
    if expires_at <= current:
        raise ApprovalInboxError("airdrop_approval_expiry_not_future")

    binding = _request_binding(
        action_class=action_class,
        payload_sha256=payload_sha256,
        source_event_id=source,
        summary=rendered_summary,
        cost_note=rendered_cost,
        reversible=reversible,
        expires_at=expires_at.isoformat(),
    )
    request_id = _request_id(binding)
    digest = _approval_digest(request_id, binding)

    state = _load_state()
    changed = _refresh_expired(state, current)
    known = state["requests"].get(request_id)
    if known is not None:
        if known["approval_digest"] != digest:
            raise ApprovalInboxError("airdrop_approval_existing_binding_mismatch")
        if changed:
            _atomic_write(state)
        return json.loads(json.dumps(known))

    if len(state["requests"]) >= MAX_REQUESTS:
        raise ApprovalInboxError("airdrop_approval_capacity_exceeded")
    record = {
        "request_id": request_id,
        **binding,
        "created_at": current.isoformat(),
        "approval_digest": digest,
        "status": "pending",
        "notified_at": None,
        "decision_at": None,
        "decision_actor": None,
        "consumed_at": None,
        "consumption_receipt": None,
    }
    _validate_record(request_id, record)
    state["requests"][request_id] = record
    _atomic_write(state)
    return json.loads(json.dumps(record))


def list_requests(*, now: datetime | None = None, pending_only: bool = False) -> list[dict]:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    state = _load_state()
    if _refresh_expired(state, current):
        _atomic_write(state)
    rows = [
        json.loads(json.dumps(record))
        for record in state["requests"].values()
        if not pending_only or record["status"] == "pending"
    ]
    rows.sort(key=lambda row: (row["expires_at"], row["request_id"]))
    return rows


def get_request(request_id: str, *, now: datetime | None = None) -> dict:
    if not isinstance(request_id, str) or not HEX32.fullmatch(request_id):
        raise ApprovalInboxError("airdrop_approval_request_id_invalid")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    state = _load_state()
    changed = _refresh_expired(state, current)
    record = state["requests"].get(request_id)
    if changed:
        _atomic_write(state)
    if record is None:
        raise ApprovalInboxError("airdrop_approval_request_not_found")
    return json.loads(json.dumps(record))


def decide(
    request_id: str,
    approval_digest: str,
    *,
    decision: str,
    actor_id: str,
    now: datetime | None = None,
) -> dict:
    if decision not in {"approved", "rejected"}:
        raise ApprovalInboxError("airdrop_approval_decision_invalid")
    if not isinstance(actor_id, str) or not actor_id.isdecimal():
        raise ApprovalInboxError("airdrop_approval_actor_invalid")
    if not isinstance(approval_digest, str) or not HEX64.fullmatch(approval_digest):
        raise ApprovalInboxError("airdrop_approval_digest_invalid")

    current = (now or datetime.now(UTC)).astimezone(UTC)
    state = _load_state()
    changed = _refresh_expired(state, current)
    record = state["requests"].get(request_id)
    if record is None:
        if changed:
            _atomic_write(state)
        raise ApprovalInboxError("airdrop_approval_request_not_found")
    if record["status"] != "pending":
        if changed:
            _atomic_write(state)
        raise ApprovalInboxError(f"airdrop_approval_not_pending:{record['status']}")
    if record["approval_digest"] != approval_digest:
        raise ApprovalInboxError("airdrop_approval_digest_mismatch")

    record["status"] = decision
    record["decision_at"] = current.isoformat()
    record["decision_actor"] = actor_id
    _atomic_write(state)
    return json.loads(json.dumps(record))


def consume(
    request_id: str,
    approval_digest: str,
    *,
    receipt: str,
    now: datetime | None = None,
) -> dict:
    if not isinstance(approval_digest, str) or not HEX64.fullmatch(approval_digest):
        raise ApprovalInboxError("airdrop_approval_digest_invalid")
    rendered_receipt = _safe_text(receipt, 240)
    if not rendered_receipt:
        raise ApprovalInboxError("airdrop_approval_receipt_invalid")

    current = (now or datetime.now(UTC)).astimezone(UTC)
    state = _load_state()
    changed = _refresh_expired(state, current)
    record = state["requests"].get(request_id)
    if record is None:
        if changed:
            _atomic_write(state)
        raise ApprovalInboxError("airdrop_approval_request_not_found")
    if record["approval_digest"] != approval_digest:
        raise ApprovalInboxError("airdrop_approval_digest_mismatch")
    if record["status"] != "approved":
        if changed:
            _atomic_write(state)
        raise ApprovalInboxError(f"airdrop_approval_not_approved:{record['status']}")

    record["status"] = "consumed"
    record["consumed_at"] = current.isoformat()
    record["consumption_receipt"] = rendered_receipt
    _atomic_write(state)
    return json.loads(json.dumps(record))


def render_request(record: dict) -> str:
    request_id = record["request_id"]
    digest = record["approval_digest"]
    lines = [
        "🟠 FLOP Airdrop Action Inbox",
        f"状態: {record['status']}",
        f"action: {record['action_class']}",
        f"内容: {record['summary']}",
        f"費用/価値: {record['cost_note']}",
        f"取り消し: {'可能' if record['reversible'] else '不可/保証なし'}",
        f"期限: {record['expires_at']}",
        f"source event: {record['source_event_id'] or 'none'}",
        f"payload sha256: {record['payload_sha256']}",
        f"request id: {request_id}",
        f"approval digest: {digest}",
    ]
    if record["status"] == "pending":
        lines.extend(
            [
                "",
                "承認する場合:",
                f"/airdrop-approve {request_id} {digest} APPROVE",
                "拒否する場合:",
                f"/airdrop-reject {request_id} {digest} REJECT",
                "",
                "重要: ここでの承認はローカル記録だけです。署名・送信・Claim・支払いは実行しません。",
            ]
        )
    elif record["status"] == "approved":
        lines.append("承認済み。まだ外部実行はされていません。")
    elif record["status"] == "consumed":
        lines.append("この承認は消費済みで再利用できません。")
    return "\n".join(lines)


def pending_message(*, now: datetime | None = None) -> str:
    rows = list_requests(now=now, pending_only=True)
    if not rows:
        return "🟢 FLOP Airdrop Action Inbox\n\n承認待ちはありません。"
    lines = ["🟠 FLOP Airdrop Action Inbox", "", f"承認待ち: {len(rows)}件"]
    for row in rows[:10]:
        lines.append(
            f"・{row['request_id']} | {row['action_class']} | {row['summary'][:100]} | 期限 {row['expires_at']}"
        )
    if len(rows) > 10:
        lines.append(f"・ほか {len(rows) - 10}件")
    lines.append("\n詳細: /airdrop-approval <request-id>")
    return "\n".join(lines)


def poll_notices(*, now: datetime | None = None) -> list[str]:
    global _FAILURE_NOTIFIED
    current = (now or datetime.now(UTC)).astimezone(UTC)
    try:
        state = _load_state()
        changed = _refresh_expired(state, current)
        rows = [
            record
            for record in state["requests"].values()
            if record["status"] == "pending" and record["notified_at"] is None
        ]
        rows.sort(key=lambda row: (row["expires_at"], row["request_id"]))
        notices = []
        for record in rows[:NOTICE_LIMIT]:
            notices.append(render_request(record))
            record["notified_at"] = current.isoformat()
            changed = True
        if changed:
            _atomic_write(state)
    except ApprovalInboxError:
        if _FAILURE_NOTIFIED:
            return []
        _FAILURE_NOTIFIED = True
        return [
            "🔴 FLOP Airdrop Action Inbox異常\n"
            "承認状態を安全に扱えないためfail-closedです。外部実行は行っていません。"
        ]
    _FAILURE_NOTIFIED = False
    return notices
