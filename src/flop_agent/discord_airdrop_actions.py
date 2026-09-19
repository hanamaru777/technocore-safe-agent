"""Discord interaction policy for exact FLOP Airdrop Action Inbox requests.

This module has no Discord token/client and no external execution capability.
It maps one bounded component custom_id to one existing durable approval request,
reloads and validates that request (and its staged candidate when applicable),
then records only a local approval/rejection decision.
"""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime

from . import airdrop_action_stager, airdrop_approval, airdrop_ledger

CUSTOM_PREFIX = "flop-airdrop"
CUSTOM_ID_RE = re.compile(
    r"^flop-airdrop:(details|approve|reject):([0-9a-f]{32})$"
)
MAX_DETAIL_CHARS = 12_000


class DiscordAirdropActionError(RuntimeError):
    """Stable fail-closed Discord Action Inbox interaction error."""


def custom_id(action: str, request_id: str) -> str:
    value = f"{CUSTOM_PREFIX}:{action}:{request_id}"
    if not CUSTOM_ID_RE.fullmatch(value) or len(value) > 100:
        raise DiscordAirdropActionError("airdrop_interaction_custom_id_invalid")
    return value


def button_specs(record: dict) -> list[dict]:
    request_id = record.get("request_id")
    status = record.get("status")
    if not isinstance(request_id, str) or not airdrop_approval.HEX32.fullmatch(request_id):
        raise DiscordAirdropActionError("airdrop_interaction_request_id_invalid")
    if status != "pending":
        return []
    return [
        {
            "action": "details",
            "label": "詳細",
            "style": "secondary",
            "custom_id": custom_id("details", request_id),
        },
        {
            "action": "approve",
            "label": "承認",
            "style": "success",
            "custom_id": custom_id("approve", request_id),
        },
        {
            "action": "reject",
            "label": "拒否",
            "style": "danger",
            "custom_id": custom_id("reject", request_id),
        },
    ]


def _authorize(
    *,
    allowed_ids: set[str],
    expected_channel_id: str,
    user_id: str,
    channel_id: str,
) -> None:
    if channel_id != expected_channel_id:
        raise DiscordAirdropActionError("airdrop_interaction_wrong_channel")
    if user_id not in allowed_ids:
        raise DiscordAirdropActionError("airdrop_interaction_unauthorized")


def _canonical_ledger_record(source_event_id: str, source_ledger_hash: str) -> dict:
    verified = airdrop_ledger.verify_ledger()
    matches = [
        row
        for row in verified.get("records", [])
        if isinstance(row, dict) and row.get("event_id") == source_event_id
    ]
    if len(matches) != 1 or matches[0].get("hash") != source_ledger_hash:
        raise DiscordAirdropActionError("airdrop_interaction_ledger_binding_mismatch")
    return matches[0]


def _candidate_for_request(record: dict) -> dict | None:
    action_class = record.get("action_class")
    if action_class not in airdrop_action_stager.AUTO_STAGE_KEYS:
        return None
    try:
        candidate = airdrop_action_stager.get_candidate_for_request(
            record["request_id"]
        )
    except airdrop_action_stager.StagingBridgeError as error:
        raise DiscordAirdropActionError(
            "airdrop_interaction_candidate_missing"
        ) from error
    if (
        candidate.get("request_id") != record.get("request_id")
        or candidate.get("approval_digest") != record.get("approval_digest")
        or candidate.get("payload_sha256") != record.get("payload_sha256")
        or candidate.get("source_event_id") != record.get("source_event_id")
    ):
        raise DiscordAirdropActionError(
            "airdrop_interaction_candidate_binding_mismatch"
        )
    _canonical_ledger_record(
        candidate["source_event_id"],
        candidate["source_ledger_hash"],
    )
    return candidate


def _render_evidence(record: dict, candidate: dict | None) -> str:
    lines = [
        "🟠 FLOP Airdrop Action — 詳細",
        f"状態: {record['status']}",
        f"action: {record['action_class']}",
        f"内容: {record['summary']}",
        f"費用/価値: {record['cost_note']}",
        f"取り消し: {'可能' if record['reversible'] else '不可/保証なし'}",
        f"期限: {record['expires_at']}",
        f"request id: {record['request_id']}",
        f"payload sha256: {record['payload_sha256']}",
        f"approval digest: {record['approval_digest']}",
        f"source event: {record['source_event_id'] or 'none'}",
    ]
    if candidate is None:
        lines.extend(
            [
                "",
                "exact candidate: このaction classではStaging Bridge候補はありません。",
                "この詳細表示自体は承認・署名・送信を実行しません。",
            ]
        )
        return "\n".join(lines)

    ledger = _canonical_ledger_record(
        candidate["source_event_id"],
        candidate["source_ledger_hash"],
    )
    lines.extend(
        [
            f"candidate id: {candidate['candidate_id']}",
            f"source ledger hash: {candidate['source_ledger_hash']}",
            "",
            "exact payload:",
            json.dumps(
                candidate["payload"],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            "",
            "evidence:",
        ]
    )
    for evidence in ledger.get("source_evidence", []):
        if not isinstance(evidence, dict):
            continue
        lines.append(
            "・"
            f"tier={evidence.get('tier')} "
            f"authority={evidence.get('authority')} "
            f"status={evidence.get('status')} "
            f"observation={evidence.get('observation')} "
            f"url={evidence.get('final_url') or evidence.get('url') or '-'}"
        )
    lines.append("")
    lines.append("この詳細表示自体は承認・署名・送信を実行しません。")
    rendered = "\n".join(lines)
    if len(rendered) > MAX_DETAIL_CHARS:
        raise DiscordAirdropActionError("airdrop_interaction_detail_too_large")
    return rendered


def handle_interaction(
    *,
    allowed_ids: set[str],
    expected_channel_id: str,
    user_id: str,
    channel_id: str,
    component_custom_id: str,
    now: datetime | None = None,
) -> dict:
    _authorize(
        allowed_ids=allowed_ids,
        expected_channel_id=expected_channel_id,
        user_id=user_id,
        channel_id=channel_id,
    )
    match = CUSTOM_ID_RE.fullmatch(component_custom_id or "")
    if match is None:
        raise DiscordAirdropActionError("airdrop_interaction_custom_id_invalid")
    action, request_id = match.groups()
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise DiscordAirdropActionError("airdrop_interaction_timestamp_timezone_required")
    current = current.astimezone(UTC)

    try:
        record = airdrop_approval.get_request(request_id, now=current)
    except airdrop_approval.ApprovalInboxError as error:
        raise DiscordAirdropActionError(str(error)) from error

    candidate = _candidate_for_request(record)

    if action == "details":
        return {
            "ok": True,
            "action": action,
            "record": record,
            "message": _render_evidence(record, candidate),
            "edit_original": False,
        }

    if record.get("status") != "pending":
        raise DiscordAirdropActionError(
            f"airdrop_interaction_request_not_pending:{record.get('status')}"
        )

    decision = "approved" if action == "approve" else "rejected"
    try:
        updated = airdrop_approval.decide(
            request_id,
            record["approval_digest"],
            decision=decision,
            actor_id=user_id,
            now=current,
        )
    except airdrop_approval.ApprovalInboxError as error:
        raise DiscordAirdropActionError(str(error)) from error

    if decision == "approved":
        message = (
            f"✅ APPROVED locally: {request_id}\n"
            "この承認はexact payload digestにのみ有効です。"
            "まだ署名・送信・Claim・支払いは実行していません。"
        )
    else:
        message = (
            f"⛔ REJECTED locally: {request_id}\n"
            "外部実行はありません。このrequestは再承認できません。"
        )
    return {
        "ok": True,
        "action": action,
        "record": updated,
        "message": message,
        "edit_original": True,
    }
