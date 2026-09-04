"""Scaling and monotonic guards for the local collaboration reconciler.

Loaded by the production Discord collaboration wrapper.  The base feature keeps
its readable state-machine implementation; this overlay makes the two candidate
walks production-safe for a Resident state with thousands of candidates.
No network/signing surface is introduced.
"""
from __future__ import annotations

import heapq

from . import collaboration

DISCOVERY_SCAN_LIMIT = 128
DISCOVERY_CREATE_LIMIT = 8
DIRECT_REPLIES_PER_RECORD = 32

_STAGE_RANK = {
    "discovered": 0,
    "contacted": 1,
    "replied": 2,
    "task_candidate": 3,
    "human_review": 4,
    "active": 5,
    "completed": 6,
}


def bounded_discovery(state: dict, local: dict) -> bool:
    """Materialize only a bounded newest slice of not-yet-contacted candidates.

    `discovered` is an informational collaboration stage, not a write/safety
    decision.  The actual Safe First Contact lane remains authoritative and may
    evaluate its own full Resident state.  This view must never re-run expensive
    first-contact eligibility across every historical pending candidate each
    minute merely to populate Discord.
    """
    records = state.get("records", {})
    pending = (
        candidate
        for candidate in local.get("candidates", {}).values()
        if isinstance(candidate, dict) and candidate.get("status") == "pending"
    )
    newest = heapq.nlargest(
        DISCOVERY_SCAN_LIMIT,
        pending,
        key=lambda candidate: str(candidate.get("created_at", "")),
    )
    changed = False
    created = 0
    for candidate in newest:
        fingerprint = str(candidate.get("fingerprint", ""))
        source_candidate_id = str(candidate.get("candidate_id", ""))
        if not fingerprint or not source_candidate_id:
            continue
        record_id = collaboration._record_id(fingerprint, source_candidate_id)
        if record_id in records:
            continue
        try:
            allowed, _, _ = collaboration.autopilot.first_contact_eligible(candidate)
        except RuntimeError:
            allowed = False
        if not allowed:
            continue
        records[record_id] = collaboration._new_record(candidate)
        changed = True
        created += 1
        if created >= DISCOVERY_CREATE_LIMIT:
            break
    return changed


def advance_from_new_replies(state: dict, local: dict) -> bool:
    """Index directed replies once, then advance records monotonically.

    Complexity is O(candidates + matching replies) instead of
    O(collaboration_records * candidates).  Only signed messages already marked
    as direct-to-us by the existing safety classifier enter the index.
    """
    changed = False
    by_fingerprint: dict[str, list[dict]] = {}
    for candidate in local.get("candidates", {}).values():
        if not isinstance(candidate, dict) or not collaboration._direct_signed(candidate):
            continue
        fingerprint = str(candidate.get("fingerprint", ""))
        if not fingerprint:
            continue
        by_fingerprint.setdefault(fingerprint, []).append(candidate)

    for rows in by_fingerprint.values():
        rows.sort(key=lambda item: (str(item.get("created_at", "")), int(item.get("seq", -1) or -1)))

    for record in state.get("records", {}).values():
        if not isinstance(record, dict) or record.get("stage") not in collaboration.ACTIVE_STAGES:
            continue
        related = record.setdefault("related_candidate_ids", [])
        seen = {str(item) for item in related}
        rows = [
            candidate
            for candidate in by_fingerprint.get(str(record.get("fingerprint", "")), [])
            if str(candidate.get("candidate_id", "")) not in seen
            and collaboration._candidate_after(record, candidate)
        ]
        if not rows:
            continue
        # If a counterpart sent an extreme burst, keep this reconciliation cycle
        # bounded and process the newest retained slice in chronological order.
        rows = rows[-DIRECT_REPLIES_PER_RECORD:]

        for candidate in rows:
            candidate_id = str(candidate.get("candidate_id", ""))
            if candidate_id:
                related.append(candidate_id)
                del related[:-collaboration.MAX_RELATED_CANDIDATES]
                seen.add(candidate_id)
                changed = True

            stage, reason, next_action, topic, summary = collaboration._classify_reply(candidate)
            at = str(candidate.get("created_at") or collaboration.now())
            current = str(record.get("stage", "discovered"))

            # A security block always wins. Completed records are terminal.
            # Otherwise later general chatter cannot erase an already-open
            # task/review/active state.
            if current == "completed":
                continue
            if stage != "blocked" and _STAGE_RANK.get(stage, -1) < _STAGE_RANK.get(current, -1):
                continue

            record["task_topic"] = topic
            if summary:
                record["task_summary"] = summary
            changed = collaboration._set_stage(record, stage, reason, next_action, at) or changed
    return changed


def install() -> None:
    if collaboration._ensure_discovered is not bounded_discovery:
        collaboration._ensure_discovered = bounded_discovery
    if collaboration._advance_from_replies is not advance_from_new_replies:
        collaboration._advance_from_replies = advance_from_new_replies
