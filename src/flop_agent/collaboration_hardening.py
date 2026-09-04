"""Monotonic collaboration transition guard.

Loaded by the production Discord collaboration wrapper. It patches only the
local collaboration reconciler; no network/signing surface is introduced.
"""
from __future__ import annotations

from . import collaboration

_STAGE_RANK = {
    "discovered": 0,
    "contacted": 1,
    "replied": 2,
    "task_candidate": 3,
    "human_review": 4,
    "active": 5,
    "completed": 6,
}


def advance_from_new_replies(state: dict, local: dict) -> bool:
    """Advance only on unseen directed replies and never regress open work."""
    changed = False
    candidates = [item for item in local.get("candidates", {}).values() if isinstance(item, dict)]
    candidates.sort(key=lambda item: str(item.get("created_at", "")))

    for record in state.get("records", {}).values():
        if not isinstance(record, dict) or record.get("stage") not in collaboration.ACTIVE_STAGES:
            continue
        related = record.setdefault("related_candidate_ids", [])
        seen = set(str(item) for item in related)
        directed = [
            candidate
            for candidate in candidates
            if collaboration._candidate_after(record, candidate)
            and collaboration._direct_signed(candidate)
            and str(candidate.get("candidate_id", "")) not in seen
        ]
        if not directed:
            continue

        candidate = directed[-1]
        candidate_id = str(candidate.get("candidate_id", ""))
        if candidate_id:
            related.append(candidate_id)
            del related[:-collaboration.MAX_RELATED_CANDIDATES]
            changed = True

        stage, reason, next_action, topic, summary = collaboration._classify_reply(candidate)
        at = str(candidate.get("created_at") or collaboration.now())
        current = str(record.get("stage", "discovered"))

        # A security block always wins. Completed records are terminal. Otherwise
        # preserve the most advanced open-work stage instead of letting later
        # general chatter erase a task/human-review state.
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
    if collaboration._advance_from_replies is not advance_from_new_replies:
        collaboration._advance_from_replies = advance_from_new_replies
