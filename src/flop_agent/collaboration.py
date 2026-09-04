"""Bounded, local-only collaboration lifecycle for useful Agent relationships.

This module never performs Technocore network I/O and never signs or posts. It
reconciles already-durable Resident/Autopilot state into a small collaboration
state machine so an acknowledged contact can progress toward verifiable work.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import UTC, datetime
from pathlib import Path

from . import autopilot, conversation_planner, observer, resident, tclk_watch

SCHEMA_VERSION = 1
STATE_FILE = "collaboration-state.json"
MAX_RECORDS = 250
MAX_HISTORY = 24
MAX_RELATED_CANDIDATES = 20
MAX_EVIDENCE_INDEX = 250
CONTACT_CATEGORIES = {"conversation", "help_request", "specific_question", "technical_collaboration"}
TASK_TOPICS = {
    "repo_tests_bugs",
    "did_signature",
    "nonce",
    "technocore_api",
    "contribution_artifact",
    "collaboration",
}
TERMINAL_STAGES = {"completed", "blocked"}
ACTIVE_STAGES = {"contacted", "replied", "task_candidate", "human_review", "active"}
URL_RE = re.compile(r"https?://\S+", re.I)
MENTION_RE = re.compile(r"<@!?&?\d+>|@everyone|@here", re.I)
TASK_REQUEST_RE = re.compile(
    r"\b(?:please|can\s+you|could\s+you|would\s+you|help\s+(?:me|us)|"
    r"review|test|reproduce|validate|verify|check|inspect|pair\s+on|collaborate\s+on)\b",
    re.I,
)
TASK_OBJECT_RE = re.compile(
    r"\b(?:repo|repository|test|test\s+vector|bug|issue|patch|commit|pull\s+request|pr|"
    r"artifact|did|signature|nonce|api|protocol|repro|result|acceptance\s+check)\b",
    re.I,
)
SENSITIVE_RE = re.compile(
    r"\b(?:seed|private\s+key|credential|password|api\s+key|secret)\b|"
    r"\b(?:run|execute)\b.{0,48}\b(?:shell|command|curl|wget|powershell|bash)\b",
    re.I,
)


def now() -> str:
    return datetime.now(UTC).isoformat()


def state_path() -> Path:
    return resident.resident_dir() / STATE_FILE


def default_state() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "updated_at": now(),
        "records": {},
        "completed_evidence_index": [],
        "notification_baselined": False,
        "notified_stages": {},
    }


def _sanitize(value: object, limit: int = 280) -> str:
    text = URL_RE.sub("[URL]", str(value or ""))
    text = MENTION_RE.sub("[mention]", text).replace("@", "＠")
    text = "".join(
        " " if unicodedata.category(char) in {"Zl", "Zp", "Zs"}
        else "" if unicodedata.category(char) in {"Cc", "Cf", "Cs", "Co"}
        else char
        for char in text
    )
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _parse(value: object) -> datetime | None:
    return observer.parse_time(value) if isinstance(value, str) else None


def load_state() -> dict:
    path = state_path()
    if not path.exists():
        return default_state()
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("collaboration state is corrupt; refusing to continue") from error
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("collaboration state schema is invalid")
    defaults = default_state()
    for key, value in defaults.items():
        data.setdefault(key, value)
    if not isinstance(data.get("records"), dict) or not isinstance(data.get("notified_stages"), dict):
        raise RuntimeError("collaboration state structure is invalid")
    if not isinstance(data.get("completed_evidence_index"), list):
        raise RuntimeError("collaboration evidence index is invalid")
    return data


def save_state(state: dict) -> None:
    _prune(state)
    state["updated_at"] = now()
    observer.atomic_json_write(state_path(), state, compact=True)


def _record_id(fingerprint: str, source_candidate_id: str) -> str:
    return hashlib.sha256(f"{fingerprint}|{source_candidate_id}".encode()).hexdigest()[:16]


def _history(record: dict, stage: str, reason: str, at: str) -> None:
    rows = record.setdefault("history", [])
    marker = (stage, reason, at)
    if rows and (rows[-1].get("stage"), rows[-1].get("reason"), rows[-1].get("at")) == marker:
        return
    rows.append({"stage": stage, "reason": reason, "at": at})
    del rows[:-MAX_HISTORY]


def _set_stage(
    record: dict,
    stage: str,
    reason: str,
    next_action: str,
    at: str | None = None,
) -> bool:
    at = at or now()
    changed = False
    if record.get("stage") != stage:
        record["stage"] = stage
        record["stage_at"] = at
        changed = True
    if record.get("stage_reason") != reason:
        record["stage_reason"] = reason
        changed = True
    if record.get("next_action") != next_action:
        record["next_action"] = next_action
        changed = True
    if changed:
        record["last_activity_at"] = at
        _history(record, stage, reason, at)
    return changed


def _new_record(candidate: dict) -> dict:
    fingerprint = str(candidate.get("fingerprint", ""))
    source_candidate_id = str(candidate.get("candidate_id", ""))
    created = str(candidate.get("created_at") or now())
    record = {
        "id": _record_id(fingerprint, source_candidate_id),
        "fingerprint": fingerprint,
        "did": str(candidate.get("did", ""))[:128],
        "source_candidate_id": source_candidate_id,
        "first_contact_intent_id": None,
        "room": str(candidate.get("room", ""))[:48],
        "source_seq": candidate.get("seq"),
        "stage": "discovered",
        "stage_at": created,
        "stage_reason": "safe_candidate_discovered",
        "next_action": "agent_may_contact",
        "last_activity_at": created,
        "related_candidate_ids": [],
        "related_tclk_offer_id": None,
        "task_topic": None,
        "task_summary": None,
        "evidence_refs": [],
        "history": [],
    }
    _history(record, "discovered", "safe_candidate_discovered", created)
    return record


def _controlled(intent: dict) -> bool:
    return (
        intent.get("category") == "controlled_e2e"
        or intent.get("safety_decision") == "controlled_pause_only_e2e"
    )


def _acknowledged(intent_id: str, intent: dict, auto_state: dict) -> tuple[bool, str | None]:
    receipt = auto_state.get("receipts", {}).get(intent_id)
    if not isinstance(receipt, dict):
        return False, None
    status = intent.get("status")
    if status not in {None, "acknowledged", "posted"}:
        return False, None
    stamp = receipt.get("at")
    return isinstance(stamp, str), stamp if isinstance(stamp, str) else None


def _candidate_after(record: dict, candidate: dict) -> bool:
    if candidate.get("fingerprint") != record.get("fingerprint"):
        return False
    if candidate.get("candidate_id") == record.get("source_candidate_id"):
        return False
    contacted = _parse(record.get("contacted_at") or record.get("stage_at"))
    created = _parse(candidate.get("created_at"))
    if contacted is not None and created is not None:
        return created > contacted
    source_seq = record.get("source_seq")
    seq = candidate.get("seq")
    return isinstance(source_seq, int) and isinstance(seq, int) and seq > source_seq


def _direct_signed(candidate: dict) -> bool:
    signals = candidate.get("signals", {})
    return (
        isinstance(signals, dict)
        and signals.get("direct_public_signed") is True
        and candidate.get("category") == "conversation"
    )


def _candidate_text(candidate: dict) -> str:
    context = candidate.get("context", {})
    value = context.get("excerpt") if isinstance(context, dict) else ""
    return value[:560] if isinstance(value, str) else ""


def _classify_reply(candidate: dict) -> tuple[str, str, str, str | None, str | None]:
    """Classify a demonstrably-directed signed reply without executing its content."""
    text = _candidate_text(candidate)
    safe = _sanitize(text)
    signals = candidate.get("signals", {}) if isinstance(candidate.get("signals"), dict) else {}
    topic = signals.get("conversation_topic") if isinstance(signals.get("conversation_topic"), str) else None

    if SENSITIVE_RE.search(text) or conversation_planner.UNSAFE.search(text):
        return "blocked", "unsafe_direct_request", "security_hold", topic, safe

    concrete_task = (
        topic in TASK_TOPICS
        and bool(TASK_REQUEST_RE.search(text))
        and bool(TASK_OBJECT_RE.search(text))
    )
    if concrete_task:
        # Unknown URLs and tclk work are never opened/accepted automatically.
        if URL_RE.search(text) or re.search(r"\btclk\b|\bpaperrail\b", text, re.I):
            return "human_review", "external_or_tclk_task_requires_review", "review_task", topic, safe
        return "task_candidate", "concrete_public_task_detected", "review_task", topic, safe

    allowed, reason, _ = autopilot.eligible(candidate)
    if allowed:
        return "replied", "direct_signed_reply_safe_for_existing_lane", "no_action_required", topic, safe
    return "replied", f"direct_signed_reply_{reason}", "watch_reply", topic, safe


def _ensure_discovered(state: dict, local: dict) -> bool:
    changed = False
    records = state["records"]
    for candidate in local.get("candidates", {}).values():
        if not isinstance(candidate, dict) or candidate.get("status") != "pending":
            continue
        fingerprint = str(candidate.get("fingerprint", ""))
        source_candidate_id = str(candidate.get("candidate_id", ""))
        if not fingerprint or not source_candidate_id:
            continue
        try:
            allowed, _, _ = autopilot.first_contact_eligible(candidate)
        except RuntimeError:
            allowed = False
        if not allowed:
            continue
        record_id = _record_id(fingerprint, source_candidate_id)
        if record_id not in records:
            records[record_id] = _new_record(candidate)
            changed = True
    return changed


def _ensure_contacts(state: dict, local: dict, auto_state: dict) -> bool:
    changed = False
    records = state["records"]
    markers = auto_state.get("first_contact_intents", {})
    if not isinstance(markers, dict):
        markers = {}

    for intent_id, intent in auto_state.get("outbox", {}).items():
        if not isinstance(intent, dict) or _controlled(intent):
            continue
        if intent.get("category") not in CONTACT_CATEGORIES and intent_id not in markers:
            continue
        ok, ack_at = _acknowledged(intent_id, intent, auto_state)
        if not ok or ack_at is None:
            continue
        fingerprint = str(intent.get("fingerprint", ""))
        source_candidate_id = str(intent.get("source_candidate_id", ""))
        if not fingerprint or not source_candidate_id:
            continue
        record_id = _record_id(fingerprint, source_candidate_id)
        record = records.get(record_id)
        if not isinstance(record, dict):
            candidate = local.get("candidates", {}).get(source_candidate_id)
            if isinstance(candidate, dict):
                record = _new_record(candidate)
            else:
                record = {
                    "id": record_id,
                    "fingerprint": fingerprint,
                    "did": str(intent.get("source_did", ""))[:128],
                    "source_candidate_id": source_candidate_id,
                    "first_contact_intent_id": None,
                    "room": str(intent.get("room", ""))[:48],
                    "source_seq": intent.get("seq"),
                    "stage": "discovered",
                    "stage_at": str(intent.get("created_at") or ack_at),
                    "stage_reason": "outbound_contact_reconstructed",
                    "next_action": "wait_for_reply",
                    "last_activity_at": str(intent.get("created_at") or ack_at),
                    "related_candidate_ids": [],
                    "related_tclk_offer_id": None,
                    "task_topic": None,
                    "task_summary": None,
                    "evidence_refs": [],
                    "history": [],
                }
                _history(record, "discovered", "outbound_contact_reconstructed", record["stage_at"])
            records[record_id] = record
            changed = True
        if record.get("first_contact_intent_id") != intent_id:
            record["first_contact_intent_id"] = intent_id
            changed = True
        if record.get("contacted_at") != ack_at:
            record["contacted_at"] = ack_at
            changed = True
        refs = record.setdefault("evidence_refs", [])
        receipt_ref = f"autopilot-receipt:{intent_id}"
        if receipt_ref not in refs:
            refs.append(receipt_ref)
            del refs[:-8]
            changed = True
        if record.get("stage") == "discovered":
            changed = _set_stage(record, "contacted", "acknowledged_outbound_contact", "wait_for_reply", ack_at) or changed
    return changed


def _advance_from_replies(state: dict, local: dict) -> bool:
    changed = False
    candidates = [item for item in local.get("candidates", {}).values() if isinstance(item, dict)]
    candidates.sort(key=lambda item: str(item.get("created_at", "")))

    for record in state["records"].values():
        if not isinstance(record, dict) or record.get("stage") not in ACTIVE_STAGES:
            continue
        directed = [candidate for candidate in candidates if _candidate_after(record, candidate) and _direct_signed(candidate)]
        if not directed:
            continue
        candidate = directed[-1]
        candidate_id = str(candidate.get("candidate_id", ""))
        related = record.setdefault("related_candidate_ids", [])
        if candidate_id and candidate_id not in related:
            related.append(candidate_id)
            del related[:-MAX_RELATED_CANDIDATES]
            changed = True

        stage, reason, next_action, topic, summary = _classify_reply(candidate)
        record["task_topic"] = topic
        if summary:
            record["task_summary"] = summary
        at = str(candidate.get("created_at") or now())

        # Never regress active/completed work because newer general chatter exists.
        current = record.get("stage")
        if current == "active" and stage in {"replied", "task_candidate"}:
            continue
        if current == "completed":
            continue
        changed = _set_stage(record, stage, reason, next_action, at) or changed
    return changed


def _link_tclk(state: dict, observed: dict) -> bool:
    changed = False
    offers = tclk_watch.opportunities(observed)
    by_fingerprint = {
        str(item.get("counterpart_fingerprint")): item
        for item in offers
        if isinstance(item, dict) and item.get("counterpart_fingerprint")
    }
    for record in state["records"].values():
        if not isinstance(record, dict):
            continue
        offer = by_fingerprint.get(str(record.get("fingerprint")))
        if not offer:
            continue
        offer_id = str(offer.get("id", ""))
        if not offer_id:
            continue
        if record.get("related_tclk_offer_id") != offer_id:
            record["related_tclk_offer_id"] = offer_id
            changed = True
        if record.get("stage") in {"contacted", "replied", "task_candidate"}:
            changed = _set_stage(
                record,
                "human_review",
                "signed_paperrail_offer_requires_human_review",
                "review_tclk",
                str(offer.get("ts") or now()),
            ) or changed
    return changed


def _prune(state: dict) -> None:
    records = state.get("records", {})
    if not isinstance(records, dict):
        return
    if len(records) <= MAX_RECORDS:
        state["completed_evidence_index"] = state.get("completed_evidence_index", [])[-MAX_EVIDENCE_INDEX:]
        return

    # Preserve active work first. Terminal/old discovered rows are pruned oldest-first.
    def priority(item: tuple[str, dict]) -> tuple[int, datetime]:
        _, record = item
        stage = record.get("stage")
        active = 2 if stage in ACTIVE_STAGES else 1 if stage == "completed" else 0
        stamp = _parse(record.get("last_activity_at")) or datetime.min.replace(tzinfo=UTC)
        return active, stamp

    ordered = sorted(records.items(), key=priority, reverse=True)
    keep = dict(ordered[:MAX_RECORDS])
    removed = ordered[MAX_RECORDS:]
    evidence = list(state.get("completed_evidence_index", []))
    for record_id, record in removed:
        if record.get("stage") != "completed":
            continue
        evidence.append({
            "id": record_id,
            "fingerprint": str(record.get("fingerprint", ""))[:16],
            "completed_at": record.get("stage_at"),
            "evidence_refs": list(record.get("evidence_refs", []))[-8:],
        })
    state["records"] = keep
    state["completed_evidence_index"] = evidence[-MAX_EVIDENCE_INDEX:]
    notified = state.get("notified_stages", {})
    if isinstance(notified, dict):
        state["notified_stages"] = {key: value for key, value in notified.items() if key in keep}


def reconcile(*, include_tclk: bool = False) -> dict:
    """Reconcile local durable state. No Technocore read or write occurs here by default."""
    state = load_state()
    local = resident.load_state()
    auto_state = autopilot.load()
    changed = _ensure_discovered(state, local)
    changed = _ensure_contacts(state, local, auto_state) or changed
    changed = _advance_from_replies(state, local) or changed
    if include_tclk:
        # Explicit/on-demand only: Observer state can be multi-MB. Keep the 15s
        # Discord idle path light and never load it just for routine notices.
        observed = observer.load_state()
        changed = _link_tclk(state, observed) or changed
    if changed:
        save_state(state)
    return state


def ensure_notification_baseline() -> None:
    state = reconcile(include_tclk=False)
    if state.get("notification_baselined") is True:
        return
    state["notified_stages"] = {
        record_id: record.get("stage")
        for record_id, record in state.get("records", {}).items()
        if isinstance(record, dict)
    }
    state["notification_baselined"] = True
    save_state(state)


def transition_notices() -> list[dict]:
    state = reconcile(include_tclk=False)
    if state.get("notification_baselined") is not True:
        ensure_notification_baseline()
        return []
    notified = state.setdefault("notified_stages", {})
    notices: list[dict] = []
    for record_id, record in state.get("records", {}).items():
        if not isinstance(record, dict):
            continue
        stage = record.get("stage")
        previous = notified.get(record_id)
        if previous == stage:
            continue
        notified[record_id] = stage
        if stage in {"replied", "task_candidate", "human_review", "completed"}:
            notices.append({
                "id": record_id,
                "stage": stage,
                "previous_stage": previous,
                "fingerprint": record.get("fingerprint"),
                "reason": record.get("stage_reason"),
                "next_action": record.get("next_action"),
                "task_summary": record.get("task_summary"),
                "tclk_offer_id": record.get("related_tclk_offer_id"),
            })
        elif stage == "blocked" and previous in ACTIVE_STAGES:
            notices.append({
                "id": record_id,
                "stage": stage,
                "previous_stage": previous,
                "fingerprint": record.get("fingerprint"),
                "reason": record.get("stage_reason"),
                "next_action": record.get("next_action"),
                "task_summary": record.get("task_summary"),
                "tclk_offer_id": record.get("related_tclk_offer_id"),
            })
    save_state(state)
    return notices


def records(*, include_tclk: bool = False) -> list[dict]:
    state = reconcile(include_tclk=include_tclk)
    rank = {
        "human_review": 8,
        "task_candidate": 7,
        "active": 6,
        "replied": 5,
        "contacted": 4,
        "discovered": 3,
        "blocked": 2,
        "completed": 1,
    }
    rows = [record for record in state.get("records", {}).values() if isinstance(record, dict)]
    return sorted(
        rows,
        key=lambda item: (
            rank.get(str(item.get("stage")), 0),
            _parse(item.get("last_activity_at")) or datetime.min.replace(tzinfo=UTC),
        ),
        reverse=True,
    )


def get(record_id: str, *, include_tclk: bool = True) -> dict | None:
    if not isinstance(record_id, str) or not re.fullmatch(r"[0-9a-f]{16}", record_id):
        return None
    state = reconcile(include_tclk=include_tclk)
    record = state.get("records", {}).get(record_id)
    return record if isinstance(record, dict) else None


def metrics() -> dict:
    rows = records(include_tclk=False)
    counts = {stage: 0 for stage in ("discovered", "contacted", "replied", "task_candidate", "human_review", "active", "completed", "blocked")}
    for row in rows:
        stage = row.get("stage")
        if stage in counts:
            counts[stage] += 1
    counts["total"] = len(rows)
    counts["replies_from_contacted"] = sum(
        any(item.get("stage") in {"replied", "task_candidate", "human_review", "active", "completed"} for item in row.get("history", []))
        for row in rows
    )
    return counts
