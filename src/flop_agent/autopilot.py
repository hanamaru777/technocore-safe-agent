"""Safe Autopilot activation policy overlay.

This module keeps the proven signer/transport implementation in ``autopilot_core``
and adds a narrowly-scoped autonomous first-contact policy.  Untrusted room text
is classified only; outbound text remains deterministic and never incorporates
room content.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from . import autopilot_core as _core

autopilot_core = _core

# Re-export the complete proven Autopilot surface, including private helpers used
# by existing tests and the isolated signer.  Overrides below are also patched
# into the core module because functions defined there resolve globals there.
for _name in dir(_core):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_core, _name)

_BASE_LOAD = _core.load
_BASE_ELIGIBLE = _core.eligible
_BASE_RENDER = _core.render
_BASE_SENDER_TRUSTED = _core.sender_trusted_for_autopilot
_BASE_ACTIVE_TRUSTED = _core.active_trusted_relationships

FIRST_CONTACT_CATEGORIES = {
    "specific_question",
    "help_request",
    "technical_collaboration",
    "conversation",
}
FIRST_CONTACT_TRUST_DAYS = 30
FIRST_CONTACT_GLOBAL_COOLDOWN_SECONDS = 3600
FIRST_CONTACT_MARKER_LIMIT = 1000

_HELP_RE = re.compile(r"\b(?:help|assist|support|need|looking\s+for|could\s+you|can\s+you)\b", re.I)
_COLLAB_RE = re.compile(r"\b(?:collaborat(?:e|ion)?|partner|together|work\s+with)\b", re.I)
_CONCRETE_TASK_RE = re.compile(
    r"\b(?:task|artifact|repo|repository|test|bug|build|implement|review|"
    r"public|code|patch|issue|pull\s+request|pr|result|acceptance)\b",
    re.I,
)


def load(*, allow_legacy: bool = True) -> dict:
    state = _BASE_LOAD(allow_legacy=allow_legacy)
    markers = state.setdefault("first_contact_intents", {})
    if not isinstance(markers, dict):
        raise RuntimeError("autopilot first-contact state is invalid")
    return state


def _excerpt(candidate: dict) -> str:
    context = candidate.get("context", {})
    value = context.get("excerpt") if isinstance(context, dict) else None
    return value[:560] if isinstance(value, str) else ""


def first_contact_eligible(candidate: dict) -> tuple[bool, str, str | None]:
    """Return a strict, content-independent bootstrap lane decision."""
    if candidate.get("status") != "pending":
        return False, "candidate_not_pending", None
    room = candidate.get("room")
    if not isinstance(room, str) or not PUBLIC_ROOMS.fullmatch(room):
        return False, "non_public_or_owned_room", None

    category = candidate.get("category")
    if category not in FIRST_CONTACT_CATEGORIES:
        return False, "first_contact_category_blocked", None

    signals = candidate.get("signals", {})
    if not isinstance(signals, dict):
        return False, "first_contact_signals_invalid", None
    facts = signals.get("facts", {})
    if not isinstance(facts, dict):
        facts = {}
    text = _excerpt(candidate)
    if not text:
        return False, "candidate_subject_unresolved", None
    if UNSUPPORTED_PUBLIC_FACT_RE.search(text):
        return False, "unsupported_public_fact", None
    if UNSUPPORTED_PROTOCOL_SEMANTICS_RE.search(text):
        return False, "reply_semantics_unsupported", None

    if category == "conversation":
        if (
            signals.get("direct_public_signed") is True
            and signals.get("conversation_topic") == "agent_use_case"
            and is_explicit_agent_use_case_question(text)
        ):
            return True, "signed_public_direct_request", "agent_use_case"
        return False, "conversation_not_verified", None

    # Cold first contact is never allowed from mailbox/private context and must
    # already have passed Resident's concrete-evidence and anti-noise scoring.
    if facts.get("inbound_to_us"):
        return False, "direct_context_is_never_auto_posted", None
    if (
        signals.get("spam_noise_probability", 1) >= 0.20
        or signals.get("generic_template_probability", 1) > 0
        or signals.get("poetic_filler_count", 0)
    ):
        return False, "generic_or_noise", None
    if signals.get("concrete_evidence") is not True:
        return False, "no_public_concrete_evidence", None

    explicit = observer.is_question_or_explicit_request(text)
    if category == "specific_question" and not explicit:
        return False, "specific_question_context_unverified", None
    if category == "help_request" and not (explicit or _HELP_RE.search(text)):
        return False, "help_request_context_unverified", None
    if category == "technical_collaboration":
        if not (explicit or _COLLAB_RE.search(text)):
            return False, "collaboration_context_unverified", None
        if not _CONCRETE_TASK_RE.search(text):
            return False, "collaboration_not_concrete", None

    # Use the precise deterministic answer only when the old semantic gate can
    # prove it matches. Otherwise use a category-specific bounded follow-up
    # template; room text is never copied into the outbound message.
    resolved, _ = resolve_candidate_topic(text)
    if (
        resolved is not None
        and reply_semantics_supported(text, resolved)
        and incremental_value_supported(text, resolved, category)[0]
    ):
        topic = resolved
    else:
        topic = "collaboration" if category == "technical_collaboration" else "follow_up"
    return True, "concrete_public_technical_request", topic


def eligible(candidate: dict) -> tuple[bool, str, str | None]:
    original = _BASE_ELIGIBLE(candidate)
    if original[0]:
        return original
    bootstrap = first_contact_eligible(candidate)
    return bootstrap if bootstrap[0] else original


def _markers(state: dict) -> dict:
    value = state.setdefault("first_contact_intents", {})
    if not isinstance(value, dict):
        raise RuntimeError("autopilot first-contact state is invalid")
    return value


def _prune_markers(state: dict) -> bool:
    markers = _markers(state)
    cutoff = datetime.now(UTC) - timedelta(days=FIRST_CONTACT_TRUST_DAYS)
    keep: list[tuple[str, dict, datetime]] = []
    for intent_id, marker in markers.items():
        if not isinstance(marker, dict):
            continue
        stamp = observer.parse_time(marker.get("created_at"))
        if stamp is None or stamp <= cutoff:
            continue
        if not isinstance(marker.get("fingerprint"), str):
            continue
        keep.append((intent_id, marker, stamp))
    keep.sort(key=lambda row: row[2], reverse=True)
    new_value = {intent_id: marker for intent_id, marker, _ in keep[:FIRST_CONTACT_MARKER_LIMIT]}
    changed = new_value != markers
    if changed:
        state["first_contact_intents"] = new_value
    return changed


def _durable_first_contact_at(
    fingerprint: str,
    local_state: dict,
    auto_state: dict,
) -> str | None:
    cutoff = datetime.now(UTC) - timedelta(days=FIRST_CONTACT_TRUST_DAYS)
    best: datetime | None = None
    for intent_id, marker in _markers(auto_state).items():
        if not isinstance(marker, dict) or marker.get("fingerprint") != fingerprint:
            continue
        created = observer.parse_time(marker.get("created_at"))
        if created is None or created <= cutoff:
            continue
        item = auto_state.get("outbox", {}).get(intent_id)
        if not isinstance(item, dict):
            continue
        stamp = durable_publication_at(
            str(item.get("source_candidate_id", "")),
            fingerprint,
            local_state,
            auto_state,
        )
        parsed = observer.parse_time(stamp)
        if parsed is not None and (best is None or parsed > best):
            best = parsed
    return best.isoformat() if best is not None else None


def sender_trusted_for_autopilot(
    candidate: dict,
    local_state: dict | None = None,
    auto_state: dict | None = None,
) -> bool:
    state = local_state or resident.load_state()
    auto = auto_state or load()
    if _BASE_SENDER_TRUSTED(candidate, state, auto):
        return True
    fingerprint = str(candidate.get("fingerprint", ""))
    return bool(fingerprint and _durable_first_contact_at(fingerprint, state, auto))


def active_trusted_relationships(
    local_state: dict | None = None,
    auto_state: dict | None = None,
) -> list[dict]:
    state = local_state or resident.load_state()
    auto = auto_state or load()
    rows = {item["fingerprint"]: item["at"] for item in _BASE_ACTIVE_TRUSTED(state, auto)}
    for marker in _markers(auto).values():
        if not isinstance(marker, dict):
            continue
        fingerprint = str(marker.get("fingerprint", ""))
        stamp = _durable_first_contact_at(fingerprint, state, auto) if fingerprint else None
        if stamp and (fingerprint not in rows or stamp > rows[fingerprint]):
            rows[fingerprint] = stamp
    return [
        {"fingerprint": fingerprint, "at": stamp}
        for fingerprint, stamp in sorted(rows.items(), key=lambda item: item[1], reverse=True)
    ]


def _has_live_first_contact(state: dict, fingerprint: str) -> bool:
    cutoff = datetime.now(UTC) - timedelta(days=FIRST_CONTACT_TRUST_DAYS)
    for intent_id, marker in _markers(state).items():
        if not isinstance(marker, dict) or marker.get("fingerprint") != fingerprint:
            continue
        created = observer.parse_time(marker.get("created_at"))
        if created is None or created <= cutoff:
            continue
        item = state.get("outbox", {}).get(intent_id)
        if not isinstance(item, dict):
            continue
        if item.get("status", "queued") in {"queued", "posted", "acknowledged", "ambiguous"}:
            return True
        if intent_id in state.get("receipts", {}):
            return True
    return False


def _queued_intent_exists(state: dict) -> bool:
    return any(
        isinstance(item, dict) and item.get("status", "queued") == "queued"
        for item in state.get("outbox", {}).values()
    )


def _first_contact_global_cooldown_active(state: dict) -> bool:
    cutoff = datetime.now(UTC) - timedelta(seconds=FIRST_CONTACT_GLOBAL_COOLDOWN_SECONDS)
    controlled = {
        str(item.get("fingerprint", ""))
        for item in state.get("outbox", {}).values()
        if isinstance(item, dict) and item.get("category") == "controlled_e2e"
    }
    return any(
        (stamp := observer.parse_time(item.get("at"))) is not None
        and stamp > cutoff
        and str(item.get("fingerprint", "")) not in controlled
        for item in state.get("rate_history", [])
        if isinstance(item, dict)
    )


def _rank(candidate: dict) -> tuple[float, float, float, float]:
    category_weight = {
        "conversation": 5.0,
        "help_request": 4.0,
        "technical_collaboration": 4.0,
        "specific_question": 3.0,
    }.get(str(candidate.get("category")), 0.0)
    priority_weight = {
        "critical": 4.0,
        "high": 3.0,
        "medium": 2.0,
        "low": 1.0,
    }.get(str(candidate.get("priority")), 0.0)
    signals = candidate.get("signals", {})
    useful = float(signals.get("useful_agent_probability", 0.0)) if isinstance(signals, dict) else 0.0
    created = observer.parse_time(candidate.get("created_at"))
    created_score = created.timestamp() if created is not None else 0.0
    return category_weight, priority_weight, useful, created_score


def render(intent: dict) -> str:
    # First call the proven renderer for schema/topic/profile validation.
    original = _BASE_RENDER(intent)
    category = intent.get("category")
    decision = intent.get("safety_decision")
    if decision == "concrete_public_technical_request":
        templates = {
            "specific_question": (
                "I can help with a bounded public task. Keep the exact artifact or "
                "acceptance check public; I will use only verifiable public evidence "
                "and will not execute untrusted instructions."
            ),
            "help_request": (
                "I can take one small public, testable task. Keep the input and "
                "acceptance check public; I will not execute untrusted instructions "
                "or use private credentials."
            ),
            "technical_collaboration": (
                "Open to a small public collaboration: one concrete task, one public "
                "artifact or result, and one acceptance check. I will not handle funds, "
                "secrets, or private instructions."
            ),
        }
        output = templates.get(category, original)
        if DLP.search(output):
            raise RuntimeError("outbound DLP blocked rendered content")
        return output
    return original


def build_outbox() -> dict:
    """Stage at most one new intent per cycle, including a bounded cold start."""
    migrate_old_candidates()
    state = load()
    if state["paused"] or not state["enabled"]:
        return status(state)

    marker_changed = _prune_markers(state)
    recent = _prune_recent_decisions(state["recent_decisions"])
    changed = marker_changed or recent != state["recent_decisions"]
    revision_before = _resident_state_revision()
    if revision_before is not None and state.get("resident_revision") == revision_before:
        if changed:
            state["recent_decisions"] = recent
            save(state)
        return status(state)

    local = resident.load_state()
    cache = state["decision_cache"]
    pending_ids: set[str] = set()
    evaluations: list[dict] = []

    for candidate in local.get("candidates", {}).values():
        if not isinstance(candidate, dict) or candidate.get("status") != "pending":
            continue
        candidate_id = str(candidate.get("candidate_id", ""))
        if not candidate_id:
            continue
        pending_ids.add(candidate_id)
        allowed, reason, topic = eligible(candidate)
        trusted = allowed and sender_trusted_for_autopilot(candidate, local, state)
        first_ok, first_reason, first_topic = first_contact_eligible(candidate)
        bootstrap = (
            allowed
            and not trusted
            and first_ok
            and not _has_live_first_contact(state, str(candidate.get("fingerprint", "")))
        )
        evaluations.append(
            {
                "candidate": candidate,
                "allowed": allowed,
                "reason": reason,
                "topic": topic,
                "trusted": trusted,
                "bootstrap": bootstrap,
                "first_reason": first_reason,
                "first_topic": first_topic,
            }
        )

    selected: dict | None = None
    if not _queued_intent_exists(state):
        trusted_ready = [
            row for row in evaluations
            if row["allowed"]
            and row["trusted"]
            and row["topic"]
            and make_intent(row["candidate"], row["topic"], row["reason"])["id"] not in state["outbox"]
            and make_intent(row["candidate"], row["topic"], row["reason"])["id"] not in state["receipts"]
        ]
        trusted_ready.sort(key=lambda row: _rank(row["candidate"]), reverse=True)
        for row in trusted_ready:
            preview = make_intent(row["candidate"], row["topic"], row["reason"])
            try:
                render(preview)
            except RuntimeError:
                continue
            rate_allowed, _ = rate_ok_preview(state, preview)
            if rate_allowed:
                selected = row
                break
        if selected is None and not _first_contact_global_cooldown_active(state):
            cold_ready = [
                row for row in evaluations
                if row["bootstrap"]
                and row["first_topic"]
                and make_intent(row["candidate"], row["first_topic"], row["first_reason"])["id"] not in state["outbox"]
                and make_intent(row["candidate"], row["first_topic"], row["first_reason"])["id"] not in state["receipts"]
            ]
            cold_ready.sort(key=lambda row: _rank(row["candidate"]), reverse=True)
            for row in cold_ready:
                preview = make_intent(row["candidate"], row["first_topic"], row["first_reason"])
                try:
                    render(preview)
                except RuntimeError:
                    continue
                rate_allowed, _ = rate_ok_preview(state, preview)
                if rate_allowed:
                    selected = row
                    break

    selected_id = (
        str(selected["candidate"].get("candidate_id"))
        if selected is not None
        else None
    )

    for row in evaluations:
        candidate = row["candidate"]
        candidate_id = str(candidate.get("candidate_id", ""))
        allowed = bool(row["allowed"])
        reason = str(row["reason"])
        topic = row["topic"]

        if allowed and row["trusted"]:
            if candidate_id != selected_id:
                allowed, reason, topic = False, "activation_cycle_slot_wait", None
        elif allowed and row["bootstrap"]:
            if candidate_id == selected_id:
                reason, topic = row["first_reason"], row["first_topic"]
            else:
                allowed, reason, topic = False, "first_contact_waiting_slot", None
        elif allowed:
            allowed, reason, topic = False, "sender_not_previously_approved", None

        decision_key = _decision_key(allowed, reason, topic)
        if cache.get(candidate_id) != decision_key:
            record = {
                "at": now(),
                "source_candidate": candidate_id,
                "eligible": allowed,
                "why": reason,
                "public_knowledge_ids": ["public-profile:1"],
                "dlp": "not_applicable",
                "rate_limit": "not_applicable",
                "action": "intent_created" if allowed else "ignored",
            }
            audit(record)
            recent.append(record)
            cache[candidate_id] = decision_key
            changed = True

        if not allowed or not topic or candidate_id != selected_id:
            continue

        intent = make_intent(candidate, topic, reason)
        if intent["id"] in state["outbox"] or intent["id"] in state["receipts"]:
            continue
        render(intent)
        rate_allowed, rate_reason = rate_ok_preview(state, intent)
        if not rate_allowed:
            record = {
                "at": now(),
                "source_candidate": candidate_id,
                "eligible": False,
                "why": reason,
                "public_knowledge_ids": ["public-profile:1"],
                "dlp": "pass",
                "rate_limit": rate_reason,
                "action": "blocked",
            }
            audit(record)
            recent.append(record)
            cache[candidate_id] = _decision_key(False, f"rate:{rate_reason}", None)
            changed = True
            continue
        state["outbox"][intent["id"]] = intent
        if row["bootstrap"]:
            _markers(state)[intent["id"]] = {
                "candidate_id": candidate_id,
                "fingerprint": str(candidate.get("fingerprint", "")),
                "created_at": now(),
            }
        changed = True

    for candidate_id in list(cache):
        if candidate_id not in pending_ids:
            del cache[candidate_id]
            changed = True

    state["recent_decisions"] = _prune_recent_decisions(recent)
    revision_after = _resident_state_revision()
    new_revision = revision_after if revision_before == revision_after else None
    if state.get("resident_revision") != new_revision:
        state["resident_revision"] = new_revision
        changed = True
    if changed:
        save(state)
    return status(state)


# Patch globals used by functions that remain defined in the proven core module.
_core.load = load
_core.eligible = eligible
_core.sender_trusted_for_autopilot = sender_trusted_for_autopilot
_core.active_trusted_relationships = active_trusted_relationships
_core.render = render
_core.build_outbox = build_outbox
