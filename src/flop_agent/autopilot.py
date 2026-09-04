"""Public Autopilot facade with activation safety compatibility.

The proven transport/publisher lives in ``autopilot_core``. The first-contact
policy lives in ``autopilot_policy``. This facade keeps legacy monkeypatch/config
compatibility, rejects hostile cold prompts, preserves the already-running
Signer's deterministic render behavior, and gates autonomous cold-start behind an
explicit local feature flag.
"""
from __future__ import annotations

import re
import sys
import types
from datetime import UTC, datetime, timedelta

from . import autopilot_policy as _policy

for _name in dir(_policy):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_policy, _name)

autopilot_core = _policy.autopilot_core
autopilot_policy = _policy

_BASE_DEFAULT_STATE = _policy.default_state
_BASE_ELIGIBLE = _policy._BASE_ELIGIBLE
_BASE_RENDER = _policy._BASE_RENDER
_HUMAN_TRUSTED = _policy._BASE_SENDER_TRUSTED
_HUMAN_ACTIVE_TRUSTED = _policy._BASE_ACTIVE_TRUSTED
_POLICY_BUILD_OUTBOX = _policy.build_outbox
_POLICY_RATE_OK_PREVIEW = _policy.rate_ok_preview

TRANSPORT_SAFE_CATEGORIES = {
    "help_request",
    "specific_question",
    "technical_collaboration",
    "artifact_contribution",
    "conversation",
}

# Cold start stays much narrower than the normal trusted lane.  In particular,
# artifact/returning-agent bulk observations never bootstrap autonomous contact.
FIRST_CONTACT_CATEGORIES = {
    "help_request",
    "specific_question",
    "technical_collaboration",
    "conversation",
}

_UNTRUSTED_ACTION_RE = re.compile(
    r"(?:"
    r"\bignore\s+(?:all|previous|prior)\b|"
    r"\b(?:run|execute)\s+(?:a\s+|the\s+)?(?:command|shell|script)\b|"
    r"\bopen\s+https?://|"
    r"\b(?:curl|wget|powershell|cmd(?:\.exe)?|bash)\b|"
    r"\b(?:read|show|reveal|send)\s+(?:(?:the|your|my)\s+)?"
    r"(?:env(?:ironment)?|env\s+file|credentials?|password|secrets?|seed|private\s+key)\b"
    r")",
    re.I,
)
_HELP_RE = re.compile(r"\b(?:help|assist|support|could\s+you|can\s+you)\b", re.I)
_COLLAB_RE = re.compile(r"\b(?:collaborat(?:e|ion)?|partner|together|work\s+with)\b", re.I)
_CONCRETE_TASK_RE = re.compile(
    r"\b(?:task|artifact|repo|repository|test|bug|build|implement|review|"
    r"code|patch|issue|pull\s+request|pr|result|acceptance|validate|reproduce)\b",
    re.I,
)
_REPO_TEST_HELP_RE = re.compile(
    r"\b(?:test\s+vectors?|did\s+publish\s+path|reproduc(?:e|ible|tion))\b",
    re.I,
)

_TRUST_CACHE_KEY: tuple | None = None
_TRUST_CACHE: dict[str, str] = {}
_BUILD_ACTIVATION_CONTEXT = False
_BUILD_RUNNING = False


def default_state() -> dict:
    state = _BASE_DEFAULT_STATE()
    state.setdefault("first_contact_intents", {})
    state.setdefault("first_contact_enabled", False)
    return state


def load(*, allow_legacy: bool = True) -> dict:
    state = _policy._BASE_LOAD(allow_legacy=allow_legacy)
    state.setdefault("first_contact_intents", {})
    state.setdefault("first_contact_enabled", False)
    if not isinstance(state["first_contact_intents"], dict):
        raise RuntimeError("autopilot first-contact state is invalid")
    if not isinstance(state["first_contact_enabled"], bool):
        raise RuntimeError("autopilot first-contact feature flag is invalid")
    return state


def set_first_contact_enabled(value: bool) -> dict:
    if not isinstance(value, bool):
        raise ValueError("first-contact feature flag must be boolean")
    state = load()
    if value and not state["paused"]:
        raise RuntimeError("first-contact enable requires paused autopilot")
    if state["first_contact_enabled"] != value:
        state["first_contact_enabled"] = value
        # Enabling a new policy must invalidate the #49 no-change fast path so
        # already-observed candidates are evaluated immediately, not only after
        # a future Resident state mutation.
        state["resident_revision"] = None
        save(state)
    return {
        "first_contact_enabled": value,
        "queued": status(state)["queued"],
    }


def _candidate_excerpt(candidate: dict) -> str:
    context = candidate.get("context", {})
    value = context.get("excerpt") if isinstance(context, dict) else None
    return value[:560] if isinstance(value, str) else ""


def _signed_source(candidate: dict) -> bool:
    signals = candidate.get("signals", {})
    if not isinstance(signals, dict):
        return False
    if candidate.get("category") == "conversation":
        return signals.get("direct_public_signed") is True
    facts = signals.get("facts", {})
    return isinstance(facts, dict) and int(facts.get("signed_message_count", 0) or 0) >= 1


def first_contact_eligible(candidate: dict) -> tuple[bool, str, str | None]:
    """Strict bootstrap lane; never reflects untrusted room text into output."""
    if _BUILD_RUNNING and not _BUILD_ACTIVATION_CONTEXT:
        return False, "first_contact_disabled", None
    if candidate.get("status") != "pending":
        return False, "candidate_not_pending", None
    room = candidate.get("room")
    if not isinstance(room, str) or not PUBLIC_ROOMS.fullmatch(room):
        return False, "non_public_or_owned_room", None
    category = candidate.get("category")
    if category not in FIRST_CONTACT_CATEGORIES:
        return False, "first_contact_category_blocked", None

    text = _candidate_excerpt(candidate)
    if not text:
        return False, "candidate_subject_unresolved", None
    if _UNTRUSTED_ACTION_RE.search(text):
        return False, "untrusted_sensitive_or_action_content", None
    if UNSUPPORTED_PUBLIC_FACT_RE.search(text):
        return False, "unsupported_public_fact", None
    if UNSUPPORTED_PROTOCOL_SEMANTICS_RE.search(text):
        return False, "reply_semantics_unsupported", None
    if not _signed_source(candidate):
        return False, "first_contact_unsigned_source", None

    signals = candidate.get("signals", {})
    if category == "conversation":
        if (
            signals.get("direct_public_signed") is True
            and signals.get("conversation_topic") == "agent_use_case"
            and is_explicit_agent_use_case_question(text)
        ):
            return True, "signed_public_direct_request", "agent_use_case"
        return False, "conversation_not_verified", None

    facts = signals.get("facts", {}) if isinstance(signals, dict) else {}
    if isinstance(facts, dict) and facts.get("inbound_to_us"):
        return False, "direct_context_is_never_auto_posted", None
    if (
        not isinstance(signals, dict)
        or signals.get("spam_noise_probability", 1) >= 0.20
        or signals.get("generic_template_probability", 1) > 0
        or signals.get("poetic_filler_count", 0)
    ):
        return False, "generic_or_noise", None
    if signals.get("concrete_evidence") is not True:
        return False, "no_public_concrete_evidence", None

    # A specific question may bootstrap only when the already-proven semantic
    # policy can answer that exact subject.  No generic fallback for vague facts,
    # current state, DID rotation details, or unsupported protocol semantics.
    if category == "specific_question":
        original = _BASE_ELIGIBLE(candidate)
        if original[0]:
            return original
        return False, original[1], original[2]

    explicit = observer.is_question_or_explicit_request(text)
    if category == "help_request":
        if not (explicit or _HELP_RE.search(text)) or not _CONCRETE_TASK_RE.search(text):
            return False, "help_request_context_unverified", None
    elif category == "technical_collaboration":
        if not (explicit or _COLLAB_RE.search(text)) or not _CONCRETE_TASK_RE.search(text):
            return False, "collaboration_not_concrete", None

    resolved, _ = resolve_candidate_topic(text)
    if (
        resolved is not None
        and reply_semantics_supported(text, resolved)
        and incremental_value_supported(text, resolved, category)[0]
    ):
        return True, "concrete_public_technical_request", resolved

    # Preserve the isolated Signer's proven deterministic renderer while making
    # concrete DID-publish/test-vector help actionable through its existing
    # repo_tests_bugs template.  No inbound text is copied into the reply.
    if category == "help_request" and _REPO_TEST_HELP_RE.search(text):
        return True, "concrete_public_technical_request", "repo_tests_bugs"

    # For explicit help/collaboration only, the old deterministic generic
    # templates are safe because they contain no untrusted text or live facts.
    if category == "technical_collaboration" and _COLLAB_RE.search(text):
        return True, "concrete_public_technical_request", "collaboration"
    if category == "help_request" and _HELP_RE.search(text):
        return True, "concrete_public_technical_request", "follow_up"
    return False, "candidate_subject_unresolved", None


def eligible(candidate: dict) -> tuple[bool, str, str | None]:
    original = _BASE_ELIGIBLE(candidate)
    if original[0] and candidate.get("category") not in TRANSPORT_SAFE_CATEGORIES:
        return False, "category_not_allowlisted", None
    if original[0]:
        return original
    if _BUILD_ACTIVATION_CONTEXT:
        bootstrap = first_contact_eligible(candidate)
        if bootstrap[0]:
            return bootstrap
    return original


def render(intent: dict) -> str:
    """Use the exact renderer already loaded by the isolated production Signer."""
    return _BASE_RENDER(intent)


def _autonomous_trust_map(local_state: dict, auto_state: dict) -> dict[str, str]:
    global _TRUST_CACHE_KEY, _TRUST_CACHE
    markers = _policy._markers(auto_state)
    key = (
        id(local_state),
        id(auto_state),
        len(markers),
        len(auto_state.get("outbox", {})),
        len(auto_state.get("receipts", {})),
    )
    if key == _TRUST_CACHE_KEY:
        return _TRUST_CACHE

    cutoff = datetime.now(UTC) - timedelta(days=FIRST_CONTACT_TRUST_DAYS)
    rows: dict[str, str] = {}
    for intent_id, marker in markers.items():
        if not isinstance(marker, dict):
            continue
        fingerprint = str(marker.get("fingerprint", ""))
        created = observer.parse_time(marker.get("created_at"))
        if not fingerprint or created is None or created <= cutoff:
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
        if stamp and (fingerprint not in rows or stamp > rows[fingerprint]):
            rows[fingerprint] = stamp

    _TRUST_CACHE_KEY = key
    _TRUST_CACHE = rows
    return rows


def sender_trusted_for_autopilot(
    candidate: dict,
    local_state: dict | None = None,
    auto_state: dict | None = None,
) -> bool:
    # Trust is only an identity/relationship gate. It must never widen the
    # semantics that are eligible for a follow-up. A trusted sender's current
    # candidate still has to pass the original pre-first-contact safety policy.
    base_allowed, _, _ = _BASE_ELIGIBLE(candidate)
    if not base_allowed or candidate.get("category") not in TRANSPORT_SAFE_CATEGORIES:
        return False
    state = local_state or resident.load_state()
    auto = auto_state or load()
    if _HUMAN_TRUSTED(candidate, state, auto):
        return True
    fingerprint = str(candidate.get("fingerprint", ""))
    return fingerprint in _autonomous_trust_map(state, auto)


def active_trusted_relationships(
    local_state: dict | None = None,
    auto_state: dict | None = None,
) -> list[dict]:
    state = local_state or resident.load_state()
    auto = auto_state or load()
    rows = {
        item["fingerprint"]: item["at"]
        for item in _HUMAN_ACTIVE_TRUSTED(state, auto)
    }
    for fingerprint, stamp in _autonomous_trust_map(state, auto).items():
        if fingerprint not in rows or stamp > rows[fingerprint]:
            rows[fingerprint] = stamp
    return [
        {"fingerprint": fingerprint, "at": stamp}
        for fingerprint, stamp in sorted(
            rows.items(), key=lambda item: item[1], reverse=True
        )
    ]


def _activation_rate_ok_preview(state: dict, intent: dict) -> tuple[bool, str]:
    """Preserve legacy trusted-lane queue semantics; Signer still enforces limits."""
    candidate_id = str(intent.get("source_candidate_id", ""))
    local = resident.load_state()
    candidate = local.get("candidates", {}).get(candidate_id)
    if isinstance(candidate, dict) and sender_trusted_for_autopilot(candidate, local, state):
        return True, "trusted_lane_signer_enforced"
    return _POLICY_RATE_OK_PREVIEW(state, intent)


def build_outbox() -> dict:
    """Run the policy builder; cold-start overlay is active only when explicitly enabled."""
    global _BUILD_ACTIVATION_CONTEXT, _BUILD_RUNNING
    state = load()
    _BUILD_RUNNING = True
    _BUILD_ACTIVATION_CONTEXT = bool(state.get("first_contact_enabled"))
    try:
        return _POLICY_BUILD_OUTBOX()
    finally:
        _BUILD_ACTIVATION_CONTEXT = False
        _BUILD_RUNNING = False


# Functions retained in policy/core resolve globals in their defining modules.
# Patch activation guards back into both modules.
_policy.default_state = default_state
_policy.load = load
_policy.first_contact_eligible = first_contact_eligible
_policy.eligible = eligible
_policy.render = render
_policy.sender_trusted_for_autopilot = sender_trusted_for_autopilot
_policy.active_trusted_relationships = active_trusted_relationships
_policy.rate_ok_preview = _activation_rate_ok_preview
_policy._core.default_state = default_state
_policy._core.load = load
_policy._core.eligible = eligible
_policy._core.render = render
_policy._core.sender_trusted_for_autopilot = sender_trusted_for_autopilot
_policy._core.active_trusted_relationships = active_trusted_relationships


class _FacadeModule(types.ModuleType):
    """Propagate legacy monkeypatch/config assignments into implementation modules."""

    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        if name.startswith("__") or name in {"autopilot_core", "autopilot_policy"}:
            return
        if hasattr(_policy, name):
            setattr(_policy, name, value)
        if hasattr(_policy._core, name):
            setattr(_policy._core, name, value)


sys.modules[__name__].__class__ = _FacadeModule