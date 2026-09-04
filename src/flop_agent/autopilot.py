"""Public Autopilot facade with activation safety compatibility.

The proven transport/publisher lives in ``autopilot_core``. The first-contact
policy lives in ``autopilot_policy``. This facade keeps legacy monkeypatch/config
compatibility, rejects hostile cold prompts, preserves the already-running
Signer's deterministic render behavior, and caches autonomous trust lookup so
activation remains cheap on large production state.
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
_POLICY_ELIGIBLE = _policy.eligible
_POLICY_FIRST_CONTACT = _policy.first_contact_eligible
_BASE_RENDER = _policy._BASE_RENDER
_HUMAN_TRUSTED = _policy._BASE_SENDER_TRUSTED
_HUMAN_ACTIVE_TRUSTED = _policy._BASE_ACTIVE_TRUSTED

TRANSPORT_SAFE_CATEGORIES = {
    "help_request",
    "specific_question",
    "technical_collaboration",
    "artifact_contribution",
    "conversation",
}

# Cold-start classification never follows these instructions. Rejecting them
# before semantic fallback also preserves the prior fail-closed behavior for
# prompt-injection shaped requests.
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

_TRUST_CACHE_KEY: tuple | None = None
_TRUST_CACHE: dict[str, str] = {}


def default_state() -> dict:
    state = _BASE_DEFAULT_STATE()
    state.setdefault("first_contact_intents", {})
    return state


def _candidate_excerpt(candidate: dict) -> str:
    context = candidate.get("context", {})
    value = context.get("excerpt") if isinstance(context, dict) else None
    return value[:560] if isinstance(value, str) else ""


def first_contact_eligible(candidate: dict) -> tuple[bool, str, str | None]:
    text = _candidate_excerpt(candidate)
    if text and _UNTRUSTED_ACTION_RE.search(text):
        return False, "untrusted_sensitive_or_action_content", None
    return _POLICY_FIRST_CONTACT(candidate)


def eligible(candidate: dict) -> tuple[bool, str, str | None]:
    result = _POLICY_ELIGIBLE(candidate)
    if result[0] and candidate.get("category") not in TRANSPORT_SAFE_CATEGORIES:
        return False, "category_not_allowlisted", None
    return result


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


# Functions retained in policy/core resolve globals in their defining modules.
# Patch the activation guards back into both modules.
_policy.default_state = default_state
_policy.first_contact_eligible = first_contact_eligible
_policy.eligible = eligible
_policy.render = render
_policy.sender_trusted_for_autopilot = sender_trusted_for_autopilot
_policy.active_trusted_relationships = active_trusted_relationships
_policy._core.default_state = default_state
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
