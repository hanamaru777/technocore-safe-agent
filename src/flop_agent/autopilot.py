"""Public Autopilot facade with activation safety compatibility.

The proven transport/publisher lives in ``autopilot_core``.  The first-contact
policy lives in ``autopilot_policy``.  This facade adds transport-category
compatibility and caches autonomous trust resolution so the activation path
remains cheap on large production state.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from . import autopilot_policy as _policy

for _name in dir(_policy):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_policy, _name)

autopilot_core = _policy.autopilot_core
autopilot_policy = _policy

_POLICY_ELIGIBLE = _policy.eligible
_HUMAN_TRUSTED = _policy._BASE_SENDER_TRUSTED
_HUMAN_ACTIVE_TRUSTED = _policy._BASE_ACTIVE_TRUSTED

TRANSPORT_SAFE_CATEGORIES = {
    "help_request",
    "specific_question",
    "technical_collaboration",
    "artifact_contribution",
    "conversation",
}

_TRUST_CACHE_KEY: tuple | None = None
_TRUST_CACHE: dict[str, str] = {}


def eligible(candidate: dict) -> tuple[bool, str, str | None]:
    result = _POLICY_ELIGIBLE(candidate)
    if result[0] and candidate.get("category") not in TRANSPORT_SAFE_CATEGORIES:
        return False, "category_not_allowlisted", None
    return result


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


# Functions retained in the policy/core modules resolve their globals in those
# modules, so patch the public compatibility guards back into both.
_policy.eligible = eligible
_policy.sender_trusted_for_autopilot = sender_trusted_for_autopilot
_policy.active_trusted_relationships = active_trusted_relationships
_policy._core.eligible = eligible
_policy._core.sender_trusted_for_autopilot = sender_trusted_for_autopilot
_policy._core.active_trusted_relationships = active_trusted_relationships
