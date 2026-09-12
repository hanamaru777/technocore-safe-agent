"""Local-only Resident candidate supersession for stronger signed direct requests.

A Resident candidate is only a local planning object.  This overlay never signs,
posts, follows URLs, reads signer material, or changes Autopilot publication rate
limits.  It prevents an older/weaker *pending* candidate from monopolising a DID's
six-hour candidate-generation cooldown when the Observer has a signed public
request explicitly addressed to our DID.
"""
from __future__ import annotations

from datetime import UTC, datetime

from . import conversation_planner, observer, resident

SUPERSEDED_REASON = "superseded_by_stronger_direct_request"
_HISTORY_LIMIT = 50
_INSTALLED = False
_ORIGINAL_LATEST = None
_DIRECT_DIDS: set[str] = set()


def _is_direct(item: dict) -> bool:
    signals = item.get("signals", {})
    return isinstance(signals, dict) and signals.get("direct_public_signed") is True


def _direct_dids(observed: dict) -> set[str]:
    own_did = observer.verified_did()
    if not own_did:
        return set()
    result: set[str] = set()
    for agent in observed.get("agents", {}).values():
        if not isinstance(agent, dict):
            continue
        did = agent.get("did")
        if not isinstance(did, str) or did == own_did:
            continue
        facts = agent.get("facts", {})
        for message in facts.get("recent_messages", []):
            if not isinstance(message, dict) or not isinstance(message.get("seq"), int):
                continue
            plan = conversation_planner.plan(
                room=message.get("room", ""),
                sender_did=did,
                signed=message.get("signed") is True,
                text=message.get("text", ""),
                own_did=own_did,
            )
            if plan:
                result.add(did)
                break
    return result


def _expire_weaker_pending(state: dict, did: str, at: str) -> None:
    """Expire only unapproved, unpublished, non-critical, non-direct candidates."""
    direct_ids = [
        item.get("candidate_id")
        for item in state.get("candidates", {}).values()
        if isinstance(item, dict)
        and item.get("did") == did
        and item.get("status") == "pending"
        and _is_direct(item)
    ]
    superseding = next((value for value in direct_ids if isinstance(value, str)), None)
    for item in state.get("candidates", {}).values():
        if (
            not isinstance(item, dict)
            or item.get("did") != did
            or item.get("status") != "pending"
            or item.get("priority") == "critical"
            or _is_direct(item)
        ):
            continue
        item["status"] = "expired"
        item["expired_at"] = at
        item["expiration_reason"] = SUPERSEDED_REASON
        if superseding:
            item["superseded_by"] = superseding
        fingerprint = item.get("fingerprint")
        relationship = state.get("relationships", {}).get(fingerprint)
        if isinstance(relationship, dict):
            history = relationship.setdefault("interaction_history", [])
            if isinstance(history, list):
                history.append(
                    {
                        "kind": "candidate_superseded",
                        "candidate_id": item.get("candidate_id"),
                        "reason": SUPERSEDED_REASON,
                        "at": at,
                    }
                )
                del history[:-_HISTORY_LIMIT]


def _latest_candidate_times(state: dict):
    """Patch point called inside Resident's single load/mutate/save refresh cycle."""
    assert _ORIGINAL_LATEST is not None
    at = datetime.now(UTC).isoformat()
    for did in _DIRECT_DIDS:
        _expire_weaker_pending(state, did, at)

    # Resident intentionally lets all normal candidate states participate in its
    # generation cooldown.  Exclude only candidates that this overlay just expired
    # for the narrow supersession reason; every approval/publication/rejection and
    # every ordinary pending/expired record keeps the original cooldown semantics.
    filtered = {
        key: item
        for key, item in state.get("candidates", {}).items()
        if not (
            isinstance(item, dict)
            and item.get("status") == "expired"
            and item.get("expiration_reason") == SUPERSEDED_REASON
        )
    }
    proxy = dict(state)
    proxy["candidates"] = filtered
    return _ORIGINAL_LATEST(proxy)


def _prepare_observed(observed: dict, direct_dids: set[str]) -> dict:
    """Keep critical opportunities, but do not let weaker ones race a direct request."""
    if not direct_dids:
        return observed
    opportunities = observed.get("opportunities")
    if not isinstance(opportunities, list):
        return observed
    observed["opportunities"] = [
        item
        for item in opportunities
        if not (
            isinstance(item, dict)
            and item.get("did") in direct_dids
            and item.get("kind") != "inbound_mailbox_message"
        )
    ]
    return observed


def install() -> None:
    """Install only the local Resident timestamp hook, idempotently."""
    global _INSTALLED, _ORIGINAL_LATEST
    if _INSTALLED:
        return
    _ORIGINAL_LATEST = resident._latest_candidate_times
    resident._latest_candidate_times = _latest_candidate_times
    _INSTALLED = True


def refresh(observed: dict) -> dict:
    """Run one Resident refresh with narrow supersession context."""
    global _DIRECT_DIDS
    install()
    direct = _direct_dids(observed)
    _DIRECT_DIDS = direct
    try:
        return resident.refresh(observed_state=_prepare_observed(observed, direct))
    finally:
        _DIRECT_DIDS = set()
