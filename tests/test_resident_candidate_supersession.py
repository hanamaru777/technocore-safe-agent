import json
from datetime import UTC, datetime, timedelta

from flop_agent import (
    autopilot,
    core,
    observer,
    observer_resident_isolation,
    resident,
    resident_candidate_supersession as supersession,
)


OWN = "did:key:z6MkOwn"
OTHER = "did:key:z6MkOther"


def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    (tmp_path / "verified-did.json").write_text(
        json.dumps({"did": OWN}), encoding="utf-8"
    )
    observed = observer.default_state()
    fingerprint = core.did_note_location(OTHER)[2]
    stamp = datetime.now(UTC).isoformat()
    observed["agents"][fingerprint] = {
        "did": OTHER,
        "fingerprint": fingerprint,
        "facts": {
            "first_seen": stamp,
            "last_seen": stamp,
            "last_encounter_at": stamp,
            "seen_count": 2,
            "rooms": ["lobby"],
            "message_refs": [],
            "recent_messages": [
                {
                    "room": "lobby",
                    "seq": 101,
                    "ts": stamp,
                    "text": f"{OWN} can you review this repo test issue?",
                    "signed": True,
                }
            ],
            "signed_count": 1,
            "unsigned_count": 0,
            "interaction_with_us": False,
        },
        "inferences": {
            "contribution_url_candidates": [],
            "role_candidates": [],
            "repeat_seen": False,
        },
    }
    observed["cursors"]["lobby"] = 101
    return observed, fingerprint


def weak_candidate(fingerprint, *, status="pending", priority="high"):
    created = (datetime.now(UTC) - timedelta(minutes=10)).isoformat()
    return {
        "candidate_id": "weak",
        "did": OTHER,
        "fingerprint": fingerprint,
        "room": "lobby",
        "seq": 90,
        "category": "specific_question",
        "priority": priority,
        "signals": {"direct_public_signed": False},
        "context": {"excerpt": "generic repo question", "untrusted": True},
        "created_at": created,
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "status": status,
    }


def save_with_candidate(fingerprint, item):
    state = resident.default_state()
    state["candidates"][item["candidate_id"]] = item
    state["relationships"][fingerprint] = {
        "did": OTHER,
        "relationship_state": "observed",
        "first_seen": item["created_at"],
        "last_seen": item["created_at"],
        "last_interaction": None,
        "rooms": ["lobby"],
        "important_messages": [],
        "topics": [],
        "role_candidates": [],
        "contribution_candidates": [],
        "questions": [],
        "help_requests": [],
        "interaction_history": [],
        "our_previous_action": None,
        "approval_rejection_history": [],
    }
    resident.save_state(state)


def test_signed_direct_request_supersedes_weaker_pending_and_creates_direct(monkeypatch, tmp_path):
    observed, fingerprint = setup(monkeypatch, tmp_path)
    save_with_candidate(fingerprint, weak_candidate(fingerprint))

    supersession.refresh(observed)
    state = resident.load_state()

    weak = state["candidates"]["weak"]
    assert weak["status"] == "expired"
    assert weak["expiration_reason"] == supersession.SUPERSEDED_REASON
    direct = [
        item
        for item in state["candidates"].values()
        if item.get("signals", {}).get("direct_public_signed") is True
    ]
    assert len(direct) == 1
    assert direct[0]["seq"] == 101
    assert direct[0]["status"] == "pending"
    history = state["relationships"][fingerprint]["interaction_history"]
    assert any(item.get("kind") == "candidate_superseded" for item in history)


def test_critical_pending_is_never_superseded(monkeypatch, tmp_path):
    observed, fingerprint = setup(monkeypatch, tmp_path)
    save_with_candidate(fingerprint, weak_candidate(fingerprint, priority="critical"))

    supersession.refresh(observed)
    state = resident.load_state()

    assert state["candidates"]["weak"]["status"] == "pending"
    assert not [
        item
        for item in state["candidates"].values()
        if item.get("signals", {}).get("direct_public_signed") is True
    ]


def test_approved_candidate_is_never_superseded(monkeypatch, tmp_path):
    observed, fingerprint = setup(monkeypatch, tmp_path)
    item = weak_candidate(fingerprint, status="approved")
    item["feedback_at"] = datetime.now(UTC).isoformat()
    save_with_candidate(fingerprint, item)

    supersession.refresh(observed)
    state = resident.load_state()

    assert state["candidates"]["weak"]["status"] == "approved"
    assert not [
        candidate
        for candidate in state["candidates"].values()
        if candidate.get("signals", {}).get("direct_public_signed") is True
    ]


def test_only_narrow_superseded_expiry_is_removed_from_generation_cooldown(monkeypatch, tmp_path):
    _, fingerprint = setup(monkeypatch, tmp_path)
    supersession.install()
    current = datetime.now(UTC)

    state = resident.default_state()
    normal = weak_candidate(fingerprint, status="expired")
    normal["expired_at"] = current.isoformat()
    normal["expiration_reason"] = "candidate_ttl_elapsed"
    state["candidates"]["normal"] = normal
    assert OTHER in resident._latest_candidate_times(state)

    normal["expiration_reason"] = supersession.SUPERSEDED_REASON
    assert OTHER not in resident._latest_candidate_times(state)


def test_prepare_keeps_critical_opportunity_but_filters_weaker_race(monkeypatch, tmp_path):
    observed, _ = setup(monkeypatch, tmp_path)
    observed["opportunities"] = [
        {"did": OTHER, "kind": "question_candidate"},
        {"did": OTHER, "kind": "inbound_mailbox_message"},
        {"did": "did:key:z6MkThird", "kind": "question_candidate"},
    ]
    prepared = supersession._prepare_observed(observed, {OTHER})
    assert [(item["did"], item["kind"]) for item in prepared["opportunities"]] == [
        (OTHER, "inbound_mailbox_message"),
        ("did:key:z6MkThird", "question_candidate"),
    ]


def test_maintenance_cycle_uses_local_supersession_then_builds_outbox(monkeypatch):
    observed = {"marker": "observer"}
    calls = []
    monkeypatch.setattr(observer, "load_state", lambda: observed)
    monkeypatch.setattr(
        supersession,
        "refresh",
        lambda value: calls.append(("refresh", value)),
    )
    monkeypatch.setattr(
        autopilot,
        "build_outbox",
        lambda: calls.append(("outbox", None)),
    )

    observer_resident_isolation.maintenance_cycle()
    assert calls == [("refresh", observed), ("outbox", None)]
