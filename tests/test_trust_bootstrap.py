import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import autopilot, core, discord_control, observer, resident


OWN = "did:key:z6MkOwnBootstrap"
OTHER = "did:key:z6MkOtherBootstrap"


def setup_state(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    observed = observer.default_state()
    observed["agents"]["otherboot"] = {
        "did": OTHER,
        "facts": {
            "recent_messages": [{
                "room": "lobby", "seq": 7, "ts": datetime.now(UTC).isoformat(),
                "text": "Can you explain nonce safety for a public API test?", "signed": True,
            }],
        },
    }
    observer.save_state(observed)
    local = resident.default_state()
    local["relationships"]["otherboot"] = {
        "did": OTHER, "approval_rejection_history": [], "interaction_history": [],
        "relationship_state": "unknown", "last_interaction": None,
    }
    local["daemon"]["last_refresh_at"] = datetime.now(UTC).isoformat()
    resident.save_state(local)
    auto = autopilot.default_state()
    auto.update({"enabled": True, "paused": False, "migrated_at": "done"})
    autopilot.save(auto)


def candidate(candidate_id="candidate-first", *, seq=7, expires_at=None, room="lobby"):
    return {
        "candidate_id": candidate_id, "did": OTHER, "fingerprint": "otherboot",
        "room": room, "seq": seq, "category": "conversation", "priority": "medium",
        "created_at": datetime.now(UTC).isoformat(),
        "expires_at": expires_at or (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "status": "pending", "why": "signed public direct request mapped to an allowlisted topic",
        "signals": {"direct_public_signed": True, "conversation_topic": "nonce", "facts": {"inbound_to_us": False}},
        "context": {"excerpt": "@everyone https://untrusted.invalid nonce safety?", "untrusted": True},
        "safety_decision": "signed_public_direct_request",
    }


def put_candidate(item):
    state = resident.load_state()
    state["candidates"][item["candidate_id"]] = item
    resident.save_state(state)


def test_fresh_trust_bootstrap_stages_one_reply_then_unlocks_existing_path(monkeypatch, tmp_path):
    setup_state(monkeypatch, tmp_path)
    first = candidate()
    put_candidate(first)
    control = discord_control.Control({"operator"}, "channel")

    assert "candidate-first" in control.command("operator", "/trust-candidates", "channel")["message"]
    assert "初回trust設定が必要" in control.command("operator", "/status", "channel")["message"]
    approved = control.command("operator", "/approve candidate-first", "channel")
    assert approved["ok"] and "not posted" in approved["message"]
    assert autopilot.load()["outbox"] == {}
    assert autopilot.load()["receipts"] == {}
    assert autopilot.load()["rate_history"] == []
    assert "otherboo" in control.command("operator", "/trusted", "channel")["message"]

    assert not control.command("operator", "/reply-approved candidate-first send", "channel")["ok"]
    assert autopilot.load()["outbox"] == {}
    staged = control.command("operator", "/reply-approved candidate-first SEND", "channel")
    assert staged["ok"] and "STAGED" in staged["message"]
    state = autopilot.load()
    assert len(state["outbox"]) == 1 and state["receipts"] == {}
    with pytest.raises(RuntimeError, match="already staged"):
        autopilot.stage_approved_reply("candidate-first")

    intent_id = staged["data"]["intent_id"]
    intent = state["outbox"][intent_id]
    rendered = autopilot.render(intent)
    state["receipts"][intent_id] = {"at": datetime.now(UTC).isoformat(), "text_hash": hashlib.sha256(rendered.encode()).hexdigest()}
    state["rate_history"].append({"at": datetime.now(UTC).isoformat(), "fingerprint": "otherboot", "room": "lobby", "text_hash": hashlib.sha256(rendered.encode()).hexdigest()})
    autopilot.save(state)
    activity = discord_control.activity_snapshot()
    assert activity["posts"] == 1 and activity["latest_post"]
    assert "nonce" in discord_control.history_message("otherboot")
    assert len(discord_control.trusted_relationships()) == 1

    follow_up = candidate("candidate-follow-up", seq=8)
    put_candidate(follow_up)
    autopilot.build_outbox()
    assert any(item["source_candidate_id"] == "candidate-follow-up" for item in autopilot.queue()["outbox"])


@pytest.mark.parametrize("mutate", [
    lambda item: item.update({"expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()}),
    lambda item: item.update({"room": "mb-p-private"}),
    lambda item: item["signals"].update({"direct_public_signed": False}),
])
def test_approved_reply_revalidates_safety_before_staging(monkeypatch, tmp_path, mutate):
    setup_state(monkeypatch, tmp_path)
    item = candidate(); mutate(item); put_candidate(item)
    resident.feedback("candidate-first", "approved")
    with pytest.raises(RuntimeError):
        autopilot.stage_approved_reply("candidate-first")
    assert autopilot.load()["outbox"] == {}


def test_approved_reply_requires_exact_human_approval_and_non_mutating_rate_preview(monkeypatch, tmp_path):
    setup_state(monkeypatch, tmp_path)
    put_candidate(candidate())
    state = resident.load_state()
    state["candidates"]["candidate-first"]["status"] = "approved"
    resident.save_state(state)
    before = autopilot.load()
    with pytest.raises(RuntimeError, match="approval"):
        autopilot.stage_approved_reply("candidate-first")
    assert autopilot.load()["rate_history"] == before["rate_history"]


def test_normal_pending_eligibility_semantics_are_unchanged():
    item = candidate()
    assert autopilot.eligible(item) == (True, "signed_public_direct_request", "nonce")
    item["status"] = "approved"
    assert autopilot.eligible(item) == (False, "candidate_not_pending", None)
    assert autopilot.eligible_approved_candidate(item) == (True, "signed_public_direct_request", "nonce")
