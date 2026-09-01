import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import autopilot, core, discord_control, observer, oracle_signer, resident


OWN = "did:key:z6MkOwnBootstrap"
OTHER = "did:key:z6MkOtherBootstrap"
SIGNER_DID = "did:key:z6Mk123456789ABCDEFGHJKLMNPQRSTUVWXYZabc"


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


def acknowledge_with_existing_oracle_semantics(intent_id):
    state = autopilot.load()
    item = state["outbox"][intent_id]
    exported = autopilot.export_intent(item)
    text = autopilot.render(item)
    receipt = {
        "state": "prepared", "did": SIGNER_DID, "nonce": "123",
        "text_hash": hashlib.sha256(text.encode()).hexdigest(),
        "receipt_hash": oracle_signer.receipt_hash(exported, SIGNER_DID, "123", text),
        "prepared_at": datetime.now(UTC).isoformat(),
    }
    oracle_signer.mark_acknowledged(state, {"schema_version": 1, "receipts": {intent_id: receipt}}, exported, receipt)


def test_fresh_trust_bootstrap_stages_one_reply_then_unlocks_existing_path(monkeypatch, tmp_path):
    setup_state(monkeypatch, tmp_path)
    second = candidate("candidate-second", seq=8)
    first = candidate()
    put_candidate(second); put_candidate(first)
    control = discord_control.Control({"operator"}, "channel")

    assert "candidate-first" in control.command("operator", "/trust-candidates", "channel")["message"]
    assert "初回trust設定が必要" in control.command("operator", "/status", "channel")["message"]
    approved = control.command("operator", "/approve candidate-first", "channel")
    assert approved["ok"] and "not posted" in approved["message"]
    assert autopilot.load()["outbox"] == {}
    assert autopilot.load()["receipts"] == {}
    assert autopilot.load()["rate_history"] == []
    assert "active trusted counterpart: 0" in control.command("operator", "/trusted", "channel")["message"]
    assert "初回返信待ち" in control.command("operator", "/trusted", "channel")["message"]
    assert "初回trust設定が必要" in control.command("operator", "/activity", "channel")["message"]
    autopilot.build_outbox()
    assert autopilot.load()["outbox"] == {}

    assert not control.command("operator", "/reply-approved candidate-first send", "channel")["ok"]
    assert autopilot.load()["outbox"] == {}
    staged = control.command("operator", "/reply-approved candidate-first SEND", "channel")
    assert staged["ok"] and "STAGED" in staged["message"]
    state = autopilot.load()
    assert len(state["outbox"]) == 1 and state["receipts"] == {}
    autopilot.build_outbox()
    assert len(autopilot.load()["outbox"]) == 1
    with pytest.raises(RuntimeError, match="already staged"):
        autopilot.stage_approved_reply("candidate-first")

    intent_id = staged["data"]["intent_id"]
    acknowledge_with_existing_oracle_semantics(intent_id)
    activity = discord_control.activity_snapshot()
    assert activity["posts"] == 1 and activity["latest_post"]
    assert "nonce" in discord_control.history_message("otherboot")
    assert len(discord_control.trusted_relationships()) == 1

    follow_up = candidate("candidate-follow-up", seq=9)
    put_candidate(follow_up)
    autopilot.build_outbox()
    assert any(item["source_candidate_id"] == "candidate-follow-up" for item in autopilot.queue()["outbox"])


@pytest.mark.parametrize("terminal", ["ambiguous", "quarantined"])
def test_terminal_bootstrap_intent_never_activates_counterpart_trust(monkeypatch, tmp_path, terminal):
    setup_state(monkeypatch, tmp_path)
    put_candidate(candidate()); put_candidate(candidate("candidate-second", seq=8))
    control = discord_control.Control({"operator"}, "channel")
    assert control.command("operator", "/approve candidate-first", "channel")["ok"]
    intent_id = control.command("operator", "/reply-approved candidate-first SEND", "channel")["data"]["intent_id"]
    state = autopilot.load(); state["outbox"][intent_id]["status"] = terminal; autopilot.save(state)
    autopilot.build_outbox()
    assert len(autopilot.load()["outbox"]) == 1
    assert discord_control.trusted_relationships() == []


def test_manual_published_candidate_is_durable_active_trust(monkeypatch, tmp_path):
    setup_state(monkeypatch, tmp_path)
    put_candidate(candidate())
    resident.feedback("candidate-first", "approved")
    state = resident.load_state()
    state["candidates"]["candidate-first"].update({"status": "published", "published_at": datetime.now(UTC).isoformat()})
    state["published"].append({"candidate_id": "candidate-first", "at": datetime.now(UTC).isoformat(), "permalink": "https://technocore.chat/humans#r/lobby/7"})
    resident.save_state(state)
    follow_up = candidate("candidate-follow-up", seq=8)
    assert autopilot.sender_trusted_for_autopilot(follow_up)


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
