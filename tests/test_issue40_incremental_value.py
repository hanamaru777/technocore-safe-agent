import copy
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import autopilot, core, discord_control, observer, resident


def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    local = resident.default_state(); local["daemon"]["last_refresh_at"] = datetime.now(UTC).isoformat(); resident.save_state(local)
    auto = autopilot.default_state(); auto.update({"enabled": True, "paused": False, "migrated_at": "done"}); autopilot.save(auto)


def candidate(candidate_id="candidate-40", *, text, category="help_request", fingerprint="fp00000000000040"):
    return {
        "candidate_id": candidate_id, "did": "did:key:z6MkIssue40", "fingerprint": fingerprint, "room": "lobby", "seq": 40,
        "category": category, "priority": "high", "status": "pending", "created_at": datetime.now(UTC).isoformat(),
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "signals": {"spam_noise_probability": 0.0, "generic_template_probability": 0.0, "poetic_filler_count": 0, "concrete_evidence": True,
                    "conversation_continuity": False, "useful_agent_probability": 0.9, "facts": {"inbound_to_us": False}},
        "context": {"excerpt": text, "untrusted": True},
    }


def put(item):
    state = resident.load_state(); state["candidates"][item["candidate_id"]] = item
    state["relationships"].setdefault(item["fingerprint"], {"did": item["did"], "approval_rejection_history": [], "interaction_history": []})
    resident.save_state(state)


def active_trust(item):
    state = resident.load_state()
    prior = candidate("prior-40", text="Can you explain nonce reuse safety?", fingerprint=item["fingerprint"])
    prior.update({"status": "published", "published_at": datetime.now(UTC).isoformat()})
    state["candidates"][prior["candidate_id"]] = prior
    state["relationships"][item["fingerprint"]]["approval_rejection_history"].append({"candidate_id": prior["candidate_id"], "decision": "approved", "at": datetime.now(UTC).isoformat()})
    state["published"].append({"candidate_id": prior["candidate_id"], "at": datetime.now(UTC).isoformat(), "permalink": "https://technocore.chat/humans#r/lobby/1"})
    resident.save_state(state)


def test_nonce_echo_candidate_is_revalidated_at_every_gate(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    item = candidate("85262de3a66fa9b2", text="Your post: create a signature by signing room|nonce|text. Keep the nonce strictly increasing.")
    put(item); active_trust(item)
    assert autopilot.inbound_canonical_claims(item["context"]["excerpt"], "nonce") == {"nonce_strictly_increasing_per_did_room"}
    assert autopilot.eligible(item) == (False, "redundant_reply", "nonce")
    assert discord_control.trust_candidates() == []
    before_auto, before_resident = copy.deepcopy(autopilot.load()), copy.deepcopy(resident.load_state())
    assert discord_control.candidate_outbound_preview(item) == (None, "redundant_reply", "nonce")
    assert autopilot.load() == before_auto and resident.load_state() == before_resident
    message = discord_control.candidate_message(item)
    assert "resolved topic: nonce" in message and "reply relevance: redundant" in message
    autopilot.build_outbox(); assert autopilot.queue()["outbox"] == []
    resident.feedback(item["candidate_id"], "approved")
    with pytest.raises(RuntimeError, match="safety eligibility"):
        autopilot.stage_approved_reply(item["candidate_id"])


def test_complete_nonce_echo_is_redundant(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    item = candidate(text="Keep the nonce strictly increasing for each DID and room. Do not reuse it after success.")
    assert autopilot.eligible(item) == (False, "redundant_reply", "nonce")


@pytest.mark.parametrize(("text", "topic"), [
    ("Can you explain nonce reuse safety?", "nonce"),
    ("How do I verify a did:key signature?", "did_signature"),
])
def test_genuine_question_has_incremental_fixed_reply(monkeypatch, tmp_path, text, topic):
    setup(monkeypatch, tmp_path)
    item = candidate(text=text)
    allowed, reason, resolved = autopilot.eligible(item)
    assert allowed is True and resolved == topic
    assert discord_control.candidate_outbound_preview(item) == (autopilot.render(autopilot.make_intent(item, topic, reason)), reason, topic)


def test_artifact_nonce_echo_is_rejected_but_explicit_artifact_question_can_pass(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    echo = candidate(text="I published a contribution about keeping nonces strictly increasing.", category="artifact_contribution")
    assert autopilot.eligible(echo) == (False, "redundant_reply", "nonce")
    question = candidate("artifact-question", text="Can you verify this contribution artifact's public evidence?", category="artifact_contribution")
    assert autopilot.eligible(question)[0] is True
