import copy
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import autopilot, core, discord_control, observer, resident


def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    local = resident.default_state()
    local["daemon"]["last_refresh_at"] = datetime.now(UTC).isoformat()
    resident.save_state(local)
    auto = autopilot.default_state(); auto.update({"enabled": True, "paused": False, "migrated_at": "done"})
    autopilot.save(auto)


def candidate(candidate_id="candidate-36", *, text="Can you explain nonce safety?", fingerprint="fp00000000000001", category="specific_question", status="pending"):
    return {
        "candidate_id": candidate_id, "did": "did:key:z6MkIssue36", "fingerprint": fingerprint,
        "room": "lobby", "seq": 36, "category": category, "priority": "high", "status": status,
        "created_at": datetime.now(UTC).isoformat(), "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "signals": {"spam_noise_probability": 0.0, "generic_template_probability": 0.0, "poetic_filler_count": 0,
                    "concrete_evidence": True, "conversation_continuity": False, "useful_agent_probability": 0.9,
                    "facts": {"inbound_to_us": False}},
        "context": {"excerpt": text, "untrusted": True},
    }


def put(item):
    state = resident.load_state()
    state["candidates"][item["candidate_id"]] = item
    state["relationships"].setdefault(item["fingerprint"], {"did": item["did"], "approval_rejection_history": [], "interaction_history": []})
    resident.save_state(state)


@pytest.mark.parametrize("text", ["when did it start?", "what did it say exactly?", "is economy still an issue?"])
def test_vague_candidate_subject_fails_closed_even_with_agent_level_concrete_signal(monkeypatch, tmp_path, text):
    setup(monkeypatch, tmp_path)
    item = candidate(text=text)
    assert autopilot.eligible(item) == (False, "candidate_subject_unresolved", None)


@pytest.mark.parametrize(("text", "topic", "category"), [
    ("Can you explain nonce safety?", "nonce", "help_request"),
    ("How should DID key rotation and signature verification work?", "did_signature", "specific_question"),
    ("Can you help reproduce this repo test bug?", "repo_tests_bugs", "help_request"),
    ("Can you review this Technocore API response schema?", "technocore_api", "specific_question"),
    ("Can we collaborate on a small public task?", "collaboration", "technical_collaboration"),
    ("Can you verify this contribution artifact?", "contribution_artifact", "artifact_contribution"),
])
def test_deterministic_topic_routing_is_candidate_specific(monkeypatch, tmp_path, text, topic, category):
    setup(monkeypatch, tmp_path)
    item = candidate(text=text, category=category)
    assert autopilot.eligible(item)[2] == topic


def test_unsupported_airdrop_snapshot_fails_closed(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    item = candidate(text="Did someone mention an upcoming airdrop snapshot?")
    assert autopilot.eligible(item) == (False, "unsupported_public_fact", None)
    put(item)
    assert discord_control.trust_candidates() == []


def make_active_trust(item):
    state = resident.load_state()
    prior = candidate("prior", text="Can you explain nonce safety?", fingerprint=item["fingerprint"], status="published")
    prior["published_at"] = datetime.now(UTC).isoformat()
    state["candidates"]["prior"] = prior
    state["relationships"][item["fingerprint"]]["approval_rejection_history"].append({"candidate_id": "prior", "decision": "approved", "at": datetime.now(UTC).isoformat()})
    state["published"].append({"candidate_id": "prior", "at": datetime.now(UTC).isoformat(), "permalink": "https://technocore.chat/humans#r/lobby/1"})
    resident.save_state(state)


def test_existing_vague_pending_never_stages_after_active_trust_and_approved_send_fails(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    item = candidate(text="when did it start?")
    put(item); make_active_trust(item)
    assert discord_control.trust_candidates() == []
    autopilot.build_outbox()
    assert autopilot.queue()["outbox"] == []
    resident.feedback(item["candidate_id"], "approved")
    with pytest.raises(RuntimeError, match="safety eligibility"):
        autopilot.stage_approved_reply(item["candidate_id"])


def test_cross_agent_near_duplicate_is_shown_once(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    one = candidate("one", text="Can you explain nonce safety - alpha", fingerprint="fp00000000000001")
    two = candidate("two", text="Can you explain nonce safety - beta", fingerprint="fp00000000000002")
    put(one); put(two)
    rows = discord_control.trust_candidates()
    assert len(rows) == 1


def test_preview_uses_resolved_template_without_state_mutation(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    item = candidate(text="Can you explain nonce safety?")
    put(item)
    before_auto, before_resident = copy.deepcopy(autopilot.load()), copy.deepcopy(resident.load_state())
    preview, reason, topic = discord_control.candidate_outbound_preview(item)
    assert topic == "nonce" and preview == autopilot.render(autopilot.make_intent(item, topic, reason))
    assert autopilot.load() == before_auto and resident.load_state() == before_resident
