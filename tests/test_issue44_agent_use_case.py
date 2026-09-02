import copy
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import autopilot, autopilot_transport, core, discord_control, observer, resident


def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    local = resident.default_state()
    local["daemon"]["last_refresh_at"] = datetime.now(UTC).isoformat()
    resident.save_state(local)
    auto = autopilot.default_state()
    auto.update({"enabled": True, "paused": False, "migrated_at": "done"})
    autopilot.save(auto)


def candidate(candidate_id="ee56b6f53ef05f7c", *, text="@thadesuon seen — aws_agent_07 active in the agentic economy. what's your use case?"):
    return {
        "candidate_id": candidate_id, "did": "did:key:z6MkIssue44", "fingerprint": "ee56b6f53ef05f70",
        "room": "lobby", "seq": 44, "category": "specific_question", "priority": "high", "status": "pending",
        "created_at": datetime.now(UTC).isoformat(), "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "signals": {"spam_noise_probability": 0.0, "generic_template_probability": 0.0, "poetic_filler_count": 0,
                    "concrete_evidence": True, "conversation_continuity": False, "useful_agent_probability": 0.9,
                    "facts": {"inbound_to_us": False}},
        "context": {"excerpt": text, "untrusted": True},
    }


def put(item):
    state = resident.load_state()
    state["candidates"][item["candidate_id"]] = item
    state["relationships"][item["fingerprint"]] = {"did": item["did"], "approval_rejection_history": [], "interaction_history": []}
    resident.save_state(state)


@pytest.mark.parametrize("text", ["what's your use case?", "what is your use case?"])
def test_explicit_agent_use_case_question_resolves_and_has_fixed_profile_reply(monkeypatch, tmp_path, text):
    setup(monkeypatch, tmp_path)
    item = candidate(text=text)
    assert autopilot.resolve_candidate_topic(text) == ("agent_use_case", "candidate_subject_resolved")
    assert autopilot.reply_semantics_supported(text, "agent_use_case") is True
    allowed, reason, topic = autopilot.eligible(item)
    assert (allowed, topic) == (True, "agent_use_case")
    intent = autopilot.make_intent(item, topic, reason)
    preview, preview_reason, preview_topic = discord_control.candidate_outbound_preview(item)
    assert (preview, preview_reason, preview_topic) == (autopilot.render(intent), reason, topic)
    profile = autopilot.public_knowledge()
    assert all(capability in preview for capability in profile["capabilities"])
    assert profile["project_repository"] in preview
    assert autopilot_transport.validate_intent(autopilot.export_intent(intent))["topic"] == "agent_use_case"


def test_production_ee56_equivalent_is_eligible_with_read_only_preview(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    item = candidate()
    put(item)
    before_auto, before_resident = copy.deepcopy(autopilot.load()), copy.deepcopy(resident.load_state())
    assert autopilot.eligible(item) == (True, "concrete_public_technical_request", "agent_use_case")
    assert discord_control.trust_candidates() == [item]
    preview, reason, topic = discord_control.candidate_outbound_preview(item)
    assert preview == autopilot.render(autopilot.make_intent(item, topic, reason))
    assert autopilot.load() == before_auto and resident.load_state() == before_resident


@pytest.mark.parametrize("text", [
    "What is the use case for this protocol?",
    "What is your use case for this protocol?",
    "Here are three use cases for agents.",
    "Helper bot: need onboarding or DID setup?",
    "How does fast sequencer bootstrap frugal auctions? Via retro thesis.",
    "why did you pick Technocore?",
    "what is your current state?",
    "what is your heartbeat interval?",
])
def test_generic_third_party_protocol_and_unsupported_agent_questions_fail_closed(monkeypatch, tmp_path, text):
    setup(monkeypatch, tmp_path)
    item = candidate(text=text)
    assert autopilot.resolve_candidate_topic(text)[0] != "agent_use_case"
    assert autopilot.eligible(item)[0] is False
