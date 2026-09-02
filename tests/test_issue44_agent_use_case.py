import copy
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import autopilot, autopilot_transport, conversation_planner, core, discord_control, observer, resident


OWN = "did:key:z6MkOwnIssue44"
OTHER = "did:key:z6MkOtherIssue44"


def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    (tmp_path / "verified-did.json").write_text('{"did": "' + OWN + '"}', encoding="utf-8")
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


def direct_candidate(text: str):
    plan = conversation_planner.plan(room="lobby", sender_did=OTHER, signed=True, own_did=OWN, text=f"{OWN} {text}")
    assert plan == {"topic": "agent_use_case", "category": "conversation", "safety_decision": "signed_public_direct_request"}
    item = candidate("direct-use-case", text=f"{OWN} {text}")
    item.update({"did": OTHER, "category": plan["category"], "why": "signed public direct request mapped to an allowlisted topic", "safety_decision": plan["safety_decision"]})
    item["signals"] = {"direct_public_signed": True, "conversation_topic": plan["topic"], "facts": {"inbound_to_us": False}}
    return item


@pytest.mark.parametrize("text", ["what's your use case?", "what is your use case?"])
def test_direct_signed_own_did_use_case_question_has_fixed_profile_reply(monkeypatch, tmp_path, text):
    setup(monkeypatch, tmp_path)
    item = direct_candidate(text)
    allowed, reason, topic = autopilot.eligible(item)
    assert (allowed, topic) == (True, "agent_use_case")
    intent = autopilot.make_intent(item, topic, reason)
    preview, preview_reason, preview_topic = discord_control.candidate_outbound_preview(item)
    assert (preview, preview_reason, preview_topic) == (autopilot.render(intent), reason, topic)
    profile = autopilot.public_knowledge()
    assert all(capability in preview for capability in profile["capabilities"])
    assert profile["project_repository"] in preview
    assert autopilot_transport.validate_intent(autopilot.export_intent(intent))["topic"] == "agent_use_case"


def test_direct_first_contact_is_human_gated_and_preview_is_read_only(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    item = direct_candidate("what's your use case?")
    put(item)
    before_auto, before_resident = copy.deepcopy(autopilot.load()), copy.deepcopy(resident.load_state())
    assert autopilot.eligible(item) == (True, "signed_public_direct_request", "agent_use_case")
    assert discord_control.trust_candidates() == [item]
    preview, reason, topic = discord_control.candidate_outbound_preview(item)
    assert preview == autopilot.render(autopilot.make_intent(item, topic, reason))
    assert autopilot.load() == before_auto and resident.load_state() == before_resident
    autopilot.build_outbox()
    assert autopilot.queue()["outbox"] == []
    resident.feedback(item["candidate_id"], "approved")
    assert autopilot.queue()["outbox"] == []


def test_direct_signed_own_did_message_generates_conversation_candidate(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    observed, config = observer.default_state(), observer.load_config()
    message = {"seq": 44, "from": OTHER, "text": f"{OWN} what's your use case?", "ts": datetime.now(UTC).isoformat()}
    observer.process_message(observed, config, "lobby", message, OWN, None)
    observer.save_state(observed)
    resident.refresh()
    rows = [item for item in resident.load_state()["candidates"].values() if item.get("category") == "conversation"]
    assert len(rows) == 1
    item = rows[0]
    assert item["signals"]["direct_public_signed"] is True
    assert item["signals"]["conversation_topic"] == "agent_use_case"
    assert autopilot.eligible(item) == (True, "signed_public_direct_request", "agent_use_case")
    autopilot.build_outbox()
    assert autopilot.queue()["outbox"] == []


def test_production_ee56_equivalent_is_undirected_and_cannot_stage(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    item = candidate()
    put(item)
    assert autopilot.eligible(item) == (False, "candidate_subject_unresolved", None)
    assert discord_control.trust_candidates() == []
    resident.feedback(item["candidate_id"], "approved")
    with pytest.raises(RuntimeError, match="safety eligibility"):
        autopilot.stage_approved_reply(item["candidate_id"])


@pytest.mark.parametrize("text", [
    "what's your use case?",
    "what is your use case?",
])
def test_use_case_question_requires_signed_public_own_did_address(text):
    assert conversation_planner.plan(room="lobby", sender_did=OTHER, signed=True, own_did=OWN, text=text) is None
    assert conversation_planner.plan(room="lobby", sender_did=OTHER, signed=True, own_did=OWN, text=f"did:key:z6MkOther {text}") is None
    assert conversation_planner.plan(room="lobby", sender_did=OTHER, signed=True, own_did=OWN, text=f"@other_agent {text}") is None


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
    plan = conversation_planner.plan(room="lobby", sender_did=OTHER, signed=True, own_did=OWN, text=f"{OWN} {text}")
    assert plan is None or plan["topic"] != "agent_use_case"
    assert autopilot.eligible(item)[0] is False
