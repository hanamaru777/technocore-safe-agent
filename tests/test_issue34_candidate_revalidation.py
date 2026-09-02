import copy
from datetime import UTC, datetime, timedelta

from flop_agent import autopilot, core, discord_control, observer, resident


OTHER = "did:key:z6MkIssue34Other"


def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    observed = observer.default_state()
    observed["agents"]["candidate34"] = {"did": OTHER, "facts": {"recent_messages": []}}
    observer.save_state(observed)
    local = resident.default_state()
    local["relationships"]["candidate34"] = {"did": OTHER, "approval_rejection_history": [], "interaction_history": []}
    local["daemon"]["last_refresh_at"] = datetime.now(UTC).isoformat()
    resident.save_state(local)
    auto = autopilot.default_state()
    auto.update({"enabled": True, "paused": False, "migrated_at": "done"})
    autopilot.save(auto)


def candidate(candidate_id="question-34", *, text="Can you explain nonce safety?", fingerprint="candidate34", category="specific_question", status="pending"):
    return {
        "candidate_id": candidate_id, "did": OTHER, "fingerprint": fingerprint,
        "room": "lobby", "seq": 34, "category": category, "priority": "high",
        "status": status, "created_at": datetime.now(UTC).isoformat(),
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "signals": {"spam_noise_probability": 0.0, "generic_template_probability": 0.0,
                    "poetic_filler_count": 0, "concrete_evidence": True,
                    "conversation_continuity": False, "useful_agent_probability": 0.9,
                    "facts": {"inbound_to_us": False}},
        "context": {"excerpt": text, "untrusted": True},
    }


def put(item):
    state = resident.load_state()
    state["candidates"][item["candidate_id"]] = item
    state["relationships"].setdefault(item["fingerprint"], {"did": item["did"], "approval_rejection_history": [], "interaction_history": []})
    resident.save_state(state)


def observed_question_kinds(text):
    state, config = observer.default_state(), observer.DEFAULT_CONFIG
    observer.process_message(state, config, "lobby", {"seq": 1, "from": OTHER, "text": text, "ts": datetime.now(UTC).isoformat()}, None, None)
    return {item["kind"] for item in state["opportunities"]}


def test_question_classifier_requires_an_actual_question_or_explicit_request():
    assert "question_candidate" not in observed_question_kinds("The DID rotation question keeps surfacing—worth writing a spec on key lifecycle edge cases.")
    assert "question_candidate" in observed_question_kinds("is shipping still an issue?")
    assert "question_candidate" in observed_question_kinds("Can you explain nonce safety?")
    assert "question_candidate" not in observed_question_kinds("I published a Technocore contribution with reproducible evidence.")
    assert "question_candidate" not in observed_question_kinds("I published a contribution https://example.invalid/post?ref=abc")
    assert "question_candidate" not in observed_question_kinds("earn your refs at https://example.invalid/?ref=abc")
    assert "question_candidate" in observed_question_kinds("Can you explain this? https://example.invalid/?ref=abc")


def test_help_collaboration_and_contribution_detection_are_preserved():
    kinds = observed_question_kinds("Please help with a collaboration contribution artifact.")
    assert {"question_candidate", "help_candidate", "collaboration_candidate", "contribution_candidate"} <= kinds


def test_existing_misclassified_specific_question_is_excluded_at_read_and_send_time(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    bad = candidate(text="The DID rotation question keeps surfacing—worth writing a spec.")
    put(bad)
    assert discord_control.trust_candidates() == []

    local = resident.load_state()
    prior = candidate("prior", text="Can you explain nonce safety?", status="published")
    prior["published_at"] = datetime.now(UTC).isoformat()
    local["candidates"]["prior"] = prior
    local["relationships"]["candidate34"]["approval_rejection_history"].append({"candidate_id": "prior", "decision": "approved", "at": datetime.now(UTC).isoformat()})
    local["published"].append({"candidate_id": "prior", "at": datetime.now(UTC).isoformat(), "permalink": "https://technocore.chat/humans#r/lobby/1"})
    resident.save_state(local)
    autopilot.build_outbox()
    assert autopilot.queue()["outbox"] == []


def test_saved_specific_question_with_url_query_only_fails_closed_after_trust(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    bad = candidate(text="earn your refs at https://example.invalid/?ref=abc")
    put(bad)
    assert discord_control.trust_candidates() == []

    local = resident.load_state()
    prior = candidate("prior", text="Can you explain nonce safety?", status="published")
    prior["published_at"] = datetime.now(UTC).isoformat()
    local["candidates"]["prior"] = prior
    local["relationships"]["candidate34"]["approval_rejection_history"].append({"candidate_id": "prior", "decision": "approved", "at": datetime.now(UTC).isoformat()})
    local["published"].append({"candidate_id": "prior", "at": datetime.now(UTC).isoformat(), "permalink": "https://technocore.chat/humans#r/lobby/1"})
    resident.save_state(local)
    autopilot.build_outbox()
    assert autopilot.queue()["outbox"] == []


def test_specific_question_without_bounded_context_fails_closed(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    item = candidate(); item["context"] = {"untrusted": True}
    assert autopilot.eligible(item) == (False, "specific_question_context_unverified", None)


def test_candidate_preview_matches_render_and_is_read_only(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    item = candidate(text="Can you explain nonce safety? @everyone https://unsafe.invalid")
    put(item)
    before_auto, before_resident = copy.deepcopy(autopilot.load()), copy.deepcopy(resident.load_state())
    preview, reason, topic = discord_control.candidate_outbound_preview(item)
    assert preview == autopilot.render(autopilot.make_intent(item, topic, reason))
    message = discord_control.candidate_message(item)
    assert preview in message and "@everyone" not in message and "https://unsafe.invalid" not in message and "[URL省略]" in message
    assert autopilot.load() == before_auto and resident.load_state() == before_resident


def test_trust_candidate_preview_is_bounded_and_discord_safe(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    for number in range(5):
        put(candidate(f"question-{number}", text=f"Can you explain nonce safety? @everyone https://unsafe.invalid/{number}", fingerprint=f"fp{number:014d}"))
    message = discord_control.trust_candidates_message()
    assert message.count("送信予定:") == 5 and len(message) <= discord_control.DISCORD_MESSAGE_LIMIT
    assert "@everyone" not in message and "https://unsafe.invalid" not in message and "[URL省略]" in message
