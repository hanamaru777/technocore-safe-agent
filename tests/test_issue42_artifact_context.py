import copy
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import autopilot, core, discord_control, observer, resident


def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    local = resident.default_state(); local["daemon"]["last_refresh_at"] = datetime.now(UTC).isoformat(); resident.save_state(local)
    auto = autopilot.default_state(); auto.update({"enabled": True, "paused": False, "migrated_at": "done"}); autopilot.save(auto)


def candidate(candidate_id="candidate-42", *, text, category="artifact_contribution", fingerprint="fp00000000000042"):
    return {
        "candidate_id": candidate_id, "did": "did:key:z6MkIssue42", "fingerprint": fingerprint, "room": "lobby", "seq": 42,
        "category": category, "priority": "high", "status": "pending", "created_at": datetime.now(UTC).isoformat(),
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "signals": {"spam_noise_probability": 0.0, "generic_template_probability": 0.0, "poetic_filler_count": 0, "concrete_evidence": True,
                    "conversation_continuity": False, "useful_agent_probability": 0.9, "facts": {"inbound_to_us": False}},
        "context": {"excerpt": text[:280], "untrusted": True},
    }


def put(item):
    state = resident.load_state(); state["candidates"][item["candidate_id"]] = item
    state["relationships"].setdefault(item["fingerprint"], {"did": item["did"], "approval_rejection_history": [], "interaction_history": []})
    resident.save_state(state)


def active_trust(item):
    state = resident.load_state()
    prior = candidate("prior-42", text="How should I publish contribution evidence so others can independently verify it?", fingerprint=item["fingerprint"])
    prior.update({"status": "published", "published_at": datetime.now(UTC).isoformat()})
    state["candidates"][prior["candidate_id"]] = prior
    state["relationships"][item["fingerprint"]]["approval_rejection_history"].append({"candidate_id": prior["candidate_id"], "decision": "approved", "at": datetime.now(UTC).isoformat()})
    state["published"].append({"candidate_id": prior["candidate_id"], "at": datetime.now(UTC).isoformat(), "permalink": "https://technocore.chat/humans#r/lobby/1"})
    resident.save_state(state)


def test_production_artifact_footer_candidate_is_revalidated_at_every_gate(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    item = candidate("4c3dc44d82fd7035", text="Field note on Flop european bond: Mesh networks provide resilient communication infrastructure through distributed nodes. Contributed to flop-european-bond-yields-rise-on-fis-rfdb so the swarm can verify it. [signed contribution {t}]")
    put(item); active_trust(item)
    assert autopilot.eligible(item) == (False, "reply_semantics_unsupported", "contribution_artifact")
    assert discord_control.trust_candidates() == []
    before_auto, before_resident = copy.deepcopy(autopilot.load()), copy.deepcopy(resident.load_state())
    assert discord_control.candidate_outbound_preview(item) == (None, "reply_semantics_unsupported", "contribution_artifact")
    assert autopilot.load() == before_auto and resident.load_state() == before_resident
    autopilot.build_outbox(); assert autopilot.queue()["outbox"] == []
    resident.feedback(item["candidate_id"], "approved")
    with pytest.raises(RuntimeError, match="safety eligibility"):
        autopilot.stage_approved_reply(item["candidate_id"])


@pytest.mark.parametrize("text", [
    "Mesh networks are useful. I contributed this so others can verify it.",
    "Field note on european bond yields. Contributed so the swarm can verify it. [signed contribution {t}]",
])
def test_generic_verify_it_and_unrelated_domain_artifacts_fail_closed(monkeypatch, tmp_path, text):
    setup(monkeypatch, tmp_path)
    item = candidate(text=text)
    assert autopilot.eligible(item) == (False, "reply_semantics_unsupported", "contribution_artifact")


@pytest.mark.parametrize("text", [
    "How should I publish contribution evidence so others can independently verify it?",
    "Can you review whether this artifact evidence should include private credentials?",
])
def test_genuine_contribution_evidence_questions_pass(monkeypatch, tmp_path, text):
    setup(monkeypatch, tmp_path)
    item = candidate(text=text)
    allowed, reason, topic = autopilot.eligible(item)
    assert allowed is True and topic == "contribution_artifact"
    assert discord_control.candidate_outbound_preview(item) == (autopilot.render(autopilot.make_intent(item, topic, reason)), reason, topic)


@pytest.mark.parametrize("text", [
    "This contribution's artifact evidence is not public yet.",
    "This contribution's artifact evidence excludes private configuration.",
])
def test_nonquestion_publication_hygiene_with_primary_delta_passes(monkeypatch, tmp_path, text):
    setup(monkeypatch, tmp_path)
    item = candidate(text=text)
    assert autopilot.reply_semantics_supported(item["context"]["excerpt"], "contribution_artifact") is True
    assert "keep_artifact_evidence_public_and_verifiable" in autopilot.canonical_claim_delta(item["context"]["excerpt"], "contribution_artifact")
    assert autopilot.eligible(item)[0] is True


def test_nonquestion_verifiable_evidence_passes_semantics_then_primary_gate(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    item = candidate(text="The artifact evidence still needs to be independently verifiable.")
    assert autopilot.reply_semantics_supported(item["context"]["excerpt"], "contribution_artifact") is True
    assert autopilot.eligible(item) == (False, "redundant_reply", "contribution_artifact")


def test_candidate_shows_saved_bounded_context_safely_and_read_only(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    text = "How should I publish contribution evidence so others can independently verify it? @everyone https://unsafe.invalid/\u200b" + " x" * 110
    item = candidate(text=text)
    put(item)
    before_auto, before_resident = copy.deepcopy(autopilot.load()), copy.deepcopy(resident.load_state())
    message = discord_control.candidate_message(item)
    saved = item["context"]["excerpt"]
    assert "判定対象全文:" in message and "https://unsafe.invalid" not in message and "@everyone" not in message and "\u200b" not in message
    assert discord_control.safe_excerpt(saved, 560) in message
    assert len(message) <= discord_control.DISCORD_MESSAGE_LIMIT
    assert autopilot.load() == before_auto and resident.load_state() == before_resident
    trust = discord_control.trust_candidates_message()
    assert "判定対象全文:" not in trust and len(trust) <= discord_control.DISCORD_MESSAGE_LIMIT
