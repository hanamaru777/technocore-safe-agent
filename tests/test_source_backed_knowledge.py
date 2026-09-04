import json
from datetime import UTC, datetime

import pytest

from flop_agent import autopilot, core, knowledge, knowledge_guard


FIXED_NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)


def candidate(text: str) -> dict:
    return {
        "candidate_id": "candidate-knowledge",
        "did": "did:key:z6MkOther",
        "fingerprint": "abc12345deadbeef",
        "room": "lobby",
        "seq": 10,
        "category": "specific_question",
        "status": "pending",
        "context": {"excerpt": text, "untrusted": True},
        "signals": {},
    }


def acknowledged_intent(topic: str = "repo_tests_bugs") -> tuple[str, dict]:
    intent_id = "0123456789abcdefabcd"
    return intent_id, {
        "id": intent_id,
        "source_candidate_id": "candidate-1",
        "source_did": "did:key:z6MkOther",
        "fingerprint": "abc12345deadbeef",
        "room": "lobby",
        "seq": 100,
        "category": "help_request",
        "topic": topic,
        "public_evidence_ids": ["public-profile:1"],
        "created_at": "2026-09-04T09:05:00+00:00",
        "expires_at": "2026-09-10T09:05:00+00:00",
        "safety_decision": "concrete_public_technical_request",
        "status": "acknowledged",
        "acknowledged_at": "2026-09-04T09:06:00+00:00",
    }


def test_registry_is_versioned_pinned_and_narrow():
    registry = knowledge.load_registry()

    assert registry["schema_version"] == 1
    assert registry["registry_id"] == "flop-onboarding-knowledge-v1"
    assert set(registry["topics"]) == {
        "nonce",
        "did_signature",
        "technocore_api",
        "prompt_injection_safety",
        "repo_tests_bugs",
        "agent_use_case",
        "tclk_alpha",
    }
    for item in registry["topics"].values():
        for source in item["sources"]:
            assert source["repo"] in {
                "flop-labs/technocore-chat",
                "flop-labs/tclk",
                "hanamaru777/technocore-safe-agent",
            }
            assert len(source["commit"]) == 40


def test_registry_rejects_future_review_time(monkeypatch, tmp_path):
    data = json.loads(knowledge.REGISTRY_PATH.read_text("utf-8"))
    data["checked_at"] = "2099-01-01T00:00:00+00:00"
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(data), "utf-8")
    monkeypatch.setattr(knowledge, "REGISTRY_PATH", path)

    with pytest.raises(RuntimeError, match="in the future"):
        knowledge.load_registry()


def test_signed_preview_reuses_exact_existing_signer_renderer():
    answer = knowledge.preview("nonce", current=FIXED_NOW)

    assert answer == "Use a strictly increasing nonce for each DID and room. Do not reuse an earlier nonce after a successful signed post."
    assert "candidate-knowledge" not in answer


def test_preview_is_read_only(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    before = list(tmp_path.rglob("*"))

    assert knowledge.preview("repo_tests_bugs", current=FIXED_NOW).startswith("For reproducible repo")

    assert list(tmp_path.rglob("*")) == before


def test_time_sensitive_tclk_fails_closed_when_stale():
    fresh = knowledge.topic_status("tclk_alpha", current=datetime(2026, 9, 10, tzinfo=UTC))
    stale = knowledge.topic_status("tclk_alpha", current=datetime(2026, 9, 12, tzinfo=UTC))

    assert fresh["verified"] is True
    assert fresh["signable"] is False
    assert stale["verified"] is False
    assert stale["reason"] == "stale_source"
    with pytest.raises(RuntimeError, match="stale or unverified"):
        knowledge.preview("tclk_alpha", current=datetime(2026, 9, 12, tzinfo=UTC))


def test_tclk_status_is_read_only_even_when_fresh():
    info = knowledge.candidate_knowledge(candidate("Is PaperRail in tclk alpha moving real value?"), current=FIXED_NOW)

    assert info["topic"] == "tclk_alpha"
    assert info["verified"] is True
    assert info["signable"] is False
    assert "no real value" in info["preview"]


def test_reward_or_snapshot_question_is_not_promoted_to_knowledge():
    info = knowledge.candidate_knowledge(candidate("What is the airdrop snapshot date?"), current=FIXED_NOW)

    assert info["topic"] is None
    assert info["verified"] is False
    assert info["reason"] == "unsupported_current_or_reward_fact"


def test_guard_fails_closed_registered_signed_topic_when_source_unavailable(monkeypatch):
    monkeypatch.setattr(
        knowledge_guard,
        "_ORIGINAL_ELIGIBLE",
        lambda _candidate: (True, "candidate_subject_resolved", "nonce"),
    )
    monkeypatch.setattr(knowledge, "signable_now", lambda _topic: False)

    assert knowledge_guard.guarded_eligible({}) == (
        False,
        "knowledge_source_stale_or_unverified",
        "nonce",
    )


def test_guard_does_not_change_non_registry_generic_lane(monkeypatch):
    monkeypatch.setattr(
        knowledge_guard,
        "_ORIGINAL_ELIGIBLE",
        lambda _candidate: (True, "concrete_public_technical_request", "collaboration"),
    )
    monkeypatch.setattr(knowledge, "signable_now", lambda _topic: False)

    assert knowledge_guard.guarded_eligible({}) == (
        True,
        "concrete_public_technical_request",
        "collaboration",
    )


def test_acknowledged_reply_gets_bounded_source_provenance_audit(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    intent_id, intent = acknowledged_intent()
    state = {
        "outbox": {intent_id: intent},
        "receipts": {intent_id: {"at": "2026-09-04T09:06:00+00:00"}},
    }
    monkeypatch.setattr(autopilot, "load", lambda: state)

    first = knowledge.sync_acknowledged_usage()
    second = knowledge.sync_acknowledged_usage()

    assert first == {"records": 1, "added": 1}
    assert second == {"records": 1, "added": 0}
    payload = json.loads(knowledge.audit_path().read_text("utf-8"))
    record = payload["records"][0]
    assert record["intent_id"] == intent_id
    assert record["topic"] == "repo_tests_bugs"
    assert record["registry_id"] == "flop-onboarding-knowledge-v1"
    assert record["source_ids"] == ["project-profile-3d90733d", "project-readme-3d90733d"]
    assert record["provenance_mode"] == "retroactive_mapping"
    assert len(record["answer_sha256"]) == 64
    serialized = json.dumps(payload).lower()
    assert "private key" not in serialized
    assert "sign_seed" not in serialized


def test_summary_reports_six_signed_ready_topics():
    summary = knowledge.summary(current=FIXED_NOW)

    assert summary["topics"] == 7
    assert summary["verified"] == 7
    assert summary["signable"] == 6
    assert summary["stale"] == []
