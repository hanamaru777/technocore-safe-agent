from datetime import UTC, datetime, timedelta
from pathlib import Path

from flop_agent import autopilot, collaboration, collaboration_hardening, core, observer, resident


def _setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    observer.save_state(observer.default_state())
    local = resident.default_state()
    local["daemon"]["last_refresh_at"] = datetime.now(UTC).isoformat()
    resident.save_state(local)
    collaboration_hardening.install()
    return local


def _candidate(candidate_id, text, *, created_at="2026-09-04T10:00:00+00:00"):
    return {
        "candidate_id": candidate_id,
        "did": "did:key:z6MkOther",
        "fingerprint": "abc12345deadbeef",
        "room": "lobby",
        "seq": 200,
        "category": "conversation",
        "priority": "medium",
        "signals": {"direct_public_signed": True, "conversation_topic": "repo_tests_bugs", "facts": {}},
        "context": {"excerpt": text, "untrusted": True},
        "created_at": created_at,
        "expires_at": "2026-09-10T10:00:00+00:00",
        "status": "pending",
        "safety_decision": "signed_public_direct_request",
    }


def _auto():
    intent_id = "dce534babcc3e50d7e5e"
    return {
        "schema_version": 1,
        "enabled": True,
        "paused": False,
        "outbox": {intent_id: {
            "id": intent_id,
            "source_candidate_id": "origin",
            "source_did": "did:key:z6MkOther",
            "fingerprint": "abc12345deadbeef",
            "room": "lobby",
            "seq": 100,
            "category": "help_request",
            "topic": "repo_tests_bugs",
            "public_evidence_ids": ["public-profile:1"],
            "created_at": "2026-09-04T09:05:00+00:00",
            "expires_at": "2026-09-10T09:05:00+00:00",
            "safety_decision": "concrete_public_technical_request",
            "status": "acknowledged",
        }},
        "receipts": {intent_id: {"at": "2026-09-04T09:06:00+00:00"}},
        "rate_history": [],
        "migrated_at": "done",
        "decision_cache": {},
        "recent_decisions": [],
        "resident_revision": None,
        "first_contact_enabled": True,
        "first_contact_intents": {intent_id: {"fingerprint": "abc12345deadbeef", "created_at": "2026-09-04T09:05:00+00:00"}},
    }


def test_human_review_is_not_regressed_by_already_processed_reply(monkeypatch, tmp_path):
    local = _setup(monkeypatch, tmp_path)
    local["candidates"] = {"reply": _candidate("reply", "Could you review the repo test at https://untrusted.invalid/x ?")}
    resident.save_state(local)
    monkeypatch.setattr(autopilot, "load", lambda: _auto())

    first = collaboration.records()[0]
    assert first["stage"] == "human_review"
    assert first["related_candidate_ids"] == ["reply"]

    second = collaboration.records()[0]
    assert second["stage"] == "human_review"
    assert second["related_candidate_ids"] == ["reply"]
    assert len(second["history"]) == len(first["history"])


def test_advanced_task_stage_is_not_erased_by_later_general_reply(monkeypatch, tmp_path):
    local = _setup(monkeypatch, tmp_path)
    local["candidates"] = {"task": _candidate("task", "Could you review the public repo test vectors?")}
    resident.save_state(local)
    monkeypatch.setattr(autopilot, "load", lambda: _auto())

    record = collaboration.records()[0]
    assert record["stage"] == "task_candidate"

    local = resident.load_state()
    later = _candidate("later", "Thanks for the follow-up.", created_at="2026-09-04T11:00:00+00:00")
    later["seq"] = 201
    later["signals"]["conversation_topic"] = "follow_up"
    local["candidates"]["later"] = later
    resident.save_state(local)
    monkeypatch.setattr(autopilot, "eligible", lambda candidate: (True, "signed_public_direct_request", "follow_up"))

    record = collaboration.records()[0]
    assert record["stage"] == "task_candidate"
    assert "later" in record["related_candidate_ids"]


def test_discord_service_runs_collaboration_wrapper():
    text = Path("packaging/oracle/discord.service").read_text("utf-8")
    assert "-m flop_agent.discord_collaboration" in text
    assert "-m flop_agent.discord_control" not in text
