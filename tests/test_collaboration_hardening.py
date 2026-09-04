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


def test_discovery_eligibility_checks_are_bounded_on_large_pending_state(monkeypatch):
    state = collaboration.default_state()
    local = {"candidates": {}}
    for number in range(1000):
        candidate_id = f"candidate-{number}"
        local["candidates"][candidate_id] = {
            "candidate_id": candidate_id,
            "did": f"did:key:z6Mk{number}",
            "fingerprint": f"{number:016x}",
            "room": "lobby",
            "seq": number,
            "category": "help_request",
            "created_at": f"{number:04d}",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "status": "pending",
        }

    calls = 0

    def eligible(candidate):
        nonlocal calls
        calls += 1
        return True, "ok", "repo_tests_bugs"

    monkeypatch.setattr(collaboration.autopilot, "first_contact_eligible", eligible)

    changed = collaboration_hardening.bounded_discovery(state, local)

    assert changed is True
    assert calls <= collaboration_hardening.DISCOVERY_SCAN_LIMIT
    assert len(state["records"]) == collaboration_hardening.DISCOVERY_CREATE_LIMIT
    assert all(
        int(record["source_candidate_id"].split("-")[-1]) >= 1000 - collaboration_hardening.DISCOVERY_SCAN_LIMIT
        for record in state["records"].values()
    )


def test_direct_reply_index_avoids_records_times_candidates_scan(monkeypatch):
    state = collaboration.default_state()
    state["records"] = {}
    for number in range(100):
        record_id = f"{number:016x}"
        state["records"][record_id] = {
            "id": record_id,
            "fingerprint": f"fp-{number}",
            "source_candidate_id": f"origin-{number}",
            "source_seq": 0,
            "contacted_at": "2026-09-04T09:00:00+00:00",
            "stage": "contacted",
            "related_candidate_ids": [],
            "history": [],
        }

    local = {"candidates": {}}
    for number in range(1000):
        candidate_id = f"reply-{number}"
        local["candidates"][candidate_id] = {
            "candidate_id": candidate_id,
            "fingerprint": f"fp-{number}",
            "category": "conversation",
            "signals": {"direct_public_signed": True},
            "created_at": "2026-09-04T10:00:00+00:00",
            "seq": number + 1,
        }

    candidate_after_calls = 0

    def after(record, candidate):
        nonlocal candidate_after_calls
        candidate_after_calls += 1
        return True

    monkeypatch.setattr(collaboration, "_candidate_after", after)
    monkeypatch.setattr(
        collaboration,
        "_classify_reply",
        lambda candidate: ("replied", "safe_reply", "watch_reply", None, "safe"),
    )

    collaboration_hardening.advance_from_new_replies(state, local)

    assert candidate_after_calls == 100
    assert all(record["stage"] == "replied" for record in state["records"].values())


def test_discord_service_runs_collaboration_stack():
    text = Path("packaging/oracle/discord.service").read_text("utf-8")
    assert "-m flop_agent.discord_knowledge" in text
    assert "-m flop_agent.discord_control" not in text
    # The knowledge wrapper must continue layering the accepted collaboration UX.
    wrapper = Path("src/flop_agent/discord_knowledge.py").read_text("utf-8")
    assert "from . import discord_collaboration as base" in wrapper
