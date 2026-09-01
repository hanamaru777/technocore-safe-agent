import hashlib
from datetime import UTC, datetime

from flop_agent import autopilot, core, discord_control, observer, resident


def setup_state(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    observed = observer.default_state()
    observer.save_state(observed)
    state = resident.default_state()
    state["cached_observer"] = {
        "health": {"current": "ok"},
        "cursors": {},
        "message_gaps": 0,
        "discovery_queue": 0,
        "agents_known": 1,
        "returning_agents": 0,
        "inbound": 0,
    }
    state["daemon"]["last_refresh_at"] = datetime.now(UTC).isoformat()
    resident.save_state(state)
    return state


def auto_state_with(intent_id="intent-1", *, receipt=True, controlled=False):
    intent = {
        "id": intent_id,
        "source_candidate_id": "candidate-1",
        "source_did": "did:key:z6MkOther",
        "fingerprint": "abc123",
        "room": "lobby",
        "seq": 99,
        "category": "controlled_e2e" if controlled else "conversation",
        "topic": "repo_safety",
        "public_evidence_ids": ["public-profile:1"],
        "created_at": "2026-08-31T12:00:00+00:00",
        "expires_at": "2026-09-02T12:00:00+00:00",
        "safety_decision": "controlled_pause_only_e2e" if controlled else "signed_public_direct_request",
    }
    state = {
        "schema_version": 1,
        "enabled": True,
        "paused": False,
        "outbox": {intent_id: intent},
        "receipts": {intent_id: {"at": "2026-08-31T12:05:00+00:00"}} if receipt else {},
        "rate_history": [],
        "migrated_at": "done",
    }
    if receipt:
        state["rate_history"] = [{"at": "2026-08-31T12:05:00+00:00", "fingerprint": intent["fingerprint"], "room": intent["room"], "text_hash": hashlib.sha256(autopilot.render(intent).encode()).hexdigest()}]
    return state


def test_existing_reply_is_baselined_and_not_replayed(monkeypatch, tmp_path):
    setup_state(monkeypatch, tmp_path)
    auto_state = auto_state_with()
    monkeypatch.setattr(autopilot, "load", lambda: auto_state)
    monkeypatch.setattr(autopilot, "status", lambda state=None: {"enabled": True, "paused": False, "queued": 0, "receipts": len(auto_state["receipts"]), "migration_complete": True})
    control = discord_control.Control({"42"}, "99")
    control.ensure_baseline()
    assert control.interaction_notices() == []


def test_new_reply_notifies_once_with_when_who_and_what(monkeypatch, tmp_path):
    setup_state(monkeypatch, tmp_path)
    auto_state = auto_state_with(receipt=False)
    monkeypatch.setattr(autopilot, "load", lambda: auto_state)
    monkeypatch.setattr(autopilot, "status", lambda state=None: {"enabled": True, "paused": False, "queued": 0, "receipts": len(auto_state["receipts"]), "migration_complete": True})
    control = discord_control.Control({"42"}, "99")
    control.ensure_baseline()
    auto_state["receipts"]["intent-1"] = {"at": "2026-08-31T12:05:00+00:00"}
    intent = auto_state["outbox"]["intent-1"]
    auto_state["rate_history"].append({"at": "2026-08-31T12:05:00+00:00", "fingerprint": intent["fingerprint"], "room": intent["room"], "text_hash": hashlib.sha256(autopilot.render(intent).encode()).hexdigest()})
    notices = control.interaction_notices()
    assert len(notices) == 1
    notice = notices[0]
    assert "自動返信完了" in notice
    assert "abc123" in notice
    assert "lobby #99" in notice
    assert "The public technocore-safe-agent repository" in notice
    assert "/history abc123" in notice
    assert control.interaction_notices() == []


def test_controlled_e2e_never_appears_as_real_interaction(monkeypatch, tmp_path):
    setup_state(monkeypatch, tmp_path)
    auto_state = auto_state_with(controlled=True)
    monkeypatch.setattr(autopilot, "load", lambda: auto_state)
    records = discord_control.sync_interactions()
    assert records == []
    assert "まだ直接のやりとり記録はありません" in discord_control.history_message()


def test_history_is_bounded_and_sanitized(monkeypatch, tmp_path):
    setup_state(monkeypatch, tmp_path)
    monkeypatch.setattr(autopilot, "load", lambda: {"outbox": {}, "receipts": {}})
    ui = discord_control.default_ui_state()
    ui["interactions"] = [
        {
            "id": f"in:{number}",
            "direction": "受信",
            "at": f"2026-08-31T12:{number % 60:02d}:00+00:00",
            "fingerprint": "abc123",
            "did": "did:key:z6MkOther",
            "room": "lobby",
            "seq": number,
            "kind": "署名付き直接リクエスト",
            "summary": "@everyone see https://example.invalid now",
        }
        for number in range(discord_control.INTERACTION_HISTORY_LIMIT + 25)
    ]
    discord_control.save_ui_state(ui)
    records = discord_control.sync_interactions()
    assert len(records) == discord_control.INTERACTION_HISTORY_LIMIT
    message = discord_control.history_message("abc123")
    assert "https://example.invalid" not in message
    assert "@everyone" not in message
    assert "[URL省略]" in message


def test_outbound_notice_pairs_sanitized_inbound_with_exact_fixed_reply(monkeypatch, tmp_path):
    state = setup_state(monkeypatch, tmp_path)
    state["candidates"] = {
        "candidate-1": {
            "candidate_id": "candidate-1", "status": "pending", "category": "conversation",
            "fingerprint": "abc12345deadbeef", "did": "did:key:z6MkOther", "room": "lobby", "seq": 99,
            "created_at": "2026-08-31T12:00:00+00:00", "signals": {"direct_public_signed": True, "conversation_topic": "repo_safety"},
            "context": {"untrusted": True},
        }
    }
    resident.save_state(state)
    observed = observer.load_state()
    observed["agents"]["abc12345deadbeef"] = {"facts": {"recent_messages": [{"room": "lobby", "seq": 99, "ts": "2026-08-31T12:00:00+00:00", "text": "@everyone review https://unsafe.invalid\x00 now"}]}}
    observer.save_state(observed)
    auto_state = auto_state_with(receipt=False)
    monkeypatch.setattr(autopilot, "load", lambda: auto_state)
    monkeypatch.setattr(autopilot, "status", lambda state=None: {"enabled": True, "paused": False, "queued": 0, "receipts": len(auto_state["receipts"]), "migration_complete": True})
    control = discord_control.Control({"42"}, "99")
    control.ensure_baseline()
    auto_state["receipts"]["intent-1"] = {"at": "2026-08-31T12:05:00+00:00"}
    intent = auto_state["outbox"]["intent-1"]
    auto_state["rate_history"].append({"at": "2026-08-31T12:05:00+00:00", "fingerprint": intent["fingerprint"], "room": intent["room"], "text_hash": hashlib.sha256(autopilot.render(intent).encode()).hexdigest()})
    notice = control.interaction_notices()[0]
    assert "受信:" in notice and "送信:" in notice
    assert "https://unsafe.invalid" not in notice and "@everyone" not in notice and "\x00" not in notice
    assert "The public technocore-safe-agent repository" in notice
    history = discord_control.history_message()
    assert "[URL省略]" in history and "@everyone" not in history
    assert "The public technocore-safe-agent repository" in history


def test_history_does_not_invent_exact_outbound_text_without_matching_hash(monkeypatch, tmp_path):
    setup_state(monkeypatch, tmp_path)
    auto_state = auto_state_with()  # legacy receipt has no text hash or matching rate record
    auto_state["rate_history"] = []
    monkeypatch.setattr(autopilot, "load", lambda: auto_state)
    message = discord_control.history_message()
    assert "正確な本文は保持されていません" in message
    assert "The public technocore-safe-agent repository" not in message
