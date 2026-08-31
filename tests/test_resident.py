import asyncio
import json
import subprocess
import sys
import time
import zipfile
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import core, discord_control, observer, resident, resident_daemon


def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    return observer.default_state()


def msg(seq, did, text, room="lobby"):
    return {"seq": seq, "from": did, "text": text, "ts": "2026-08-26T00:00:00Z", "room": room}


def populate(monkeypatch, tmp_path):
    state = setup(monkeypatch, tmp_path); config = observer.load_config()
    own, useful, noise = "did:key:z6MkOwn", "did:key:z6MkUseful", "did:key:z6MkNoise"
    (tmp_path / "verified-did.json").write_text(json.dumps({"did": own}), encoding="utf-8")
    observer.process_message(state, config, "lobby", msg(1, useful, "Can you help with this specific protocol error in room lobby?"), own, None)
    observer.process_message(state, config, "other", msg(1, useful, "I have a test artifact and patch"), own, None)
    for seq in range(2, 8): observer.process_message(state, config, "lobby", msg(seq, noise, "Noticed recent activity, curious if collaboration synergy helps"), own, None)
    observer.save_state(state)
    return own, useful, noise


def test_generic_template_and_near_duplicate_are_penalized(monkeypatch, tmp_path):
    _, useful, noise = populate(monkeypatch, tmp_path)
    resident.refresh(); state = resident.load_state()
    noise_q = state["relationships"][core.did_note_location(noise)[2]]
    useful_q = state["relationships"][core.did_note_location(useful)[2]]
    assert noise_q["relationship_state"] == "observed"
    assert useful_q["relationship_state"] in {"interesting", "recurring"}


def test_garbled_text_is_penalized_and_returning_is_explainable(monkeypatch, tmp_path):
    own, useful, _ = populate(monkeypatch, tmp_path)
    state, config = observer.load_state(), observer.load_config()
    fingerprint = core.did_note_location(useful)[2]
    state["agents"][fingerprint]["facts"]["last_encounter_at"] = (datetime.now(UTC) - timedelta(seconds=config["repeat_after_seconds"] + 1)).isoformat()
    observer.process_message(state, config, "third", msg(1, useful, "specific test artifact", "third"), own, None)
    observer.process_message(state, config, "lobby", msg(8, "did:key:z6MkGarbled", "!!!!@@@@####$$$$%%%%"), own, None)
    observer.save_state(state); resident.refresh()
    current = observer.load_state()["agents"]
    useful_quality = resident.quality(next(agent for agent in current.values() if agent["did"] == useful), list(current.values()), resident.load_config())
    garbled_quality = resident.quality(next(agent for agent in current.values() if agent["did"] == "did:key:z6MkGarbled"), list(current.values()), resident.load_config())
    assert useful_quality["conversation_continuity"] is True
    assert garbled_quality["facts"]["garbled_count"] == 1


def test_candidate_cooldown_relationship_and_learning_bounds(monkeypatch, tmp_path):
    _, useful, _ = populate(monkeypatch, tmp_path)
    resident.refresh(); candidates = resident.list_candidates()["candidates"]
    assert len([item for item in candidates if item["did"] == useful]) == 1
    item = next(item for item in candidates if item["did"] == useful)
    assert item["priority"] in {"high", "medium"} and item["context"]["untrusted"] is True
    resident.feedback(item["candidate_id"], "approved")
    assert resident.load_state()["relationships"][item["fingerprint"]]["relationship_state"] == "contacted"
    for _ in range(30):
        resident.load_state()["candidates"][item["candidate_id"]]["status"]
    assert 0.5 <= resident.feedback_status()["learning"]["weights"][item["category"]] <= 1.5


def test_discord_rejects_unauthorized_and_does_not_execute_content(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    control = discord_control.Control({"42"})
    assert control.command("7", "/resident-status")["error"] == "unauthorized"
    monkeypatch.setattr(discord_control.os, "system", lambda *_: pytest.fail("Discord content must not execute"))
    assert control.command("42", "https://example.invalid/; rm -rf /")["error"] == "unsupported"
    assert control.command("42", "/help", "different-channel")["error"] == "wrong_channel"


def test_notification_dedupe_and_publish_seed_gate(monkeypatch, tmp_path):
    own, useful, _ = populate(monkeypatch, tmp_path); resident.refresh()
    item = next(item for item in resident.list_candidates()["candidates"] if item["did"] == useful)
    state = resident.load_state(); state["candidates"][item["candidate_id"]]["priority"] = "critical"; resident.save_state(state)
    control = discord_control.Control({"42"})
    assert len(control.notifications()) == 1 and control.notifications() == []
    with pytest.raises(RuntimeError, match="approved"):
        resident.publish_approved(item["candidate_id"], True)


def test_publisher_fails_closed_off_windows_and_without_signer(monkeypatch, tmp_path):
    _, useful, _ = populate(monkeypatch, tmp_path); resident.refresh()
    item = next(item for item in resident.list_candidates()["candidates"] if item["did"] == useful)
    resident.feedback(item["candidate_id"], "approved")
    monkeypatch.setattr(resident.os, "name", "posix")
    with pytest.raises(RuntimeError, match="Windows"):
        resident.publish_approved(item["candidate_id"], True)


def test_export_is_allowlisted_and_excludes_sensitive_names(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path); resident.load_state(); resident.save_state(resident.default_state())
    (tmp_path / "secret.txt").write_text("never export", encoding="utf-8")
    archive = resident.export_state()
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
    assert "manifest.json" in names and "observer/resident-state.json" in names and "secret.txt" not in names
    assert all("seed" not in name.lower() and "secret" not in name.lower() for name in names)


def test_oracle_import_uses_runtime_layout_and_rejects_unsafe_archives(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path); resident.save_state(resident.default_state())
    archive = resident.export_state()
    target = tmp_path / "imported"
    script = core.ROOT / "packaging" / "oracle" / "import-state.py"
    result = subprocess.run([sys.executable, str(script), archive, str(target)], capture_output=True, text=True, check=False)
    assert result.returncode == 0 and (target / "observer" / "resident-state.json").exists()
    unsafe = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(unsafe, "w") as bundle:
        bundle.writestr("manifest.json", '{"files": []}')
        bundle.writestr("not-allowed.txt", "x")
    result = subprocess.run([sys.executable, str(script), str(unsafe), str(target)], capture_output=True, text=True, check=False)
    assert result.returncode != 0
    slip = tmp_path / "slip.zip"
    with zipfile.ZipFile(slip, "w") as bundle:
        bundle.writestr("manifest.json", '{"files": [{"name": "../bad.json", "sha256": "x"}]}')
        bundle.writestr("../bad.json", "{}")
    assert subprocess.run([sys.executable, str(script), str(slip), str(target)], capture_output=True, text=True, check=False).returncode != 0
    duplicate = tmp_path / "duplicate.zip"
    with pytest.warns(UserWarning):
        with zipfile.ZipFile(duplicate, "w") as bundle:
            bundle.writestr("manifest.json", '{"files": []}'); bundle.writestr("manifest.json", '{"files": []}')
    assert subprocess.run([sys.executable, str(script), str(duplicate), str(target)], capture_output=True, text=True, check=False).returncode != 0
    flat = tmp_path / "flat.zip"
    with zipfile.ZipFile(flat, "w") as bundle:
        data = b'{"schema_version": 1}'
        bundle.writestr("resident-state.json", data)
        bundle.writestr("manifest.json", json.dumps({"files": [{"name": "resident-state.json", "sha256": "00"}]}))
    assert subprocess.run([sys.executable, str(script), str(flat), str(target)], capture_output=True, text=True, check=False).returncode != 0
    mismatch = tmp_path / "mismatch.zip"
    with zipfile.ZipFile(mismatch, "w") as bundle:
        bundle.writestr("observer/resident-state.json", b'{"schema_version": 1}')
        bundle.writestr("manifest.json", json.dumps({"files": [{"name": "observer/resident-state.json", "sha256": "00"}]}))
    assert subprocess.run([sys.executable, str(script), str(mismatch), str(target)], capture_output=True, text=True, check=False).returncode != 0


def test_ttl_cooldown_and_expired_publish_gate(monkeypatch, tmp_path):
    _, useful, _ = populate(monkeypatch, tmp_path); resident.refresh()
    item = next(item for item in resident.list_candidates()["candidates"] if item["did"] == useful)
    state = resident.load_state(); state["candidates"][item["candidate_id"]]["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat(); resident.save_state(state)
    resident.refresh(); assert resident.candidate(item["candidate_id"])["candidate"]["status"] == "expired"
    monkeypatch.setattr(resident.os, "name", "nt")
    with pytest.raises(RuntimeError, match="expired"):
        resident.publish_approved(item["candidate_id"], True)
    state = resident.load_state(); config = resident.load_config()
    state["candidates"][item["candidate_id"]]["created_at"] = (datetime.now(UTC) - timedelta(seconds=config["candidate_cooldown_seconds"] + 1)).isoformat()
    state["candidates"][item["candidate_id"]]["feedback_at"] = state["candidates"][item["candidate_id"]]["created_at"]
    observer.emit_event(observer.load_state(), "help_candidate", "lobby", msg(99, useful, "help with new constraint"), useful)
    observed = observer.load_state(); observer.emit_event(observed, "help_candidate", "lobby", msg(99, useful, "help with new constraint"), useful); observer.save_state(observed); resident.save_state(state)
    resident.refresh(); assert len([candidate for candidate in resident.list_candidates()["candidates"] if candidate["did"] == useful]) >= 2
    state = resident.load_state(); state["candidates"][item["candidate_id"]]["status"] = "published"; state["candidates"][item["candidate_id"]]["expires_at"] = (datetime.now(UTC) + timedelta(hours=1)).isoformat(); resident.save_state(state)
    with pytest.raises(RuntimeError, match="approved"):
        resident.publish_approved(item["candidate_id"], True)


def test_pause_keeps_relationship_refresh_but_stops_candidates(monkeypatch, tmp_path):
    own, useful, _ = populate(monkeypatch, tmp_path); resident.pause(True)
    state = observer.load_state(); config = observer.load_config()
    observer.process_message(state, config, "third", msg(1, useful, "specific test artifact", "third"), own, None); observer.save_state(state)
    resident.refresh(); local = resident.load_state()
    assert local["daemon"]["last_refresh_at"] is not None
    assert core.did_note_location(useful)[2] not in local["relationships"]
    assert not local["candidates"]


def test_discord_notification_digest_and_safe_human_response(monkeypatch, tmp_path):
    _, useful, _ = populate(monkeypatch, tmp_path); resident.refresh()
    item = next(item for item in resident.list_candidates()["candidates"] if item["did"] == useful)
    state = resident.load_state(); state["candidates"][item["candidate_id"]]["priority"] = "critical"; resident.save_state(state)
    control = discord_control.Control({"42"}, "99")
    message = control.command("42", f"/candidate {item['candidate_id']}", "99")["message"]
    assert "候補" in message and "抜粋" in message and len(control.notifications()) == 1 and control.notifications() == []
    assert "6時間レポート" in control.digest()


def test_resident_worker_refreshes_without_network_and_daemon_entrypoint(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path); calls = []; shared = observer.default_state()
    async def run():
        stop = asyncio.Event()
        def refresh(*, observed_state=None): calls.append(observed_state); stop.set(); return {}
        monkeypatch.setattr(resident, "refresh", refresh)
        monkeypatch.setattr(resident, "load_config", lambda: {"refresh_interval_seconds": 5})
        monkeypatch.setattr(observer, "load_state", lambda: pytest.fail("daemon refresh must not reload observer state"))
        await observer.resident_worker({}, stop, shared)
    asyncio.run(run())
    assert calls == [shared] and resident_daemon.main.__module__ == "flop_agent.resident_daemon"
    unit = (core.ROOT / "packaging" / "oracle" / "resident.service").read_text("utf-8")
    assert "flop_agent.resident_daemon" in unit and ".venv/bin/python" in unit and "uv run" not in unit


def test_generic_poetic_question_is_not_high_candidate(monkeypatch, tmp_path):
    own, _, _ = populate(monkeypatch, tmp_path)
    state, config = observer.load_state(), observer.load_config()
    did = "did:key:z6MkPoetic"
    observer.process_message(state, config, "lobby", msg(1, did, "Curious if dreams and melodies reveal collaboration synergy?"), own, None)
    observer.save_state(state); resident.refresh()
    assert not [item for item in resident.list_candidates()["candidates"] if item["did"] == did]


def test_notifications_are_rate_limited_and_status_is_cached(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path); state = resident.default_state()
    for number in range(4):
        state["candidates"][str(number)] = {"candidate_id": str(number), "status": "pending", "priority": "high", "category": "help_request", "fingerprint": "abc", "room": "lobby", "seq": number, "why": "artifact evidence", "context": {"excerpt": "test", "untrusted": True}}
    resident.save_state(state); control = discord_control.Control({"42"}, "99")
    assert len(control.notifications()) == 3
    assert len(control.notifications()) == 0
    monkeypatch.setattr(observer, "load_state", lambda: pytest.fail("status must not load observer state"))
    assert resident.resident_status()["agents_known"] == 0


def test_five_thousand_agent_refresh_is_linear_enough(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path); own = "did:key:z6MkOwn"; (tmp_path / "verified-did.json").write_text(json.dumps({"did": own}), encoding="utf-8")
    state = observer.default_state(); timestamp = datetime.now(UTC).isoformat()
    for number in range(5000):
        did = f"did:key:z6MkLoad{number}"
        fingerprint = core.did_note_location(did)[2]
        state["agents"][fingerprint] = {"did": did, "fingerprint": fingerprint, "facts": {"first_seen": timestamp, "last_seen": timestamp, "last_encounter_at": timestamp, "seen_count": 1, "rooms": ["lobby"], "message_refs": [], "recent_messages": [{"text": f"unique technical test artifact {number}"}], "signed_count": 1, "unsigned_count": 0, "interaction_with_us": False}, "inferences": {"contribution_url_candidates": [], "role_candidates": [], "repeat_seen": False}}
    observer.save_state(state)
    started = time.perf_counter(); resident.refresh(); elapsed = time.perf_counter() - started
    assert elapsed < 10