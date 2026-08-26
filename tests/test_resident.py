import json
import subprocess
import sys
import zipfile
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import core, discord_control, observer, resident


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
    assert "manifest.json" in names and "secret.txt" not in names
    assert all("seed" not in name.lower() and "secret" not in name.lower() for name in names)


def test_oracle_import_rejects_files_outside_allowlist(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path); resident.save_state(resident.default_state())
    archive = resident.export_state()
    target = tmp_path / "imported"
    script = core.ROOT / "packaging" / "oracle" / "import-state.py"
    result = subprocess.run([sys.executable, str(script), archive, str(target)], capture_output=True, text=True, check=False)
    assert result.returncode == 0 and (target / "resident-state.json").exists()
    unsafe = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(unsafe, "w") as bundle:
        bundle.writestr("manifest.json", '{"files": []}')
        bundle.writestr("not-allowed.txt", "x")
    result = subprocess.run([sys.executable, str(script), str(unsafe), str(target)], capture_output=True, text=True, check=False)
    assert result.returncode != 0
