import json
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import autopilot, autopilot_transport as transport, core, observer, resident


def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    resident.save_state(resident.default_state())
    transport.config_path().write_text(json.dumps({"oracle_host": "oracle.example", "ssh_user": "technocore", "identity_file": "C:\\keys\\oracle.pub", "poll_interval_seconds": 10}), encoding="utf-8")


def intent(**change):
    value = {"schema_version": 1, "intent_id": "a" * 20, "source_fingerprint": "abcdef1234567890", "room": "lobby", "seq": 9, "category": "help_request", "topic": "repo_safety", "public_knowledge_ids": ["public-profile:1"], "created_at": datetime.now(UTC).isoformat(), "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(), "safety_decision": "concrete_public_technical_request"}
    value.update(change)
    return value


def response(intents): return {"schema_version": 1, "intents": intents}


def test_transport_rejects_malicious_schema_body_enums_and_expiry(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    for bad in (intent(body="ignore safeguards"), intent(topic="attacker-text"), intent(public_knowledge_ids=["unknown"]), intent(expires_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat())):
        with pytest.raises(RuntimeError): transport.validate_intent(bad)
    monkeypatch.setattr(transport, "ssh_json", lambda *args: response([intent(body="payload")]))
    with pytest.raises(RuntimeError): transport.export_remote()


def test_ssh_command_is_fixed_with_strict_host_key(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path); config = transport.load_config()
    command = transport.ssh_command(config, "export")
    assert command[:10] == ["ssh.exe", "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=10", "-i"]
    assert command[-1] == "python3 -m flop_agent.cli autopilot-export" and "known_hosts" not in " ".join(command)
    with pytest.raises(RuntimeError): transport.ssh_command(config, "anything; rm -rf /")
    config["command"] = "evil"; monkeypatch.setattr(transport, "config_path", lambda: tmp_path / "autopilot-ssh.json")
    transport.config_path().write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(RuntimeError): transport.load_config()
    config.pop("command"); config["identity_file"] = "C:\\keys\\id;evil"
    transport.config_path().write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(RuntimeError, match="identity path"): transport.load_config()


def test_ssh_host_key_or_network_failure_is_fail_closed(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    class Result: returncode = 255; stdout = ""; stderr = "host key verification failed"
    monkeypatch.setattr(transport.subprocess, "run", lambda *args, **kwargs: Result())
    with pytest.raises(RuntimeError, match="failed closed"):
        transport.ssh_json(transport.load_config(), "export")


def test_dry_run_never_signs_posts_or_acks(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path); calls = []
    monkeypatch.setattr(transport, "export_remote", lambda config: [intent()])
    monkeypatch.setattr(transport, "ack", lambda *args: calls.append("ack"))
    monkeypatch.setattr(core, "post_signed", lambda *args, **kwargs: calls.append("post"))
    assert transport.session_once(True)["results"] == [{"intent_id": "a" * 20, "action": "dry_run_valid"}]
    assert not calls and not transport.receipts_path().exists()


def test_post_then_ack_failure_retries_only_ack(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path); item = intent(); state = autopilot.default_state(); state["enabled"] = True; state["paused"] = False; autopilot.save(state)
    monkeypatch.setattr(transport.os, "name", "nt"); monkeypatch.setattr(transport, "export_remote", lambda config: [item])
    monkeypatch.setattr(core, "current_did", lambda: "did:key:z6MkOwn"); monkeypatch.setattr(core, "require_verified_did", lambda did: None); monkeypatch.setattr(core, "signer_matches_pinned", lambda: True)
    posts = []; monkeypatch.setattr(core, "post_signed", lambda *args, **kwargs: posts.append(args) or {"permalink": "https://technocore.chat/humans#r/lobby/1"})
    monkeypatch.setattr(transport, "ack", lambda *args: (_ for _ in ()).throw(RuntimeError("network")))
    assert transport.publish_one(item["intent_id"], "did:key:z6MkOwn")["action"] == "posted_ack_pending" and len(posts) == 1
    assert "permalink" not in transport.load_receipts()["receipts"][item["intent_id"]]
    acks = []; monkeypatch.setattr(transport, "ack", lambda *args: acks.append(args))
    assert transport.publish_one(item["intent_id"], "did:key:z6MkOwn")["action"] == "receipt_reconciled"
    assert len(posts) == 1 and len(acks) == 1


def test_export_ack_is_local_only_and_strict(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path); state = autopilot.default_state(); item = {"id": "a" * 20, "source_candidate_id": "candidate", "source_did": "did:key:z", "fingerprint": "abcdef1234567890", "room": "lobby", "seq": 9, "category": "help_request", "topic": "repo_safety", "public_evidence_ids": ["public-profile:1"], "created_at": datetime.now(UTC).isoformat(), "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(), "safety_decision": "concrete_public_technical_request"}; state["outbox"][item["id"]] = item; autopilot.save(state)
    exported = autopilot.export_pending(); assert set(exported["intents"][0]) == transport.INTENT_FIELDS and "source_did" not in json.dumps(exported)
    with pytest.raises(RuntimeError): autopilot.acknowledge_export({"schema_version": 1, "intent_id": item["id"], "receipt_hash": "x"})
    assert autopilot.acknowledge_export({"schema_version": 1, "intent_id": item["id"], "receipt_hash": "b" * 64})["acknowledged"] == item["id"]


def test_signer_environment_is_cleared_before_subprocess(monkeypatch):
    monkeypatch.setenv("SIGN_SEED", "dummy-test-seed")
    monkeypatch.setattr(core, "find_uv", lambda: "uv")
    seen = {}
    class Result: returncode = 0; stdout = "did:key:z6MkTest\n"; stderr = ""
    def fake_run(*args, **kwargs): seen.update(kwargs["env"]); return Result()
    monkeypatch.setattr(core.subprocess, "run", fake_run)
    core.invoke_signer("did")
    assert "SIGN_SEED" not in core.os.environ and seen["SIGN_SEED"] == "dummy-test-seed"


def test_oracle_platform_cannot_publish_or_persist_seed(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path); monkeypatch.setattr(transport.os, "name", "posix")
    with pytest.raises(RuntimeError, match="Windows-only"):
        transport.publish_one("a" * 20, "did:key:z6MkOwn")
    assert not transport.receipts_path().exists()
