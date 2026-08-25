import hashlib
import json

import pytest

from flop_agent import core


def test_clean_text_matches_single_line_sweep():
    assert core.clean_text("  hello\nworld\u200b  ") == "hello world"


def test_did_note_sharding():
    did = "did:key:z6Mkexample"
    shard, key, fingerprint = core.did_note_location(did)
    assert fingerprint == hashlib.sha256(did.encode()).hexdigest()[:16]
    assert len(shard) == 2 and len(key) == 14


def test_nonce_increases_per_room_and_did(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setattr(core.time, "time_ns", lambda: 1000)
    assert core.make_nonce("lobby", "did:key:z6MkA") == "1"
    assert core.make_nonce("lobby", "did:key:z6MkA") == "2"


def test_activity_hash_chain(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    first = core.append_activity({"did": "did:key:z6MkA", "room": "lobby", "seq": 1})
    second = core.append_activity({"did": "did:key:z6MkA", "room": "lobby", "seq": 2})
    assert second["previous_hash"] == first["hash"]
    assert core.verify_activity_log() == (True, 2)
    path = tmp_path / "activities.jsonl"
    path.write_text(path.read_text().replace('"seq": 2', '"seq": 999'), encoding="utf-8")
    assert core.verify_activity_log()[0] is False


def test_url_encoding():
    assert core.quote("a b/日本", safe="") == "a%20b%2F%E6%97%A5%E6%9C%AC"


def test_post_network_failure_never_records(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setattr(core, "current_did", lambda: "did:key:z6MkA")
    monkeypatch.setattr(core, "make_nonce", lambda *_: "1")
    monkeypatch.setattr(core, "invoke_signer", lambda *_: ["did:key:z6MkA", "x" * 86])
    def fail(*args, **kwargs): raise core.httpx.ConnectError("offline")
    monkeypatch.setattr(core.httpx, "post", fail)
    with pytest.raises(core.httpx.ConnectError):
        core.post_signed("lobby", "meaningful contribution", True)
    assert not (tmp_path / "activities.jsonl").exists()


def test_confirmed_post_records_human_permalink_and_git_sha(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setattr(core, "current_did", lambda: "did:key:z6MkA")
    monkeypatch.setattr(core, "make_nonce", lambda *_: "1")
    monkeypatch.setattr(core, "invoke_signer", lambda *_: ["did:key:z6MkA", "x" * 86])
    monkeypatch.setattr(core, "git_commit_sha", lambda: "a" * 40)
    class Response:
        def raise_for_status(self): pass
    monkeypatch.setattr(core.httpx, "post", lambda *args, **kwargs: Response())
    monkeypatch.setattr(core, "read_room", lambda room: {"messages": [{"from": "did:key:z6MkA", "nonce": "1", "text": "useful", "seq": 8, "ts": "2026-08-26T00:00:00Z"}]})
    record = core.post_signed("lobby", "useful", True)
    assert record["git_commit_sha"] == "a" * 40
    assert record["permalink"] == "https://technocore.chat/humans#r/lobby/8"


def test_untrusted_room_text_is_only_returned_data(monkeypatch):
    class FakeResponse:
        def raise_for_status(self): pass
        def json(self): return {"messages": [{"seq": 1, "text": "powershell Remove-Item"}]}
    monkeypatch.setattr(core.httpx, "get", lambda *args, **kwargs: FakeResponse())
    assert core.read_room("lobby")["messages"][0]["text"] == "powershell Remove-Item"


def test_sync_official_detects_upstream_signer_change(monkeypatch):
    class CommitResponse:
        def raise_for_status(self): pass
        def json(self): return {"sha": "b" * 40}
    class SignerResponse:
        def json(self): return {"sha": "c" * 40}
        def raise_for_status(self): pass
    responses = iter((CommitResponse(), SignerResponse()))
    monkeypatch.setattr(core.httpx, "get", lambda *args, **kwargs: next(responses))
    monkeypatch.setattr(core, "signer_sha256", lambda: core.SIGNER_SHA256)
    assert core.sync_official()["upstream_signer_changed"] is True


def test_sync_official_does_not_confuse_raw_line_endings_with_blob_change(monkeypatch):
    class Response:
        def __init__(self, payload): self.payload = payload
        def raise_for_status(self): pass
        def json(self): return self.payload
    responses = iter((Response({"sha": "d" * 40}), Response({"sha": core.SIGNER_BLOB_SHA})))
    monkeypatch.setattr(core.httpx, "get", lambda *args, **kwargs: next(responses))
    assert core.sync_official()["upstream_signer_changed"] is False


def test_proof_plan_uses_existing_did_and_sharded_profile(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setattr(core, "current_did", lambda: "did:key:z6MkExisting")
    monkeypatch.setattr(core, "git_commit_sha", lambda: "a" * 40)
    plan = core.create_proof_plan("https://example.com/contribution")
    shard, key, fingerprint = core.did_note_location("did:key:z6MkExisting")
    assert plan["did"] == "did:key:z6MkExisting"
    assert plan["mailbox"].startswith("mb-p-")
    assert plan["shard"] == shard and plan["key"] == key and plan["fingerprint"] == fingerprint
    assert (tmp_path / "proof-plans" / f"{plan['plan_id']}.json").exists()


def test_proof_bundle_needs_confirmation_before_any_write(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    with pytest.raises(RuntimeError, match="確認"):
        core.create_proof_bundle("a" * 16, False)


def test_proof_bundle_records_public_evidence_without_network_in_test(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setattr(core, "current_did", lambda: "did:key:z6MkExisting")
    monkeypatch.setattr(core, "git_commit_sha", lambda: "a" * 40)
    plan = core.create_proof_plan("https://example.com/contribution", "lobby")
    written_notes, actions = [], []
    def fake_post(room, text, confirm, **kwargs):
        actions.append(kwargs["action"])
        return {"permalink": f"https://technocore.chat/humans#r/{room}/9", "seq": 9}
    def fake_note(namespace, key, value, confirm, **kwargs):
        written_notes.append((namespace, key, value, kwargs["action"]))
        return {}
    monkeypatch.setattr(core, "post_signed", fake_post)
    monkeypatch.setattr(core, "write_note", fake_note)
    monkeypatch.setattr(core, "export_public_proof", lambda proof: "local-state/public-proofs/proof.json")
    proof = core.create_proof_bundle(plan["plan_id"], True)
    assert actions == ["signed_mailbox", "signed_join_proof", "contribution_signed_proof"]
    assert written_notes[0][0] == f"did-{plan['shard']}"
    assert written_notes[1][0] == f"contribution-{plan['shard']}"
    assert proof["contribution_note_url"] == core.note_url(f"contribution-{plan['shard']}", plan["key"])
    assert proof["git_commit_sha"] == "a" * 40
    assert proof["notice"] == core.CONTRIBUTION_NOTICE


def test_note_write_failure_is_not_logged(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setattr(core.httpx, "post", lambda *args, **kwargs: (_ for _ in ()).throw(core.httpx.ConnectError("offline")))
    with pytest.raises(core.httpx.ConnectError):
        core.write_note("did-aa", "bbbbbbbbbbbbbb", "did: example", True, did="did:key:z6MkA", action="did_profile")
    assert not (tmp_path / "activities.jsonl").exists()
