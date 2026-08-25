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
        content = b"changed signer"
        def raise_for_status(self): pass
    responses = iter((CommitResponse(), SignerResponse()))
    monkeypatch.setattr(core.httpx, "get", lambda *args, **kwargs: next(responses))
    monkeypatch.setattr(core, "signer_sha256", lambda: core.SIGNER_SHA256)
    assert core.sync_official()["upstream_signer_changed"] is True
