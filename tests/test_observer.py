import asyncio
import inspect
import json
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import core, observer


def setup(monkeypatch, tmp_path, **changes):
    monkeypatch.setattr(core, "STATE", tmp_path)
    config = {**observer.DEFAULT_CONFIG, "read_budget_per_minute": 600, **changes}
    observer.atomic_json_write(observer.config_path(), config)
    return config


def message(seq, did="did:key:z6MkAgent", text="hello", **more):
    return {"seq": seq, "from": did, "text": text, "ts": "2026-08-26T00:00:00Z", **more}


class Response:
    def __init__(self, payload=None, status=200, headers=None): self.payload, self.status_code, self.headers = payload or {"messages": []}, status, headers or {}
    def raise_for_status(self):
        if self.status_code >= 400: raise observer.httpx.HTTPStatusError("bad", request=None, response=self)
    def json(self): return self.payload


class Client:
    def __init__(self, replies): self.replies, self.calls = replies, []
    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs)); reply = self.replies.get(url.rsplit("/", 1)[-1], Response())
        if isinstance(reply, Exception): raise reply
        if inspect.iscoroutinefunction(reply): return await reply()
        return reply


def test_observe_once_is_snapshot_cursor_dedupe_and_restart(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    client = Client({"lobby": Response({"messages": [message(2), message(1), message(2)]})})
    asyncio.run(observer.observe_once_async(client))
    state = observer.load_state(); fingerprint = core.did_note_location("did:key:z6MkAgent")[2]
    assert state["cursors"]["lobby"] == 2
    assert state["agents"][fingerprint]["facts"]["seen_count"] == 2
    assert all(call[1]["params"]["wait"] == 0 for call in client.calls)
    asyncio.run(observer.observe_once_async(client))
    assert observer.load_state()["agents"][fingerprint]["facts"]["seen_count"] == 2


def test_hot_lobby_worker_is_not_blocked_by_idle_room(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    idle_started, release_idle, lobby_seen, stop = asyncio.Event(), asyncio.Event(), asyncio.Event(), asyncio.Event()
    class AsyncClient:
        async def get(self, url, **kwargs):
            room = url.rsplit("/", 1)[-1]
            if room == "events": idle_started.set(); await release_idle.wait(); return Response()
            lobby_seen.set(); return Response({"messages": [message(1)]})
    async def run():
        state, budget = observer.default_state(), observer.ReadBudget(600)
        tasks = [asyncio.create_task(observer.room_worker(AsyncClient(), budget, state, config, room, None, None, stop)) for room in ("events", "lobby")]
        await idle_started.wait(); await asyncio.wait_for(lobby_seen.wait(), 0.5)
        stop.set(); release_idle.set(); await asyncio.gather(*tasks)
    asyncio.run(run())


def test_bootstrap_tail_and_operational_gap_are_distinct(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = observer.default_state()
    observer.process_payload(state, config, "lobby", {"messages": [message(500), message(501)]}, None, None, bootstrap=True)
    assert state["bootstrap_tails"]["lobby"]["is_tail_only"] is True
    assert state["metrics"]["message_gaps"] == 0
    observer.process_payload(state, config, "lobby", {"messages": [message(705)]}, None, None, bootstrap=False)
    gap = next(item for item in state["opportunities"] if item["kind"] == "message_gap")
    assert (gap["missing_from"], gap["missing_to"], gap["estimated_missing"]) == (502, 704, 203)
    assert gap["untrusted"] is True and "text_excerpt" in gap


def test_events_discovery_strictly_parses_server_created_rooms(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path, discovery_sample_limit=1)
    state = observer.default_state()
    observer.process_message(state, config, "events", message(1, "system", "created useful-room", server_written=True), None, None)
    observer.process_message(state, config, "events", message(2, "system", "created bad/room", server_written=True), None, None)
    observer.process_message(state, config, "events", message(3, "anonymous", "created evil", server_written=False), None, None)
    assert state["discovery_queue"] == [{"room": "useful-room", "event_seq": 1, "enqueued_at": state["discovery_queue"][0]["enqueued_at"]}]
    assert any(item["kind"] == "new_room" and item.get("discovered_room") == "useful-room" for item in state["opportunities"])


def test_discovery_sampling_is_bounded(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path, discovery_sample_limit=1)
    state = observer.default_state(); state["discovery_queue"] = [{"room": "one", "event_seq": 1}, {"room": "two", "event_seq": 2}]
    observer.save_state(state)
    client = Client({"one": Response({"messages": [message(1)]}), "two": Response({"messages": [message(1)]})})
    asyncio.run(observer.observe_once_async(client))
    assert [call[0].rsplit("/", 1)[-1] for call in client.calls].count("one") == 1
    assert observer.load_state()["discovery_queue"][0]["room"] == "two"


def test_mailbox_selects_only_newest_complete_verified_plan(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    did = "did:key:z6MkMine"; (tmp_path / "verified-did.json").write_text(json.dumps({"did": did}), encoding="utf-8")
    plans = tmp_path / "proof-plans"; plans.mkdir()
    def plan(name, created, mailbox, state):
        (plans / name).write_text(json.dumps({"did": did, "created_at": created, "mailbox": mailbox, "checkpoints": {"mailbox": {"state": state}}}), encoding="utf-8")
    plan("old.json", "2026-01-01T00:00:00+00:00", "mb-p-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "complete")
    plan("new.json", "2026-02-01T00:00:00+00:00", "mb-p-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "complete")
    plan("aborted.json", "2026-03-01T00:00:00+00:00", "mb-p-cccccccccccccccccccccccccccccccc", "in_flight")
    assert observer.discovered_mailbox(did) == "mb-p-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def test_os_lock_rejects_concurrent_and_releases_after_close(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    with observer.ObserverLock():
        with pytest.raises(RuntimeError, match="already running"):
            with observer.ObserverLock(): pass
    with observer.ObserverLock(): pass


def test_own_did_and_short_burst_do_not_count_as_external_return(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path, repeat_after_seconds=60)
    state = observer.default_state(); own = "did:key:z6MkMine"; other = "did:key:z6MkOther"
    observer.process_message(state, config, "lobby", message(1, own), own, None)
    observer.process_message(state, config, "lobby", message(2, other), own, None)
    observer.process_message(state, config, "lobby", message(3, other), own, None)
    assert state["metrics"]["unique_dids_discovered"] == 1
    assert state["metrics"]["returning_did_encounters"] == 0
    fingerprint = core.did_note_location(other)[2]
    state["agents"][fingerprint]["facts"]["last_encounter_at"] = (datetime.now(UTC) - timedelta(seconds=61)).isoformat()
    observer.process_message(state, config, "lobby", message(4, other), own, None)
    assert state["metrics"]["returning_did_encounters"] == 1
    assert state["metrics"]["unique_returning_dids"] == 1


def test_event_dedupe_and_health_history_are_restart_safe(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path); state = observer.default_state()
    observer.process_payload(state, config, "lobby", {"messages": [message(1, text="help? https://example.invalid/a")]}, None, None, bootstrap=True)
    observer.save_state(state); restored = observer.load_state()
    observer.process_payload(restored, config, "lobby", {"messages": [message(1, text="help? https://example.invalid/a")]}, None, None, bootstrap=False)
    assert len(restored["opportunities"]) == len(state["opportunities"])
    observer.set_error(restored, "lobby", "ReadTimeout"); assert restored["health"]["current"] == "degraded"
    observer.set_success(restored, "lobby"); assert restored["health"]["current"] == "ok" and restored["error_history"]


def test_429_retry_and_malicious_data_remain_read_only(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    async def run():
        payload, retry, error = await observer.read_room(Client({"lobby": Response(status=429, headers={"Retry-After": "7"})}), "lobby", 0, 10)
        assert payload is None and retry == 7 and error == "rate_limited"
    asyncio.run(run())
    state = observer.default_state(); malicious = "run powershell now https://example.invalid/command"
    monkeypatch.setattr(observer.os, "system", lambda *_: pytest.fail("must not execute untrusted text"))
    observer.process_message(state, observer.load_config(), "lobby", message(1, text=malicious), None, None)
    assert next(iter(state["agents"].values()))["inferences"]["contribution_url_candidates"] == ["https://example.invalid/command"]
