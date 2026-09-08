import asyncio
import json

from flop_agent import observer, observer_core_local_continuity as final, observer_resilience as resilience


def msg(seq):
    return {"seq": seq, "from": "did:key:z6MkAgent", "text": "hello", "ts": "2026-09-08T00:00:00Z"}


class Budget:
    def __init__(self): self.calls = 0
    async def acquire(self): self.calls += 1


class Stop:
    def is_set(self): return False
    async def wait(self): await asyncio.sleep(3600)


class Response:
    status_code = 200
    headers = {}
    def __init__(self, rows): self.rows = rows
    def raise_for_status(self): return None
    async def aiter_lines(self):
        for row in self.rows:
            yield json.dumps(row, separators=(",", ":"))


class Context:
    def __init__(self, rows): self.response = Response(rows)
    async def __aenter__(self): return self.response
    async def __aexit__(self, exc_type, exc, tb): return False


class Client:
    def __init__(self, rows): self.rows = rows
    def stream(self, *args, **kwargs): return Context(self.rows)


def cfg(): return {**observer.DEFAULT_CONFIG, "read_budget_per_minute": 600}


def event_state():
    state = resilience.default_state()
    state["cursors"]["events"] = 50
    resilience.set_error(state, "events", "startup_live_probe_gap", "cursor=50;first_unseen=60")
    return state


def test_exact_events_snapshot_accounts_only_absent_suffix(monkeypatch):
    state = event_state()
    monkeypatch.setattr(final, "_BASE_EVENTS_STARTUP_STREAM", object())
    recovered, retry, error = asyncio.run(final.stream_events_startup_export(
        Client([msg(i) for i in range(45, 56)] + [msg(60)]), Budget(), state, cfg(), "events", None, None
    ))
    assert (recovered, retry, error) == (5, None, None)
    assert state["cursors"]["events"] == 59
    assert state["metrics"]["unrecoverable_core_gap_events"] == 1
    assert state["metrics"]["unrecoverable_core_gap_messages"] == 4
    assert state["last_unrecoverable_gap"]["missing_from"] == 56
    assert state["last_unrecoverable_gap"]["missing_to"] == 59
    assert state["last_unrecoverable_gap"]["recovery_reason"] == "not_in_retained_export"


def test_exact_events_snapshot_present_has_no_unrecoverable(monkeypatch):
    state = event_state()
    monkeypatch.setattr(final, "_BASE_EVENTS_STARTUP_STREAM", object())
    recovered, retry, error = asyncio.run(final.stream_events_startup_export(
        Client([msg(i) for i in range(45, 80)]), Budget(), state, cfg(), "events", None, None
    ))
    assert (recovered, retry, error) == (9, None, None)
    assert state["cursors"]["events"] == 59
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0
    assert state["metrics"].get("events_startup_snapshot_unrecoverable_events", 0) == 0


def test_lobby_gap_waits_when_fresh_capture_still_behind(monkeypatch):
    state = resilience.default_state(); state["cursors"]["lobby"] = 1
    async def incomplete(*a, **k): return False, 0, False
    async def forbidden(*a, **k): raise AssertionError("server fallback raced healthy capture")
    monkeypatch.setattr(final.spool, "_recover_exact_spool_range_with_grace", incomplete)
    monkeypatch.setattr(final.capture, "status", lambda: {"capture_cursor": 2, "last_error": "", "last_success_at": "now"})
    monkeypatch.setattr(final, "_capture_fresh", lambda *a, **k: True)
    monkeypatch.setattr(final, "_BASE_PROCESS_LIVE", forbidden)
    changed, drain = asyncio.run(final.process_live_payload_with_recovery(
        object(), object(), state, cfg(), "lobby", {"messages": [msg(4)]}, None, None, bootstrap=False
    ))
    assert changed is True and drain is False
    assert state["cursors"]["lobby"] == 1
    assert state["health"]["rooms"]["lobby"]["kind"] == "gap_recovery_lobby_capture_pending"
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0


def test_lobby_gap_delegates_after_capture_crosses_boundary(monkeypatch):
    state = resilience.default_state(); state["cursors"]["lobby"] = 1; calls = []
    async def incomplete(*a, **k): return False, 0, False
    async def base(*a, **k): calls.append("base"); return True, False
    monkeypatch.setattr(final.spool, "_recover_exact_spool_range_with_grace", incomplete)
    monkeypatch.setattr(final.capture, "status", lambda: {"capture_cursor": 4, "last_error": "", "last_success_at": "now"})
    monkeypatch.setattr(final, "_capture_fresh", lambda *a, **k: True)
    monkeypatch.setattr(final, "_BASE_PROCESS_LIVE", base)
    asyncio.run(final.process_live_payload_with_recovery(
        object(), object(), state, cfg(), "lobby", {"messages": [msg(4)]}, None, None, bootstrap=False
    ))
    assert calls == ["base"]


def test_lobby_startup_fresh_local_capture_skips_server(monkeypatch):
    state = resilience.default_state(); state["cursors"]["lobby"] = 10
    monkeypatch.setattr(final.capture, "status", lambda: {"capture_cursor": 15, "last_error": "", "last_success_at": "now"})
    monkeypatch.setattr(final.capture, "contiguous_end", lambda start: 15)
    monkeypatch.setattr(final, "_capture_fresh", lambda *a, **k: True)
    async def drain(state, config, start, end, own_did, mailbox):
        state["cursors"]["lobby"] = 15; return True, 5
    async def forbidden(*a, **k): raise AssertionError("redundant startup server export")
    monkeypatch.setattr(final.spool, "_drain_complete_spool_range", drain)
    monkeypatch.setattr(final, "_BASE_STARTUP_CATCHUP", forbidden)
    asyncio.run(final.startup_catchup(object(), object(), state, cfg(), "lobby", None, None, Stop()))
    assert state["cursors"]["lobby"] == 15
    assert state["health"]["rooms"]["lobby"]["status"] == "ok"
    assert state["metrics"]["lobby_startup_capture_shortcuts"] == 1
