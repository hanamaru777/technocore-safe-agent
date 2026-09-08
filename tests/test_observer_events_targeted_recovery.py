import asyncio
import json

from flop_agent import (
    core,
    observer,
    observer_events_targeted_recovery as targeted,
    observer_resilience as resilience,
    observer_startup_resilience as startup,
)


def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    config = {**observer.DEFAULT_CONFIG, "read_budget_per_minute": 600}
    observer.atomic_json_write(observer.config_path(), config)
    return config


def message(seq):
    return {
        "seq": seq,
        "from": "did:key:z6MkAgent",
        "text": "hello",
        "ts": "2026-09-08T00:00:00Z",
    }


class CountingBudget:
    def __init__(self):
        self.calls = 0

    async def acquire(self):
        self.calls += 1


class FakeResponse:
    def __init__(self, rows):
        self.rows = rows
        self.status_code = 200
        self.headers = {}

    def raise_for_status(self):
        return None

    async def aiter_lines(self):
        for row in self.rows:
            yield json.dumps(row, separators=(",", ":"))


class FakeContext:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeClient:
    def __init__(self, rows):
        self.response = FakeResponse(rows)

    def stream(self, method, url, **kwargs):
        return FakeContext(self.response)


def test_startup_gap_stream_stops_exactly_at_proven_endpoint(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = resilience.default_state()
    state["cursors"]["events"] = 50
    resilience.set_error(
        state,
        "events",
        "startup_live_probe_gap",
        "cursor=50;first_unseen=60",
    )
    budget = CountingBudget()
    client = FakeClient([message(seq) for seq in range(45, 101)])

    monkeypatch.setattr(targeted, "_BASE_STARTUP_STREAM", startup._stream_events_startup_export)

    recovered, retry, error = asyncio.run(
        targeted._startup_stream_wrapper(
            client, budget, state, config, "events", None, None
        )
    )

    assert retry is None
    assert error is None
    assert recovered == 9
    assert state["cursors"]["events"] == 59
    assert state["health"]["rooms"]["events"]["status"] == "ok"
    assert state["metrics"]["startup_stream_export_attempts"] == 1
    assert state["metrics"]["startup_stream_export_successes"] == 1
    assert state["metrics"]["startup_stream_export_messages"] == 9
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0


def test_target_missing_from_snapshot_stays_fail_closed(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = resilience.default_state()
    state["cursors"]["events"] = 50
    resilience.set_error(
        state,
        "events",
        "startup_live_probe_gap",
        "cursor=50;first_unseen=60",
    )
    rows = [message(seq) for seq in range(45, 59)] + [message(60), message(61)]
    client = FakeClient(rows)

    monkeypatch.setattr(targeted, "_BASE_STARTUP_STREAM", startup._stream_events_startup_export)

    recovered, retry, error = asyncio.run(
        targeted._startup_stream_wrapper(
            client, CountingBudget(), state, config, "events", None, None
        )
    )

    assert recovered == 0
    assert retry is None
    assert error == "target_not_in_export"
    assert state["cursors"]["events"] == 50
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0


def test_steady_live_gap_uses_exact_target_before_base(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["events"] = 50
    calls = []

    async def fake_targeted(*args, stop_after_seq, **kwargs):
        calls.append(("target", stop_after_seq))
        assert stop_after_seq == 59
        state["cursors"]["events"] = 59
        return 9, None, None

    async def fake_base(*args, **kwargs):
        calls.append(("base", state["cursors"]["events"]))
        assert state["cursors"]["events"] == 59
        state["cursors"]["events"] = 60
        return True, False

    monkeypatch.setattr(targeted, "stream_events_export_targeted", fake_targeted)
    monkeypatch.setattr(targeted, "_BASE_PROCESS_LIVE", fake_base)

    changed, drain = asyncio.run(
        targeted.process_live_payload_with_recovery(
            object(),
            object(),
            state,
            {},
            "events",
            {"messages": [message(60)]},
            None,
            None,
            bootstrap=False,
        )
    )

    assert changed is True
    assert drain is False
    assert calls == [("target", 59), ("base", 59)]
    assert state["cursors"]["events"] == 60
    assert state["metrics"]["gap_recovery_attempts"] == 1
    assert state["metrics"]["events_steady_stream_attempts"] == 1
    assert state["metrics"]["events_steady_stream_successes"] == 1
    assert state["metrics"]["events_steady_stream_failures"] == 0
    assert state["metrics"]["events_steady_stream_messages"] == 9


def test_steady_live_transport_error_retries_live_without_export(monkeypatch):
    state = resilience.default_state()

    async def forbidden(*args, **kwargs):
        raise AssertionError("untargeted export/base fallback must not run")

    monkeypatch.setattr(targeted, "_BASE_RECOVER_AFTER_ERROR", forbidden)

    changed, recovered, retry, error = asyncio.run(
        targeted.recover_after_live_error(
            object(), object(), state, {}, "events", None, None
        )
    )

    assert changed is True
    assert recovered == 0
    assert retry is None
    assert error == "retry_live"
    assert state["metrics"]["events_steady_stream_live_error_attempts"] == 1
    assert state["metrics"]["events_steady_live_error_retries"] == 1


def test_non_events_delegates_unchanged(monkeypatch):
    state = resilience.default_state()
    calls = []

    async def fake_process(*args, **kwargs):
        calls.append("process")
        return False, False

    async def fake_recover(*args, **kwargs):
        calls.append("recover")
        return False, 0, None, None

    monkeypatch.setattr(targeted, "_BASE_PROCESS_LIVE", fake_process)
    monkeypatch.setattr(targeted, "_BASE_RECOVER_AFTER_ERROR", fake_recover)

    asyncio.run(
        targeted.process_live_payload_with_recovery(
            object(), object(), state, {}, "lobby", {"messages": []}, None, None,
            bootstrap=False,
        )
    )
    asyncio.run(
        targeted.recover_after_live_error(
            object(), object(), state, {}, "lobby", None, None
        )
    )

    assert calls == ["process", "recover"]
