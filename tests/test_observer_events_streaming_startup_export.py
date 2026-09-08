import asyncio
import json

from flop_agent import core, observer, observer_resilience, observer_startup_resilience


def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    config = {**observer.DEFAULT_CONFIG, "read_budget_per_minute": 600}
    observer.atomic_json_write(observer.config_path(), config)
    return config


def message(seq, text="hello", did="did:key:z6MkAgent"):
    return {
        "seq": seq,
        "from": did,
        "text": text,
        "ts": "2026-09-08T00:00:00Z",
    }


class CountingBudget:
    def __init__(self):
        self.calls = 0

    async def acquire(self):
        self.calls += 1


class Writer:
    def __init__(self):
        self.dirty = 0

    def mark_dirty(self):
        self.dirty += 1


class FakeResponse:
    def __init__(self, rows, *, status_code=200, fail_after=None, headers=None):
        self.rows = rows
        self.status_code = status_code
        self.fail_after = fail_after
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            request = observer.httpx.Request("GET", "https://technocore.chat/r/events/export")
            response = observer.httpx.Response(self.status_code, request=request)
            raise observer.httpx.HTTPStatusError(
                "error", request=request, response=response
            )

    async def aiter_lines(self):
        for index, row in enumerate(self.rows):
            if self.fail_after is not None and index >= self.fail_after:
                raise observer.httpx.ReadTimeout("stream stalled")
            yield json.dumps(row, separators=(",", ":"))


class FakeStreamContext:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def stream(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return FakeStreamContext(self.response)


def test_events_stream_export_skips_old_rows_and_drains_contiguous_tail(
    monkeypatch, tmp_path
):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["events"] = 50
    budget = CountingBudget()
    writer = Writer()
    client = FakeClient(FakeResponse([message(seq) for seq in range(45, 61)]))

    recovered, retry, error = asyncio.run(
        observer_startup_resilience._stream_events_startup_export(
            client, budget, state, config, "events", None, None, writer
        )
    )

    assert error is None
    assert retry is None
    assert recovered == 10
    assert budget.calls == 1
    assert state["cursors"]["events"] == 60
    assert state["health"]["rooms"]["events"]["status"] == "ok"
    assert state["metrics"]["startup_stream_export_attempts"] == 1
    assert state["metrics"]["startup_stream_export_successes"] == 1
    assert state["metrics"]["startup_stream_export_messages"] == 10
    assert state["metrics"]["startup_stream_export_failures"] == 0
    assert state["metrics"]["startup_stream_export_bytes"] > 0
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0
    assert writer.dirty >= 1
    assert client.calls[0][0] == "GET"
    assert client.calls[0][1].endswith("/r/events/export")


def test_events_stream_export_makes_bounded_progress_before_stream_failure(
    monkeypatch, tmp_path
):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["events"] = 50
    budget = CountingBudget()
    writer = Writer()
    monkeypatch.setattr(observer_resilience, "RECOVERY_CHUNK_MESSAGES", 2)
    client = FakeClient(
        FakeResponse([message(51), message(52), message(53)], fail_after=2)
    )

    recovered, retry, error = asyncio.run(
        observer_startup_resilience._stream_events_startup_export(
            client, budget, state, config, "events", None, None, writer
        )
    )

    assert error == "ReadTimeout"
    assert retry is None
    assert recovered == 2
    assert state["cursors"]["events"] == 52
    assert state["metrics"]["startup_stream_export_attempts"] == 1
    assert state["metrics"]["startup_stream_export_successes"] == 0
    assert state["metrics"]["startup_stream_export_failures"] == 1
    assert state["metrics"]["startup_stream_export_messages"] == 2
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0
    assert writer.dirty >= 1


def test_events_live_gap_uses_streaming_export_not_buffered_export(
    monkeypatch, tmp_path
):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["events"] = 50
    stop = asyncio.Event()
    budget = CountingBudget()
    writer = Writer()
    client = FakeClient(FakeResponse([message(seq) for seq in range(51, 61)]))

    async def fake_live(*args, **kwargs):
        return {"messages": [message(60)]}, None, None

    async def forbidden_buffered_export(*args, **kwargs):
        raise AssertionError("events startup gap must use streaming export")

    monkeypatch.setattr(observer_resilience, "read_room_live", fake_live)
    monkeypatch.setattr(observer_resilience, "read_room_export", forbidden_buffered_export)

    asyncio.run(
        observer_startup_resilience.startup_catchup(
            client, budget, state, config, "events", None, None, stop, writer
        )
    )

    assert budget.calls == 2
    assert state["cursors"]["events"] == 60
    assert state["health"]["rooms"]["events"]["status"] == "ok"
    assert state["metrics"]["startup_live_probe_attempts"] == 1
    assert state["metrics"]["startup_live_probe_successes"] == 0
    assert state["metrics"]["startup_live_probe_fallbacks"] == 1
    assert state["metrics"]["startup_stream_export_attempts"] == 1
    assert state["metrics"]["startup_stream_export_successes"] == 1
    assert state["metrics"]["startup_stream_export_messages"] == 10
    assert state["metrics"]["startup_export_attempts"] == 0
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0


def test_events_stream_export_rejects_non_monotonic_snapshot(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["events"] = 50
    budget = CountingBudget()
    client = FakeClient(FakeResponse([message(51), message(53), message(52)]))

    recovered, retry, error = asyncio.run(
        observer_startup_resilience._stream_events_startup_export(
            client, budget, state, config, "events", None, None
        )
    )

    assert recovered == 0
    assert retry is None
    assert error == "invalid_export_order"
    assert state["cursors"]["events"] == 50
    assert state["metrics"]["startup_stream_export_failures"] == 1
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0
