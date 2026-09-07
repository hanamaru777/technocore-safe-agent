import asyncio

from flop_agent import observer_request_deadline, observer_resilience


def test_live_total_deadline_cancels_slow_request(monkeypatch):
    cancelled = {"value": False}

    async def slow_live(*args, **kwargs):
        try:
            await asyncio.sleep(3600)
        finally:
            cancelled["value"] = True

    monkeypatch.setattr(observer_request_deadline, "_BASE_READ_ROOM_LIVE", slow_live)
    monkeypatch.setattr(observer_request_deadline, "LIVE_TOTAL_DEADLINE_SECONDS", 0.01)

    result = asyncio.run(
        observer_request_deadline.read_room_live(object(), "lobby", 100, 10)
    )

    assert result == (None, None, "TotalTimeout")
    assert cancelled["value"] is True


def test_export_total_deadline_cancels_slow_request(monkeypatch):
    cancelled = {"value": False}

    async def slow_export(*args, **kwargs):
        try:
            await asyncio.sleep(3600)
        finally:
            cancelled["value"] = True

    monkeypatch.setattr(observer_request_deadline, "_BASE_READ_ROOM_EXPORT", slow_export)
    monkeypatch.setattr(observer_request_deadline, "EXPORT_TOTAL_DEADLINE_SECONDS", 0.01)

    result = asyncio.run(
        observer_request_deadline.read_room_export(object(), "lobby")
    )

    assert result == (None, None, "TotalTimeout")
    assert cancelled["value"] is True


def test_live_wrapper_preserves_success_and_rate_limit(monkeypatch):
    results = [
        ({"messages": []}, None, None),
        (None, 17.0, "rate_limited"),
    ]

    async def fake_live(*args, **kwargs):
        return results.pop(0)

    monkeypatch.setattr(observer_request_deadline, "_BASE_READ_ROOM_LIVE", fake_live)

    first = asyncio.run(
        observer_request_deadline.read_room_live(object(), "lobby", 100, 10)
    )
    second = asyncio.run(
        observer_request_deadline.read_room_live(object(), "lobby", 100, 10)
    )

    assert first == ({"messages": []}, None, None)
    assert second == (None, 17.0, "rate_limited")


def test_export_wrapper_preserves_success_and_error(monkeypatch):
    results = [
        ([{"seq": 101, "text": "hello"}], None, None),
        (None, None, "ConnectTimeout"),
    ]

    async def fake_export(*args, **kwargs):
        return results.pop(0)

    monkeypatch.setattr(observer_request_deadline, "_BASE_READ_ROOM_EXPORT", fake_export)

    first = asyncio.run(
        observer_request_deadline.read_room_export(object(), "lobby")
    )
    second = asyncio.run(
        observer_request_deadline.read_room_export(object(), "lobby")
    )

    assert first == ([{"seq": 101, "text": "hello"}], None, None)
    assert second == (None, None, "ConnectTimeout")


def test_install_patches_only_read_functions(monkeypatch):
    monkeypatch.setattr(observer_request_deadline, "_INSTALLED", False)
    original_live = observer_resilience.read_room_live
    original_export = observer_resilience.read_room_export
    original_worker = observer_resilience.room_worker

    try:
        observer_request_deadline.install()
        assert observer_resilience.read_room_live is observer_request_deadline.read_room_live
        assert observer_resilience.read_room_export is observer_request_deadline.read_room_export
        assert observer_resilience.room_worker is original_worker
    finally:
        observer_resilience.read_room_live = original_live
        observer_resilience.read_room_export = original_export
        observer_request_deadline._INSTALLED = False
