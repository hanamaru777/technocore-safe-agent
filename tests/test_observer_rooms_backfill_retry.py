import asyncio

from flop_agent import observer, observer_resilience, observer_rooms_backfill_retry as retry


class Writer:
    def __init__(self):
        self.dirty = 0

    def mark_dirty(self):
        self.dirty += 1


def config():
    return {**observer.DEFAULT_CONFIG, "rooms_backfill_interval_seconds": 3600}


def state():
    return observer_resilience.default_state()


def test_success_keeps_normal_one_hour_cadence():
    s = state()
    observer_resilience.set_success(s, "rooms")
    delay, backoff = retry.next_delay(s, config(), 30.0)
    assert delay == 3600.0
    assert backoff == 0.0


def test_transient_error_uses_bounded_exponential_backoff():
    s = state()
    observer_resilience.set_error(s, "rooms", "ConnectTimeout", "")

    delay, backoff = retry.next_delay(s, config(), 0.0)
    assert delay == 5.0
    assert backoff == 5.0

    delay, backoff = retry.next_delay(s, config(), backoff)
    assert delay == 10.0
    assert backoff == 10.0

    delay, backoff = retry.next_delay(s, config(), 40.0)
    assert delay == 60.0
    assert backoff == 60.0


def test_rate_limit_honors_retry_after_without_hour_sleep():
    s = state()
    observer_resilience.set_error(s, "rooms", "rate_limited", "37")
    delay, backoff = retry.next_delay(s, config(), 0.0)
    assert delay == 37.0
    assert backoff == 37.0


def test_worker_retries_error_then_returns_to_normal_cadence(monkeypatch):
    s = state()
    cfg = config()
    stop = asyncio.Event()
    writer = Writer()
    calls = 0
    delays = []

    async def fake_backfill(client, budget, current, current_config):
        nonlocal calls
        calls += 1
        if calls == 1:
            observer_resilience.set_error(current, "rooms", "ConnectTimeout", "")
        else:
            observer_resilience.set_success(current, "rooms")
            stop.set()
        return True

    async def fake_wait(awaitable, timeout):
        delays.append(timeout)
        if stop.is_set():
            await awaitable
            return None
        awaitable.close()
        raise TimeoutError

    monkeypatch.setattr(retry.observer, "backfill_into_state", fake_backfill)
    monkeypatch.setattr(retry.asyncio, "wait_for", fake_wait)

    asyncio.run(retry.backfill_worker(object(), object(), s, cfg, stop, writer))

    assert calls == 2
    assert delays == [5.0, 3600.0]
    assert s["health"]["rooms"]["rooms"]["status"] == "ok"
    assert writer.dirty == 2
    assert s["metrics"]["unrecoverable_core_gap_events"] == 0
    assert s["metrics"]["unrecoverable_core_gap_messages"] == 0
