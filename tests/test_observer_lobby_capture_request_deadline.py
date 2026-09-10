from __future__ import annotations

import pytest

from flop_agent import (
    observer_lobby_capture as capture,
    observer_lobby_capture_request_deadline as deadline,
)


class FakeResponse:
    def __init__(self, chunks, *, status_code=200, headers=None):
        self._chunks = list(chunks)
        self.status_code = status_code
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def raise_for_status(self):
        return None

    def iter_bytes(self):
        yield from self._chunks


class FakeClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def stream(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.response


def test_live_stream_parses_bounded_response():
    response = FakeResponse([b'{"messages":[{"seq":11,"text":"a"}]}'])
    client = FakeClient(response)

    rows, retry = deadline.bounded_fetch_live(client, 10)

    assert retry is None
    assert [row["seq"] for row in rows] == [11]
    method, url, kwargs = client.calls[0]
    assert method == "GET" and url.endswith("/r/lobby")
    assert kwargs["params"]["since"] == 10
    assert kwargs["params"]["wait"] == 0
    assert kwargs["params"]["limit"] == capture.LIVE_LIMIT


def test_trickling_response_hits_total_wall_clock_deadline(monkeypatch):
    response = FakeResponse([b'{"messages":[', b'{"seq":11,"text":"a"}]}'])
    client = FakeClient(response)
    times = iter([0.0, 1.0, deadline.TOTAL_REQUEST_SECONDS + 0.1])
    monkeypatch.setattr(deadline.time, "monotonic", lambda: next(times))

    with pytest.raises(RuntimeError, match="capture_total_timeout"):
        deadline._bounded_get_bytes(
            client,
            "https://technocore.chat/r/lobby",
            params={},
            max_bytes=capture.MAX_EXPORT_BYTES,
        )


def test_response_size_stays_bounded(monkeypatch):
    response = FakeResponse([b"1234", b"5678"])
    client = FakeClient(response)
    monkeypatch.setattr(deadline.time, "monotonic", lambda: 0.0)

    with pytest.raises(RuntimeError, match="capture_response_too_large"):
        deadline._bounded_get_bytes(
            client,
            "https://technocore.chat/r/lobby",
            params={},
            max_bytes=7,
        )


def test_install_patches_only_capture_get_helpers(monkeypatch):
    original_live = capture._fetch_live
    original_export = capture._fetch_export
    monkeypatch.setattr(capture, "_fetch_live", original_live)
    monkeypatch.setattr(capture, "_fetch_export", original_export)
    monkeypatch.setattr(deadline, "_INSTALLED", False)

    deadline.install()
    assert capture._fetch_live is deadline.bounded_fetch_live
    assert capture._fetch_export is deadline.bounded_fetch_export

    deadline.install()
    assert capture._fetch_live is deadline.bounded_fetch_live
    assert capture._fetch_export is deadline.bounded_fetch_export


def test_deadline_overlay_remains_get_only_and_seedless():
    import inspect

    source = inspect.getsource(deadline)
    assert ".post(" not in source
    assert "subprocess" not in source
    assert "SIGN_SEED" not in source
