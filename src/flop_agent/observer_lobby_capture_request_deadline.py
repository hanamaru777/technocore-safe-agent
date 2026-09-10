"""Bound standalone lobby capture GETs by total wall-clock time.

The capture lane already uses httpx read timeouts, but those are inactivity timers.
A response that trickles bytes can therefore keep the standalone capture request
alive for minutes while its persisted cursor stops advancing. Production Issue
#57 evidence showed exactly that shape: capture age exceeded 200 seconds while
``last_error`` was still empty, followed later by ``ReadTimeout``.

This overlay keeps the existing GET-only capture protocol and byte limits, but
streams response bytes and aborts once one request exceeds a bounded wall-clock
budget. It introduces no Technocore writes, signing, subprocesses, URL following,
or secret access.
"""
from __future__ import annotations

import json
import time
from urllib.parse import quote

from . import core, observer_lobby_capture as capture

TOTAL_REQUEST_SECONDS = 8.0
_INSTALLED = False


def _bounded_get_bytes(client, url: str, *, params: dict | None, max_bytes: int):
    started = time.monotonic()
    chunks: list[bytes] = []
    size = 0

    with client.stream("GET", url, params=params, timeout=capture._timeout()) as response:
        if response.status_code == 429:
            return response, b""
        response.raise_for_status()
        for chunk in response.iter_bytes():
            size += len(chunk)
            if size > max_bytes:
                raise RuntimeError("capture_response_too_large")
            if time.monotonic() - started > TOTAL_REQUEST_SECONDS:
                raise RuntimeError("capture_total_timeout")
            chunks.append(chunk)

        if time.monotonic() - started > TOTAL_REQUEST_SECONDS:
            raise RuntimeError("capture_total_timeout")

    return response, b"".join(chunks)


def bounded_fetch_live(client, cursor: int) -> tuple[list[dict], float | None]:
    response, body = _bounded_get_bytes(
        client,
        f"{core.BASE_URL}/r/{quote(capture.ROOM, safe='')}",
        params={
            "format": "json",
            "since": cursor,
            "wait": 0,
            "limit": capture.LIVE_LIMIT,
        },
        max_bytes=capture.MAX_EXPORT_BYTES,
    )
    if response.status_code == 429:
        return [], capture._retry_after(response)
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("capture_invalid_live") from error
    return capture._valid_rows(payload), None


def bounded_fetch_export(client) -> tuple[list[dict], float | None]:
    response, body = _bounded_get_bytes(
        client,
        f"{core.BASE_URL}/r/{quote(capture.ROOM, safe='')}/export",
        params=None,
        max_bytes=capture.MAX_EXPORT_BYTES,
    )
    if response.status_code == 429:
        return [], capture._retry_after(response)
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError("capture_invalid_export") from error

    rows: list[dict] = []
    for raw in text.splitlines():
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as error:
            raise RuntimeError("capture_invalid_export") from error
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("seq"), int)
            or not isinstance(item.get("text"), str)
        ):
            raise RuntimeError("capture_invalid_export")
        rows.append(item)
    return sorted(rows, key=lambda item: item["seq"]), None


def install() -> None:
    """Patch only the standalone capture GET helpers exactly once."""
    global _INSTALLED
    if _INSTALLED:
        return
    capture._fetch_live = bounded_fetch_live
    capture._fetch_export = bounded_fetch_export
    _INSTALLED = True
