"""Hard wall-clock deadlines for Technocore Observer reads.

HTTPX read timeouts measure inactivity between received chunks, not total request
lifetime. A large retained-ring export can therefore remain in flight for far
longer than the nominal read timeout if bytes keep trickling. On a hot room that
can pin the room worker until the retained prefix has moved past its cursor.

This overlay adds a total wall-clock bound around the existing read-only live and
export functions. It performs no writes, signing, URL following, command
execution, or secret access.
"""
from __future__ import annotations

import asyncio

from . import observer_resilience

LIVE_TOTAL_DEADLINE_SECONDS = 20.0
EXPORT_TOTAL_DEADLINE_SECONDS = 20.0
TOTAL_TIMEOUT_ERROR = "TotalTimeout"

_BASE_READ_ROOM_LIVE = observer_resilience.read_room_live
_BASE_READ_ROOM_EXPORT = observer_resilience.read_room_export
_INSTALLED = False


async def read_room_live(client, room: str, since: int, wait: int):
    try:
        return await asyncio.wait_for(
            _BASE_READ_ROOM_LIVE(client, room, since, wait),
            timeout=LIVE_TOTAL_DEADLINE_SECONDS,
        )
    except TimeoutError:
        return None, None, TOTAL_TIMEOUT_ERROR


async def read_room_export(client, room: str):
    try:
        return await asyncio.wait_for(
            _BASE_READ_ROOM_EXPORT(client, room),
            timeout=EXPORT_TOTAL_DEADLINE_SECONDS,
        )
    except TimeoutError:
        return None, None, TOTAL_TIMEOUT_ERROR


def install() -> None:
    """Install total request deadlines before startup/live workers begin."""
    global _INSTALLED
    if _INSTALLED:
        return
    observer_resilience.read_room_live = read_room_live
    observer_resilience.read_room_export = read_room_export
    _INSTALLED = True
