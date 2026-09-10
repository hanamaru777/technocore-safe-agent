"""Bound optional tclk parser work so it cannot starve core Observer rooms.

Production Issue #57 evidence showed the main Resident event loop idle while a
synchronous ``node tools/tclk_decode.mjs`` child consumed CPU.  ``tclk-offers`` is
an optional secondary lane, so one burst of parser-heavy frames must never pin the
same loop that drains protected lobby/events continuity.

This overlay preserves the pinned official parser for admitted frames but admits
at most one parser invocation per bounded interval.  Excess optional frames fail
closed (not accepted/presented) rather than delaying core read-side progress.
There are no Technocore writes, signing calls, URL following, or secret reads.
"""
from __future__ import annotations

import threading
import time

from . import tclk_watch

MIN_PARSE_INTERVAL_SECONDS = 15.0
_BASE_OFFICIAL_OFFER = tclk_watch.official_offer
_LOCK = threading.Lock()
_NEXT_PARSE_AT = 0.0
_INSTALLED = False


def _candidate(text: object) -> bool:
    return bool(
        isinstance(text, str)
        and text.startswith(tclk_watch.TCLK_PREFIX)
        and len(text) <= tclk_watch.MAX_FRAME_CHARS
        and all(0x20 <= ord(char) <= 0x7E for char in text)
    )


def bounded_official_offer(text: object):
    """Admit one optional parser call per interval; shed the rest fail-closed."""
    global _NEXT_PARSE_AT

    # Preserve the base parser's cheap validation semantics without consuming an
    # admission slot for obviously non-candidate input.
    if not _candidate(text):
        return _BASE_OFFICIAL_OFFER(text)

    now = time.monotonic()
    with _LOCK:
        if now < _NEXT_PARSE_AT:
            return None
        # Reserve the next slot before invoking Node.  Even a parser timeout or
        # expensive malformed frame therefore cannot trigger an immediate burst of
        # additional blocking subprocesses from the same 200-message room slice.
        _NEXT_PARSE_AT = now + MIN_PARSE_INTERVAL_SECONDS

    return _BASE_OFFICIAL_OFFER(text)


def install() -> None:
    """Patch only the optional tclk decoder admission point exactly once."""
    global _INSTALLED
    if _INSTALLED:
        return
    tclk_watch.official_offer = bounded_official_offer
    _INSTALLED = True
