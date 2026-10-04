"""Retired Close Call Discord compatibility surface.

The Close Call campaign ended on 2026-10-04. Generic Discord control still
imports this module for the historical ``/close1`` command and background
worker. Keep those call sites safe and silent until a broader Discord-control
cleanup removes them completely.

No network reads, state writes, signing, or Discord posts happen here.
"""
from __future__ import annotations

POLL_INTERVAL_SECONDS = 300

_RETIRED_STATUS = (
    "✅ Close Callは終了済みです。\n"
    "定期通知は停止しました。履歴はGitHub #667 / #669を参照してください。"
)


def status_message(*_args, **_kwargs) -> str:
    """Return a compact terminal status for the historical slash command."""

    return _RETIRED_STATUS


def periodic_notices(*_args, **_kwargs) -> list[str]:
    """Keep the compatibility worker permanently silent after campaign end."""

    return []
