"""Retired Close Call Discord compatibility surface.

The Close Call campaign ended on 2026-10-04. Generic Discord control still
imports this module for the historical ``/close1`` command and background
worker. Keep those call sites safe and silent until a broader Discord-control
cleanup removes them completely.

No Discord posts happen here. The scanner helper remains only because account
reconciliation regression tests use the same read-only owner-state bridge.
"""
from __future__ import annotations

from . import close1_account_reconciliation, close1_candidate_scanner

POLL_INTERVAL_SECONDS = 300
OWNER_DID = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"

_RETIRED_STATUS = (
    "✅ Close Callは終了済みです。\n"
    "定期通知は停止しました。履歴はGitHub #667 / #669を参照してください。"
)


def _candidate_fetch() -> close1_candidate_scanner.CandidateScan:
    """Retain the read-only reconciled-account bridge; never notify Discord."""

    ledger = close1_account_reconciliation.reconcile_pending(owner_did=OWNER_DID)
    available_cash, current_position = close1_account_reconciliation.scanner_account(ledger)
    return close1_candidate_scanner.fetch_candidate_scan(
        our_did=OWNER_DID,
        available_cash=available_cash,
        current_position=current_position,
    )


def status_message(*_args, **_kwargs) -> str:
    """Return a compact terminal status for the historical slash command."""

    return _RETIRED_STATUS


def periodic_notices(*_args, **_kwargs) -> list[str]:
    """Keep the compatibility worker permanently silent after campaign end."""

    return []
