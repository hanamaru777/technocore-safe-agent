import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime

import pytest

from flop_agent import close1_account_reconciliation as account
from flop_agent import close1_candidate_scanner as scanner_module
from flop_agent import close1_discord_progress as progress
from flop_agent import close1_standalone_watch as watch


OWNER = account.OWNER_DID
OTHER = "did:key:z6MkeTcR7He7sY6imuJguhifiNKrWceKNus5HGuajbAwymdK"


def _state_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(account, "state_path", lambda: tmp_path / account.STATE_FILE)


def _record(
    *,
    sweep=200,
    trade_id="trade-a",
    maker=OWNER,
    countersigner=OTHER,
    side="buy",
    qty="2",
    px="200",
    outcome="settled",
    maker_fee="4",
    taker_fee="4",
    reason="expired",
):
    terms = {
        "id": trade_id,
        "maker": maker,
        "side": side,
        "qty": qty,
        "px": px,
        "taker": countersigner,
        "until": sweep,
        "countersigner": countersigner,
    }
    result = {"id": trade_id, "outcome": outcome}
    if outcome == "settled":
        result.update(maker_fee=maker_fee, taker_fee=taker_fee)
    else:
        result["reason"] = reason
    value = {
        "input": {
            "t": "sweep",
            "n": sweep,
            "ref": "200",
            "close": "2026-09-30T00:00:00Z",
            "owners": 20,
            "trades": [terms],
        },
        "output": {
            "sweep": sweep,
            "reference": "200",
            "close": "2026-09-30T00:00:00Z",
            "minted": [],
            "trades": [result],
            "global_price": "200.00",
        },
    }
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(raw).hexdigest()
    entry = {
        "n": sweep,
        "file": digest,
        "path": f"sweeps/{digest}.json",
        "status": "full",
        "bytes": len(raw),
    }
    return entry, raw


def _index(*entries):
    return json.dumps(
        {"contest": "close-1", "sweeps": list(entries)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _pending(trade_id="trade-a", sweep=200):
    ledger = account.checkpoint_ledger()
    ledger["pending_trades"][trade_id] = {
        "search_start_sweep": sweep,
        "next_search_sweep": sweep,
        "marked_at": "2026-09-30T00:00:00+00:00",
    }
    ledger["pending_trade_ids"] = [trade_id]
    ledger.update(status="own_state_pending", reason="binding_awaiting_archive")
    return ledger


def test_trusted_checkpoint_is_exact_flat_account():
    ledger = account.checkpoint_ledger()

    assert ledger["as_of_sweep"] == 189
    assert ledger["cash"] == "10000"
    assert ledger["lots"] == []
    assert ledger["position"] == "0"
    assert ledger["cumulative_fees"] == "0"
    assert account.scanner_account(ledger) == ("10000", "0")


def test_pending_marker_is_durable_idempotent_and_blocks_scanner(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    first = account.mark_pending(
        "future-trade", search_start_sweep=201, now="2026-09-30T01:00:00+00:00"
    )
    second = account.mark_pending(
        "future-trade", search_start_sweep=202, now="2026-09-30T02:00:00+00:00"
    )

    assert first == second
    assert account.load_ledger()["pending_trades"] == first["pending_trades"]
    with pytest.raises(RuntimeError, match="own_state_unreconciled"):
        account.scanner_account(second)


def test_pending_marker_reuses_original_search_cursor(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    first = account.mark_pending("future-trade", search_start_sweep=201)
    second = account.mark_pending("future-trade", search_start_sweep=202)
    assert second == first


def test_pending_marker_blocks_second_distinct_binding(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    first = account.mark_pending("future-trade", search_start_sweep=201)

    with pytest.raises(RuntimeError, match="pending_binding_inflight"):
        account.mark_pending("second-trade", search_start_sweep=201)

    assert account.load_ledger() == first
    assert account.load_ledger()["pending_trade_ids"] == ["future-trade"]


def test_settled_maker_buy_and_sell_use_exact_fees_and_fifo():
    first_entry, first_raw = _record()
    opened = account.reconcile_records(
        _pending(), archive_tip_sweep=200, records=[(first_entry, first_raw)]
    )

    assert opened["status"] == "reconciled"
    assert opened["cash"] == "9596"
    assert opened["lots"] == [["2", "200"]]
    assert opened["position"] == "2"
    assert opened["cumulative_fees"] == "4"

    second_entry, second_raw = _record(
        sweep=201,
        trade_id="trade-b",
        side="sell",
        qty="2",
        px="220",
        maker_fee="4.4",
        taker_fee="4.4",
    )
    opened["pending_trades"]["trade-b"] = {
        "search_start_sweep": 201,
        "next_search_sweep": 201,
        "marked_at": "2026-09-30T01:00:00+00:00",
    }
    opened["pending_trade_ids"] = ["trade-b"]
    opened.update(status="own_state_pending", reason="binding_awaiting_archive")
    closed = account.reconcile_records(
        opened, archive_tip_sweep=201, records=[(second_entry, second_raw)]
    )

    assert closed["cash"] == "10031.6"
    assert closed["lots"] == []
    assert closed["position"] == "0"
    assert closed["cumulative_fees"] == "8.4"
    assert closed["settled_trade_ids"] == ["trade-a", "trade-b"]


def test_countersigner_uses_inverted_maker_side_and_exact_taker_fee():
    entry, raw = _record(
        maker=OTHER,
        countersigner=OWNER,
        side="sell",
        taker_fee="7.25",
    )
    result = account.reconcile_records(
        _pending(), archive_tip_sweep=200, records=[(entry, raw)]
    )

    assert result["cash"] == "9592.75"
    assert result["lots"] == [["2", "200"]]
    assert result["position"] == "2"
    assert result["cumulative_fees"] == "7.25"


def test_fifo_partial_close_and_flip_matches_frozen_account_transition():
    first_entry, first_raw = _record(qty="3", px="200", maker_fee="6")
    opened = account.reconcile_records(
        _pending(), archive_tip_sweep=200, records=[(first_entry, first_raw)]
    )
    second_entry, second_raw = _record(
        sweep=201,
        trade_id="trade-b",
        side="sell",
        qty="5",
        px="210",
        maker_fee="10.5",
    )
    opened["pending_trades"]["trade-b"] = {
        "search_start_sweep": 201,
        "next_search_sweep": 201,
        "marked_at": "2026-09-30T01:00:00+00:00",
    }
    opened["pending_trade_ids"] = ["trade-b"]
    opened.update(status="own_state_pending", reason="binding_awaiting_archive")

    result = account.reconcile_records(
        opened, archive_tip_sweep=201, records=[(second_entry, second_raw)]
    )

    # 10,000 - 6 - 600 - 10.5 + (3 * 210) - (2 * 210)
    assert result["cash"] == "9593.5"
    assert result["lots"] == [["-2", "210"]]
    assert result["position"] == "-2"
    assert result["cumulative_fees"] == "16.5"


def test_long_partial_then_full_close_preserves_fifo_cash_semantics():
    entry, raw = _record(qty="3", maker_fee="6")
    ledger = account.reconcile_records(
        _pending(), archive_tip_sweep=200, records=[(entry, raw)]
    )
    for sweep, trade_id, qty, px, fee in (
        (201, "trade-b", "1", "210", "2.1"),
        (202, "trade-c", "2", "220", "4.4"),
    ):
        ledger["pending_trades"][trade_id] = {
            "search_start_sweep": sweep,
            "next_search_sweep": sweep,
            "marked_at": "2026-09-30T01:00:00+00:00",
        }
        ledger["pending_trade_ids"] = [trade_id]
        ledger.update(status="own_state_pending", reason="binding_awaiting_archive")
        close_entry, close_raw = _record(
            sweep=sweep,
            trade_id=trade_id,
            side="sell",
            qty=qty,
            px=px,
            maker_fee=fee,
        )
        ledger = account.reconcile_records(
            ledger, archive_tip_sweep=sweep, records=[(close_entry, close_raw)]
        )

    assert ledger["cash"] == "10037.5"
    assert ledger["lots"] == []
    assert ledger["position"] == "0"
    assert ledger["cumulative_fees"] == "12.5"


def test_short_open_partial_and_full_close_preserves_fifo_cash_semantics():
    entry, raw = _record(side="sell", qty="3", maker_fee="6")
    ledger = account.reconcile_records(
        _pending(), archive_tip_sweep=200, records=[(entry, raw)]
    )
    assert ledger["cash"] == "9394"
    assert ledger["lots"] == [["-3", "200"]]

    for sweep, trade_id, qty, px, fee in (
        (201, "trade-b", "1", "190", "1.9"),
        (202, "trade-c", "2", "180", "3.6"),
    ):
        ledger["pending_trades"][trade_id] = {
            "search_start_sweep": sweep,
            "next_search_sweep": sweep,
            "marked_at": "2026-09-30T01:00:00+00:00",
        }
        ledger["pending_trade_ids"] = [trade_id]
        ledger.update(status="own_state_pending", reason="binding_awaiting_archive")
        close_entry, close_raw = _record(
            sweep=sweep,
            trade_id=trade_id,
            side="buy",
            qty=qty,
            px=px,
            maker_fee=fee,
        )
        ledger = account.reconcile_records(
            ledger, archive_tip_sweep=sweep, records=[(close_entry, close_raw)]
        )

    assert ledger["cash"] == "10038.5"
    assert ledger["lots"] == []
    assert ledger["position"] == "0"
    assert ledger["cumulative_fees"] == "11.5"


def test_void_preserves_balances_and_reason():
    entry, raw = _record(outcome="void", reason="named taker mismatch")
    result = account.reconcile_records(
        _pending(), archive_tip_sweep=200, records=[(entry, raw)]
    )

    assert result["status"] == "reconciled"
    assert result["cash"] == "10000"
    assert result["lots"] == []
    assert result["cumulative_fees"] == "0"
    assert result["void_trades"] == {"trade-a": "named taker mismatch"}


def test_hash_mismatch_fails_closed_without_balance_mutation():
    entry, raw = _record()
    before = _pending()
    bad = bytearray(raw)
    bad[-2] ^= 1
    result = account.reconcile_records(
        before, archive_tip_sweep=200, records=[(entry, bytes(bad))]
    )

    assert result["status"] == "own_state_unreconciled"
    assert result["reason"] == "close1_archive_hash_mismatch"
    assert result["cash"] == "10000"
    assert result["lots"] == []
    assert result["pending_trades"] == before["pending_trades"]


def test_found_trade_with_missing_outcome_fails_closed_but_absence_advances_cursor():
    entry, raw = _record()
    value = json.loads(raw)
    value["output"]["trades"] = []
    malformed = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(malformed).hexdigest()
    entry.update(file=digest, path=f"sweeps/{digest}.json", bytes=len(malformed))
    result = account.reconcile_records(
        _pending(), archive_tip_sweep=200, records=[(entry, malformed)]
    )
    assert result["status"] == "own_state_unreconciled"
    assert result["reason"] == "close1_archive_trade_alignment_invalid"

    other_entry, other_raw = _record(
        trade_id="different",
        maker=OTHER,
        countersigner="did:key:z6MkeVj5ofGVVYiBgBL2se7GHN7TkgTPP4vPAJpYB8n5bh3G",
    )
    missing = account.reconcile_records(
        _pending(), archive_tip_sweep=200, records=[(other_entry, other_raw)]
    )
    assert missing["status"] == "own_state_pending"
    assert missing["reason"] == "binding_awaiting_archive"
    assert missing["pending_trades"]["trade-a"]["next_search_sweep"] == 201


def test_found_trade_with_mismatched_output_id_fails_closed():
    entry, raw = _record()
    value = json.loads(raw)
    value["output"]["trades"][0]["id"] = "different"
    malformed = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(malformed).hexdigest()
    entry.update(file=digest, path=f"sweeps/{digest}.json", bytes=len(malformed))

    result = account.reconcile_records(
        _pending(), archive_tip_sweep=200, records=[(entry, malformed)]
    )

    assert result["status"] == "own_state_unreconciled"
    assert result["reason"] == "close1_archive_trade_outcome_missing"
    assert result["cash"] == "10000"


def test_duplicate_trade_occurrence_in_one_sweep_fails_closed():
    entry, raw = _record()
    value = json.loads(raw)
    value["input"]["trades"].append(deepcopy(value["input"]["trades"][0]))
    value["output"]["trades"].append(deepcopy(value["output"]["trades"][0]))
    duplicate = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(duplicate).hexdigest()
    entry.update(file=digest, path=f"sweeps/{digest}.json", bytes=len(duplicate))

    result = account.reconcile_records(
        _pending(), archive_tip_sweep=200, records=[(entry, duplicate)]
    )

    assert result["status"] == "own_state_unreconciled"
    assert result["reason"] == "close1_archive_duplicate_trade_id"
    assert result["cash"] == "10000"


def test_reconciliation_is_idempotent_and_conflicting_duplicate_fails_closed():
    entry, raw = _record()
    first = account.reconcile_records(
        _pending(), archive_tip_sweep=200, records=[(entry, raw)]
    )
    second = account.reconcile_records(
        first, archive_tip_sweep=200, records=[(entry, raw)]
    )
    assert second["status"] == "reconciled"
    assert second["cash"] == first["cash"]
    assert second["settled_trade_ids"] == ["trade-a"]
    assert len(second["source_evidence"]) == 2

    changed_entry, changed_raw = _record(px="201")
    conflicted = account.reconcile_records(
        second, archive_tip_sweep=201, records=[(changed_entry, changed_raw)]
    )
    assert conflicted["status"] == "own_state_unreconciled"
    assert conflicted["reason"] == "close1_archive_trade_evidence_conflict"
    assert conflicted["cash"] == first["cash"]


def test_archive_lag_keeps_pending_and_does_not_fetch_a_sweep(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    account.save_ledger(_pending(sweep=201))
    entry, _ = _record(sweep=200, trade_id="unrelated", maker=OTHER)
    calls = []

    def fetch(url, limit):
        calls.append((url, limit))
        return _index(entry)

    result = account.reconcile_pending(fetcher=fetch)

    assert result["status"] == "own_state_pending"
    assert result["reason"] == "archive_lag"
    assert result["pending_trades"]
    assert result["pending_trades"]["trade-a"]["next_search_sweep"] == 201
    assert calls == [(account.INDEX_URL, account.INDEX_MAX_BYTES)]


def test_unrelated_archive_trade_does_not_change_owner_account():
    entry, raw = _record(maker=OTHER, countersigner=("did:key:z6MkeVj5ofGVVYiBgBL2se7GHN7TkgTPP4vPAJpYB8n5bh3G"))
    result = account.reconcile_records(
        account.checkpoint_ledger(),
        archive_tip_sweep=200,
        records=[(entry, raw)],
    )

    assert result["status"] == "flat_confirmed"
    assert result["cash"] == "10000"
    assert result["settled_trade_ids"] == []
    assert result["as_of_sweep"] == account.CHECKPOINT_SWEEP


def test_pending_trade_is_hash_checked_fetched_and_persisted(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    account.save_ledger(_pending())
    entry, raw = _record()
    calls = []

    def fetch(url, limit):
        calls.append((url, limit))
        if url == account.INDEX_URL:
            return _index(entry)
        assert url == account.ARCHIVE_BASE + entry["path"]
        return raw

    result = account.reconcile_pending(
        fetcher=fetch, reconciled_at="2026-09-30T03:00:00+00:00"
    )

    assert result["status"] == "reconciled"
    assert result["archive_tip_sweep"] == 200
    assert result["last_reconciled_at"] == "2026-09-30T03:00:00+00:00"
    assert result["source_evidence"][-1] == {
        "kind": "official_archive_sweep",
        "sweep": 200,
        "file_sha256": entry["file"],
        "trade_ids": ["trade-a"],
    }
    assert account.load_ledger() == result
    assert len(calls) == 2


def test_pending_trade_absent_then_present_next_sweep_reconciles(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    account.save_ledger(_pending())
    unrelated_entry, unrelated_raw = _record(
        sweep=200,
        trade_id="unrelated",
        maker=OTHER,
        countersigner="did:key:z6MkeVj5ofGVVYiBgBL2se7GHN7TkgTPP4vPAJpYB8n5bh3G",
    )
    settled_entry, settled_raw = _record(sweep=201)
    entries = (unrelated_entry, settled_entry)
    payloads = {
        account.ARCHIVE_BASE + unrelated_entry["path"]: unrelated_raw,
        account.ARCHIVE_BASE + settled_entry["path"]: settled_raw,
    }

    result = account.reconcile_pending(
        fetcher=lambda url, limit: _index(*entries) if url == account.INDEX_URL else payloads[url]
    )

    assert result["status"] == "reconciled"
    assert result["settled_trade_ids"] == ["trade-a"]
    assert result["as_of_sweep"] == 201
    assert [row["sweep"] for row in result["source_evidence"][1:]] == [200, 201]
    assert result["source_evidence"][1]["trade_ids"] == []


def test_bounded_search_cursor_resumes_without_refetching_prior_sweeps(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    account.save_ledger(_pending())
    third = "did:key:z6MkeVj5ofGVVYiBgBL2se7GHN7TkgTPP4vPAJpYB8n5bh3G"
    entries = []
    payloads = {}
    for sweep in range(200, 207):
        kwargs = (
            {"trade_id": "trade-a", "maker": OWNER, "countersigner": OTHER}
            if sweep == 206
            else {"trade_id": f"unrelated-{sweep}", "maker": OTHER, "countersigner": third}
        )
        entry, raw = _record(sweep=sweep, **kwargs)
        entries.append(entry)
        payloads[account.ARCHIVE_BASE + entry["path"]] = raw
    calls = []

    def fetch(url, limit):
        calls.append(url)
        return _index(*entries) if url == account.INDEX_URL else payloads[url]

    first = account.reconcile_pending(fetcher=fetch)
    assert first["status"] == "own_state_pending"
    assert first["reason"] == "bounded_reconciliation_remaining"
    assert first["pending_trades"]["trade-a"]["next_search_sweep"] == 204
    first_calls = list(calls)

    second = account.reconcile_pending(fetcher=fetch)
    assert second["status"] == "reconciled"
    assert second["settled_trade_ids"] == ["trade-a"]
    second_sweep_urls = calls[len(first_calls) + 1 :]
    assert second_sweep_urls == [
        account.ARCHIVE_BASE + entries[index]["path"] for index in (4, 5, 6)
    ]


def test_transient_archive_failure_can_recover_without_binding_retry(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    account.save_ledger(_pending())
    failed = account.reconcile_pending(
        fetcher=lambda url, limit: (_ for _ in ()).throw(OSError("offline"))
    )
    assert failed["status"] == "own_state_unreconciled"
    assert failed["pending_trades"] == _pending()["pending_trades"]

    entry, raw = _record()
    recovered = account.reconcile_pending(
        fetcher=lambda url, limit: _index(entry) if url == account.INDEX_URL else raw
    )
    assert recovered["status"] == "reconciled"
    assert recovered["settled_trade_ids"] == ["trade-a"]


def test_reconciliation_fetch_count_is_bounded_per_run(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    ledger = account.checkpoint_ledger()
    entries = []
    payloads = {}
    for offset in range(account.MAX_PENDING_SWEEPS_PER_RUN + 1):
        sweep = 200 + offset
        trade_id = f"trade-{offset}"
        ledger["pending_trades"][trade_id] = {
            "search_start_sweep": sweep,
            "next_search_sweep": sweep,
            "marked_at": "2026-09-30T00:00:00+00:00",
        }
        entry, raw = _record(sweep=sweep, trade_id=trade_id, qty="1", maker_fee="2")
        entries.append(entry)
        payloads[account.ARCHIVE_BASE + entry["path"]] = raw
    ledger["pending_trade_ids"] = sorted(ledger["pending_trades"])
    ledger.update(status="own_state_pending", reason="binding_awaiting_archive")
    account.save_ledger(ledger)
    calls = []

    def fetch(url, limit):
        calls.append(url)
        return _index(*entries) if url == account.INDEX_URL else payloads[url]

    result = account.reconcile_pending(fetcher=fetch)

    assert result["status"] == "own_state_pending"
    assert result["reason"] == "bounded_reconciliation_remaining"
    assert len(result["pending_trades"]) == 1
    assert len(calls) == 1 + account.MAX_PENDING_SWEEPS_PER_RUN


def test_redacted_candidate_search_sweep_fails_closed(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    account.save_ledger(_pending())
    digest = "a" * 64
    redacted = {
        "n": 200,
        "file": digest,
        "path": f"redacted/{digest}.json",
        "status": "redacted",
        "bytes": 123,
    }

    result = account.reconcile_pending(
        fetcher=lambda url, limit: _index(redacted)
    )

    assert result["status"] == "own_state_unreconciled"
    assert result["reason"] == "close1_archive_relevant_sweep_redacted"


@pytest.mark.parametrize("mapping_name", ["void_trades", "trade_evidence"])
def test_invalid_terminal_mapping_key_loads_fail_closed(monkeypatch, tmp_path, mapping_name):
    _state_dir(monkeypatch, tmp_path)
    ledger = account.checkpoint_ledger()
    ledger[mapping_name]["invalid key!"] = (
        "reason" if mapping_name == "void_trades" else "a" * 64
    )
    account.state_path().write_text(json.dumps(ledger), encoding="utf-8")

    loaded = account.load_ledger()

    assert loaded["status"] == "own_state_unreconciled"
    assert loaded["reason"] == "ledger_invalid"
    assert loaded["cash"] is None


def test_corrupt_ledger_is_not_reset_to_flat(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    account.state_path().write_text("not-json", encoding="utf-8")

    ledger = account.load_ledger()

    assert ledger["status"] == "own_state_unreconciled"
    assert ledger["cash"] is None
    with pytest.raises(RuntimeError, match="own_state_unreconciled"):
        account.scanner_account(ledger)


def test_no_pending_trade_keeps_pretrade_checkpoint_without_archive_fetch(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    result = account.reconcile_pending(
        fetcher=lambda url, limit: (_ for _ in ()).throw(AssertionError("no fetch"))
    )
    assert result == account.checkpoint_ledger()


def test_watcher_flat_checkpoint_uses_exact_10000_and_zero(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    captured = {}
    monkeypatch.setattr(
        watch.close1_candidate_scanner,
        "fetch_candidate_scan",
        lambda **kwargs: captured.update(kwargs) or (_ for _ in ()).throw(ValueError("stop")),
    )

    result = watch.run_once(now=datetime(2026, 9, 30, tzinfo=UTC))

    assert result == {"status": "fetch_error", "sent": False}
    assert captured == {
        "our_did": OWNER,
        "available_cash": "10000",
        "current_position": "0",
    }


def test_watcher_uses_reconciled_cash_and_position(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    ledger = account.checkpoint_ledger()
    ledger.update(
        status="reconciled",
        reason="official_archive_reconciled",
        cash="8765.43",
        lots=[["-3", "220"]],
        position="-3",
        cumulative_fees="11.2",
        settled_trade_ids=["old-trade"],
        trade_evidence={"old-trade": "b" * 64},
    )
    captured = {}
    monkeypatch.setattr(account, "reconcile_pending", lambda **kwargs: ledger)
    monkeypatch.setattr(
        watch.close1_candidate_scanner,
        "fetch_candidate_scan",
        lambda **kwargs: captured.update(kwargs) or (_ for _ in ()).throw(ValueError("stop")),
    )

    result = watch.run_once(
        sender=lambda value: None,
        now=datetime(2026, 9, 30, tzinfo=UTC),
    )

    assert result == {"status": "fetch_error", "sent": False}
    assert captured == {
        "our_did": OWNER,
        "available_cash": "8765.43",
        "current_position": "-3",
    }


@pytest.mark.parametrize("own_status", ["own_state_pending", "own_state_unreconciled"])
def test_watcher_blocks_scanner_for_nonterminal_owner_state(monkeypatch, tmp_path, own_status):
    _state_dir(monkeypatch, tmp_path)
    ledger = _pending()
    ledger["status"] = own_status
    called = False

    monkeypatch.setattr(account, "reconcile_pending", lambda **kwargs: ledger)

    def scanner(**kwargs):
        nonlocal called
        called = True
        raise AssertionError("scanner must remain blocked")

    monkeypatch.setattr(watch.close1_candidate_scanner, "fetch_candidate_scan", scanner)
    result = watch.run_once(now=datetime(2026, 9, 30, tzinfo=UTC))

    assert result == {
        "status": "own_state_unreconciled",
        "own_state_status": own_status,
        "sent": False,
    }
    assert called is False


def test_discord_progress_scanner_uses_reconciled_owner_state(monkeypatch):
    ledger = account.checkpoint_ledger()
    ledger.update(
        status="reconciled",
        reason="official_archive_reconciled",
        cash="9100",
        lots=[["4", "200"]],
        position="4",
        cumulative_fees="8",
        settled_trade_ids=["old-trade"],
        trade_evidence={"old-trade": "c" * 64},
    )
    captured = {}
    monkeypatch.setattr(account, "reconcile_pending", lambda **kwargs: ledger)
    monkeypatch.setattr(
        scanner_module,
        "fetch_candidate_scan",
        lambda **kwargs: captured.update(kwargs) or "scan",
    )

    assert progress._candidate_fetch() == "scan"
    assert captured == {
        "our_did": OWNER,
        "available_cash": "9100",
        "current_position": "4",
    }


def test_discord_progress_scanner_blocks_pending_owner_state(monkeypatch):
    monkeypatch.setattr(account, "reconcile_pending", lambda **kwargs: _pending())
    called = False

    def scanner(**kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(scanner_module, "fetch_candidate_scan", scanner)
    with pytest.raises(RuntimeError, match="own_state_unreconciled"):
        progress._candidate_fetch()
    assert called is False


def test_owner_ledger_is_separate_from_alert_state():
    assert account.STATE_FILE != watch.STATE_FILE


def test_reconciliation_has_no_signing_or_write_surface():
    source = account.Path(account.__file__).read_text("utf-8")
    forbidden = (
        "SIGN_SEED",
        "OCI_VAULT_SECRET_OCID",
        "post_signed",
        "post_message",
        "maker_signature",
        "taker_signature",
        "Capture",
        "sqlite",
    )
    assert all(token not in source for token in forbidden)


def test_shared_state_path(monkeypatch, tmp_path):
    monkeypatch.setattr(account.core, "STATE", tmp_path)
    assert account.state_path() == tmp_path / "close1" / account.STATE_FILE


def test_shared_write_permissions_and_ownership(monkeypatch, tmp_path):
    import os
    import stat
    _state_dir(monkeypatch, tmp_path)
    ledger = account.checkpoint_ledger()
    account.save_ledger(ledger)
    parent = account.state_path().parent.stat()
    account.mark_pending("shared-trade", search_start_sweep=201)
    after = account.state_path().stat()
    assert account.load_ledger()["pending_trade_ids"] == ["shared-trade"]
    if os.name == "posix":
        assert stat.S_IMODE(after.st_mode) == 0o660
        assert after.st_gid == parent.st_gid


def test_shared_ledger_packaging():
    from pathlib import Path
    root = Path("packaging/oracle")
    script = (root / "prepare-signer.sh").read_text("utf-8")
    assert 'close1=$state/close1' in script
    assert 'legacy=$state/observer/close1-own-account.json' in script
    assert '[[ -e $legacy && -e $shared ]]' in script
    assert script.index('both legacy and dedicated Close Call') < script.index('mv -n -- "$legacy" "$shared"')
    assert 'install -d -o technocore -g technocore-autopilot -m 2770 "$close1"' in script
    assert 'chown technocore:technocore-autopilot "$shared"' in script
    assert 'chmod 0660 "$shared"' in script
    assert 'runuser -u technocore -- env FLOP_STATE_DIR="$state"' in script
    assert 'save_ledger(checkpoint_ledger())' in script
    assert '[[ -L $ledger || ( -e $ledger && ! -f $ledger ) ]]' in script
    assert 'stat -c %h' in script
    unit = (root / "technocore-safe-agent-signer.service").read_text("utf-8")
    paths = next(line for line in unit.splitlines() if line.startswith("ReadWritePaths=")).split("=", 1)[1].split()
    assert paths == ["/var/lib/technocore-safe-agent/" + name for name in
                     ("autopilot", "signer", "nonces.json", "activities.jsonl", "close1")]
    watcher = (root / "technocore-safe-agent-close1-standalone-watch.service").read_text("utf-8")
    assert "ReadWritePaths=/var/lib/technocore-safe-agent/observer /var/lib/technocore-safe-agent/close1" in watcher


@pytest.mark.parametrize("existing", ["legacy", "shared", "both", "neither"])
def test_prepare_shared_ledger_migration(tmp_path, existing):
    import os
    import shutil
    import subprocess
    from pathlib import Path
    if os.name != "posix":
        pytest.skip("migration filesystem behavior requires POSIX")
    bash = shutil.which("bash")
    if not bash or not Path(bash).exists():
        pytest.skip("bash unavailable")
    root = tmp_path / "state"
    (root / "observer").mkdir(parents=True)
    (root / "close1").mkdir()
    legacy = root / "observer" / account.STATE_FILE
    shared = root / "close1" / account.STATE_FILE
    if existing in ("legacy", "both"):
        legacy.write_bytes(b'legacy-ledger-evidence')
    if existing in ("shared", "both"):
        shared.write_bytes(b'dedicated-ledger-evidence')
    source = Path("packaging/oracle/prepare-signer.sh").read_text("utf-8")
    block = source.split('close1=$state/close1', 1)[1].split('systemctl daemon-reload', 1)[0]
    # Only the migration block runs, in tmp_path. Stub privileged ownership
    # commands and initial checkpoint creation; verify their real form statically.
    harness = tmp_path / "migration.sh"
    harness.write_text('set -euo pipefail\nstate=$1\napp=$2\ninstall() { mkdir -p -- "${@: -1}"; }\nchown() { :; }\nchmod() { :; }\nrunuser() { printf \'initial-checkpoint\' > "$shared"; }\nclose1=$state/close1\n' + block, encoding="utf-8", newline="\n")
    shell_root = root.as_posix()
    result = subprocess.run([bash, str(harness), shell_root, tmp_path.as_posix()], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if existing == "both":
        assert result.returncode != 0
        assert legacy.read_bytes() == b"legacy-ledger-evidence"
        assert shared.read_bytes() == b"dedicated-ledger-evidence"
    else:
        assert result.returncode == 0, result.stderr
        assert not legacy.exists()
        expected = {"legacy": b"legacy-ledger-evidence", "shared": b"dedicated-ledger-evidence", "neither": b"initial-checkpoint"}[existing]
        assert shared.read_bytes() == expected
        # Re-running preparation must preserve the ledger bytes.
        again = subprocess.run([bash, str(harness), shell_root, tmp_path.as_posix()], capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert again.returncode == 0, again.stderr
        assert shared.read_bytes() == expected


def test_batch_pending_helper_allows_exact_batch_without_weakening_single_guard(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    allowed = ["batch-a", "batch-b"]
    first = account.mark_pending_batch_leg(
        "batch-a", search_start_sweep=201, allowed_trade_ids=allowed,
    )
    second = account.mark_pending_batch_leg(
        "batch-b", search_start_sweep=201, allowed_trade_ids=allowed,
    )
    assert first["pending_trade_ids"] == ["batch-a"]
    assert second["pending_trade_ids"] == ["batch-a", "batch-b"]
    with pytest.raises(RuntimeError, match="pending_binding_inflight"):
        account.mark_pending("outside", search_start_sweep=201)


def test_batch_pending_helper_rejects_binding_outside_exact_batch(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    original = account.mark_pending("outside", search_start_sweep=201)
    with pytest.raises(RuntimeError, match="pending_binding_outside_batch"):
        account.mark_pending_batch_leg(
            "batch-a", search_start_sweep=201,
            allowed_trade_ids=["batch-a", "batch-b"],
        )
    assert account.load_ledger() == original
