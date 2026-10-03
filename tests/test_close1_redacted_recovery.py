import hashlib
import json

from flop_agent import close1_account_reconciliation as account
from flop_agent import close1_redacted_recovery as recovery


OWNER = account.OWNER_DID
MAKER = "did:key:z6MkoKH69MkGYQqMMoMLaQjcRbqyqs7w9TuaPCtuR3aJTKwM"
OTHER = "did:key:z6MkeTcR7He7sY6imuJguhifiNKrWceKNus5HGuajbAwymdK"


def _state_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(account, "state_path", lambda: tmp_path / account.STATE_FILE)


def _pending(trade_id="mm-close1-157-b82473", sweep=2382):
    ledger = account.checkpoint_ledger()
    ledger["pending_trades"][trade_id] = {
        "search_start_sweep": sweep,
        "next_search_sweep": sweep,
        "marked_at": "2026-10-03T18:27:11.202728+00:00",
    }
    ledger["pending_trade_ids"] = [trade_id]
    ledger.update(status="own_state_unreconciled", reason="close1_archive_relevant_sweep_redacted")
    return ledger


def _redacted_record(
    *,
    trade_id="mm-close1-157-b82473",
    sweep=2382,
    px="234.56",
    qty="1",
    taker_fee="2.3456",
    outcome="settled",
):
    terms = {
        "countersigner": OWNER,
        "id": trade_id,
        "maker": MAKER,
        "px": px,
        "qty": qty,
        "side": "buy",
        "taker": "any",
        "until": sweep,
    }
    result = {"id": trade_id, "outcome": outcome}
    if outcome == "settled":
        result.update(maker_fee=taker_fee, taker_fee=taker_fee)
    else:
        result["reason"] = "expired"
    duplicate_terms = {**terms, "countersigner": OTHER}
    duplicate_result = {"id": trade_id, "outcome": "void", "reason": "settled"}
    value = {
        "input": {
            "t": "sweep",
            "n": sweep,
            "ref": "234.57",
            "close": "234.33",
            "owners": 18028908,
            "trades": [{"redacted": True}, terms, duplicate_terms],
        },
        "output": {
            "sweep": sweep,
            "reference": "234.57",
            "close": "234.33",
            "minted": [],
            "trades": [{"redacted": True}, result, duplicate_result],
            "global_price": "234.33",
        },
    }
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    full_hash = "f" * 64
    redacted_hash = hashlib.sha256(raw).hexdigest()
    entry = {
        "n": sweep,
        "file": full_hash,
        "path": f"redacted/{full_hash}.json",
        "status": "redacted",
        "bytes": len(raw),
        "redacted": 1,
        "sha256": redacted_hash,
    }
    index = json.dumps(
        {"contest": "close-1", "sweeps": [entry]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return entry, raw, index


def test_live_shape_redacted_settlement_recovers_exact_short(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    account.save_ledger(_pending())
    entry, raw, index = _redacted_record()

    def fetch(url, limit):
        return index if url == account.INDEX_URL else raw

    result = recovery.recover_pending_redacted(
        fetcher=fetch,
        reconciled_at="2026-10-04T00:00:00+00:00",
    )

    assert result["status"] == "reconciled"
    assert result["reason"] == "official_redacted_archive_reconciled"
    assert result["cash"] == "9763.0944"
    assert result["lots"] == [["-1", "234.56"]]
    assert result["position"] == "-1"
    assert result["cumulative_fees"] == "2.3456"
    assert result["settled_trade_ids"] == ["mm-close1-157-b82473"]
    assert result["pending_trade_ids"] == []
    assert result["source_evidence"][-1]["sweep"] == 2382
    assert result["source_evidence"][-1]["file_sha256"] == entry["sha256"]
    assert account.load_ledger() == result


def test_redacted_pending_absence_fails_closed_without_cursor_advance(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    before = _pending()
    account.save_ledger(before)
    entry, raw, index = _redacted_record(trade_id="different-trade")

    result = recovery.recover_pending_redacted(
        fetcher=lambda url, limit: index if url == account.INDEX_URL else raw
    )

    assert result["status"] == "own_state_unreconciled"
    assert result["reason"] == "close1_redacted_pending_trade_not_visible"
    assert result["cash"] == "10000"
    assert result["position"] == "0"
    assert result["pending_trades"] == before["pending_trades"]


def test_redacted_blob_hash_mismatch_fails_closed(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    account.save_ledger(_pending())
    entry, raw, index = _redacted_record()
    bad = bytearray(raw)
    bad[-2] ^= 1

    result = recovery.recover_pending_redacted(
        fetcher=lambda url, limit: index if url == account.INDEX_URL else bytes(bad)
    )

    assert result["status"] == "own_state_unreconciled"
    assert result["reason"] == "close1_redacted_archive_hash_mismatch"
    assert result["cash"] == "10000"
    assert result["pending_trade_ids"] == ["mm-close1-157-b82473"]


def test_untracked_visible_owner_trade_fails_closed(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    account.save_ledger(_pending())
    entry, raw, _ = _redacted_record()
    value = json.loads(raw)
    unknown = {
        "countersigner": OWNER,
        "id": "unknown-owner-trade",
        "maker": MAKER,
        "px": "234.50",
        "qty": "1",
        "side": "buy",
        "taker": "any",
        "until": 2382,
    }
    value["input"]["trades"].append(unknown)
    value["output"]["trades"].append(
        {
            "id": "unknown-owner-trade",
            "outcome": "settled",
            "maker_fee": "2.345",
            "taker_fee": "2.345",
        }
    )
    changed = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    entry["bytes"] = len(changed)
    entry["sha256"] = hashlib.sha256(changed).hexdigest()
    index = json.dumps(
        {"contest": "close-1", "sweeps": [entry]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    result = recovery.recover_pending_redacted(
        fetcher=lambda url, limit: index if url == account.INDEX_URL else changed
    )

    assert result["status"] == "own_state_unreconciled"
    assert result["reason"] == "close1_redacted_untracked_owner_trade"
    assert result["cash"] == "10000"


def test_no_pending_is_noop_and_does_not_fetch(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    ledger = account.checkpoint_ledger()
    account.save_ledger(ledger)

    result = recovery.recover_pending_redacted(
        fetcher=lambda url, limit: (_ for _ in ()).throw(AssertionError("no fetch"))
    )

    assert result == ledger
