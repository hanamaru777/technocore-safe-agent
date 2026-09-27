import json
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal

from flop_agent import close1_candidate_scanner as scanner
from flop_agent import close1_standalone_watch as watch


def _scan(*, reference="224.92", top3="93.99", move="0.040", trade_id="a", side="buy"):
    candidate = scanner.CandidateView(
        room="close1-offers",
        seq=1,
        trade_id=trade_id,
        taker_side=side,
        qty=Decimal("4"),
        px=Decimal("224.92"),
        until=999,
        base_fee=Decimal("8.9968"),
        required_cash=Decimal("908.6768"),
        dynamic_top3_price=Decimal("231.66"),
        dynamic_condition="above",
        move_percent_from_mark=Decimal(move),
        visible_leader_coverage=6,
        visible_leaders=6,
        warning="test",
    )
    leaders = tuple(
        scanner.LeaderView(
            did=f"did:key:z6Mk{'1' * 43}{i}",
            score=Decimal(top3),
            position=Decimal("-42"),
            stable=True,
            reason="stable",
        )
        for i in "123"
    )
    return scanner.CandidateScan(
        sweep=700,
        reference=Decimal(reference),
        reference_age_seconds=10,
        mark=Decimal(reference),
        top3_cutoff=Decimal(top3),
        visible_leaders=leaders,
        verified_offers=1,
        sampled_trade_ids=0,
        rejected_offers=0,
        candidates=(candidate,),
        strategy_gate="ready",
    )


def _state_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(watch.resident, "resident_dir", lambda: tmp_path)


def test_first_success_sends_activation_once(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    sent = []
    now = datetime(2026, 9, 27, 15, 0, tzinfo=UTC)

    first = watch.run_once(fetcher=lambda: _scan(), sender=sent.append, now=now)
    second = watch.run_once(fetcher=lambda: _scan(), sender=sent.append, now=now)

    assert first["sent"] is True
    assert first["reasons"] == ["監視開始"]
    assert second["sent"] is False
    assert len(sent) == 1
    assert "standalone監視" in sent[0]
    assert "取引は未実行" in sent[0]


def test_price_shock_sends(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    sent = []
    now = datetime(2026, 9, 27, 15, 0, tzinfo=UTC)
    watch.run_once(fetcher=lambda: _scan(reference="224.00"), sender=sent.append, now=now)
    sent.clear()

    result = watch.run_once(fetcher=lambda: _scan(reference="226.00"), sender=sent.append, now=now)

    assert result["sent"] is True
    assert "5分価格急変" in result["reasons"]


def test_top3_material_shift_sends(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    sent = []
    now = datetime(2026, 9, 27, 15, 0, tzinfo=UTC)
    watch.run_once(fetcher=lambda: _scan(top3="90"), sender=sent.append, now=now)
    sent.clear()

    result = watch.run_once(fetcher=lambda: _scan(top3="101"), sender=sent.append, now=now)

    assert result["sent"] is True
    assert "TOP3変化" in result["reasons"]


def test_near_candidate_and_material_improvement_send(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    sent = []
    now = datetime(2026, 9, 27, 15, 0, tzinfo=UTC)
    watch.run_once(fetcher=lambda: _scan(move="0.040"), sender=sent.append, now=now)
    sent.clear()

    near = watch.run_once(fetcher=lambda: _scan(move="0.028"), sender=sent.append, now=now)
    assert near["sent"] is True
    assert "勝ち筋候補接近" in near["reasons"]
    sent.clear()

    improved = watch.run_once(fetcher=lambda: _scan(move="0.020", trade_id="b"), sender=sent.append, now=now)
    assert improved["sent"] is True
    assert "勝ち筋候補接近" in improved["reasons"]


def test_send_failure_does_not_advance_activation_baseline(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    now = datetime(2026, 9, 27, 15, 0, tzinfo=UTC)

    failed = watch.run_once(
        fetcher=lambda: _scan(),
        sender=lambda message: (_ for _ in ()).throw(RuntimeError("nope")),
        now=now,
    )
    assert failed["status"] == "send_error"

    sent = []
    retried = watch.run_once(fetcher=lambda: _scan(), sender=sent.append, now=now)
    assert retried["sent"] is True
    assert retried["reasons"] == ["監視開始"]


def test_fetch_failure_is_read_only_state_error(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    result = watch.run_once(
        fetcher=lambda: (_ for _ in ()).throw(ValueError("bad")),
        sender=lambda message: None,
        now=datetime(2026, 9, 27, 15, 0, tzinfo=UTC),
    )
    assert result == {"status": "fetch_error", "sent": False}
    state = json.loads((tmp_path / watch.STATE_FILE).read_text("utf-8"))
    assert state["activated"] is False
    assert state["last_error"] == "fetch:ValueError"


def test_no_signing_or_contest_write_surface():
    source = watch.Path(watch.__file__).read_text("utf-8")
    forbidden = (
        "SIGN_SEED",
        "OCI_VAULT_SECRET_OCID",
        "say-signed",
        "post_message",
        "maker_signature",
        "taker_signature",
    )
    assert all(token not in source for token in forbidden)
