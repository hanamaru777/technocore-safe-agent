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


def test_watcher_prefers_nearer_basket_over_single(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    base = _scan(move="0.040", trade_id="single")
    legs = (
        scanner.BasketLegView(
            room="close1-offers",
            seq=1,
            trade_id="leg-a",
            maker="did:key:z6MkeTcR7He7sY6imuJguhifiNKrWceKNus5HGuajbAwymdK",
            qty=Decimal("4"),
            px=Decimal("224.00"),
            until=999,
            base_fee=Decimal("8.96"),
            required_cash=Decimal("904.96"),
        ),
        scanner.BasketLegView(
            room="close1-offers",
            seq=2,
            trade_id="leg-b",
            maker="did:key:z6MkeVj5ofGVVYiBgBL2se7GHN7TkgTPP4vPAJpYB8n5bh3G",
            qty=Decimal("4"),
            px=Decimal("224.10"),
            until=999,
            base_fee=Decimal("8.964"),
            required_cash=Decimal("905.364"),
        ),
    )
    basket = scanner.BasketCandidateView(
        taker_side="buy",
        legs=legs,
        qty=Decimal("8"),
        weighted_px=Decimal("224.05"),
        until=999,
        base_fee=Decimal("17.924"),
        required_cash=Decimal("1810.324"),
        dynamic_top3_price=Decimal("229.00"),
        dynamic_condition="above",
        move_percent_from_mark=Decimal("0.020"),
        visible_leader_coverage=6,
        visible_leaders=6,
        warning="test basket",
    )
    scan = replace(base, baskets=(basket,))
    sent = []

    result = watch.run_once(
        fetcher=lambda: scan,
        sender=sent.append,
        now=datetime(2026, 9, 27, 15, 0, tzinfo=UTC),
    )

    assert result["sent"] is True
    assert "BASKET BUY 8" in sent[0]
    assert "legs 2" in sent[0]
    assert "leg-a:4@224.00" in sent[0]
    state = json.loads((tmp_path / watch.STATE_FILE).read_text("utf-8"))
    assert state["last_candidate_trade_id"] == "basket:leg-a,leg-b"
    assert state["last_candidate_move_abs"] == "0.020"


def test_watcher_renders_base_fee_only_flat_target(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    base = _scan(move="0.020", trade_id="single")
    candidate = replace(
        base.candidates[0],
        flat_target_score=Decimal("125"),
        base_fee_flat_exit_price=Decimal("231.25"),
        base_fee_flat_move_percent=Decimal("0.028"),
    )
    scan = replace(base, candidates=(candidate,))
    sent = []

    result = watch.run_once(
        fetcher=lambda: scan,
        sender=sent.append,
        now=datetime(2026, 9, 27, 15, 0, tzinfo=UTC),
    )

    assert result["sent"] is True
    assert "flat +125 POLF" in sent[0]
    assert "SELL >= 231.25" in sent[0]
    assert "entry比 +2.80%" in sent[0]
    assert "clawback未反映" in sent[0]


def test_large_recent_flow_alerts_once_then_requires_material_increase(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    now = datetime(2026, 9, 27, 15, 0, tzinfo=UTC)
    taker = "did:key:z6MktKSLKLKHwEfLbYT4kP1cxSCdaKhCNuvEu9xJnuYb9bLP"

    flow40 = scanner.RecentFlowView(
        taker=taker,
        taker_side="buy",
        qty=Decimal("40"),
        trades=2,
        min_px=Decimal("223.50"),
        max_px=Decimal("223.70"),
        latest_ts="2026-09-27T14:59:00Z",
    )
    sent = []
    first_scan = replace(_scan(move="0.040"), recent_flows=(flow40,))
    first = watch.run_once(fetcher=lambda: first_scan, sender=sent.append, now=now)

    assert first["sent"] is True
    assert "大口フロー" in first["reasons"]
    assert "recent gross taker flow #1: BUY 40 contracts / 2 trades" in sent[-1]
    assert "PnL反映前の早期警戒" in sent[-1]

    sent.clear()
    same = watch.run_once(fetcher=lambda: first_scan, sender=sent.append, now=now)
    assert same["sent"] is False
    assert sent == []

    flow55 = replace(flow40, qty=Decimal("55"), trades=3)
    modest_scan = replace(_scan(move="0.040"), recent_flows=(flow55,))
    modest = watch.run_once(fetcher=lambda: modest_scan, sender=sent.append, now=now)
    assert modest["sent"] is False

    flow60 = replace(flow40, qty=Decimal("60"), trades=3)
    increased_scan = replace(_scan(move="0.040"), recent_flows=(flow60,))
    increased = watch.run_once(fetcher=lambda: increased_scan, sender=sent.append, now=now)
    assert increased["sent"] is True
    assert increased["reasons"] == ["大口フロー"]


def test_multiple_large_flows_are_tracked_independently(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    now = datetime(2026, 9, 27, 15, 0, tzinfo=UTC)
    flow_a = scanner.RecentFlowView(
        taker="did:key:z6MkhofStkaUftV6iqiEL9oYckZjfNBYCrybEQ7sp53mfLKm",
        taker_side="buy",
        qty=Decimal("43.21"),
        trades=1,
        min_px=Decimal("233.58"),
        max_px=Decimal("233.58"),
        latest_ts="2026-09-27T14:59:00Z",
    )
    flow_b = scanner.RecentFlowView(
        taker="did:key:z6MknBwYcpzXkazAuiuhD8pia4Kgw1NynrBq8xNFKnnquwpM",
        taker_side="buy",
        qty=Decimal("43.13"),
        trades=2,
        min_px=Decimal("232.90"),
        max_px=Decimal("233.20"),
        latest_ts="2026-09-27T14:58:30Z",
    )
    scan = replace(_scan(move="0.040"), recent_flows=(flow_a, flow_b))
    sent = []

    first = watch.run_once(fetcher=lambda: scan, sender=sent.append, now=now)

    assert first["sent"] is True
    assert "大口フロー" in first["reasons"]
    assert "gross taker flow #1" in sent[-1]
    assert "gross taker flow #2" in sent[-1]
    state = json.loads((tmp_path / watch.STATE_FILE).read_text("utf-8"))
    assert state["flow_alerted_qty"] == {
        f"{flow_a.taker}:buy": "43.21",
        f"{flow_b.taker}:buy": "43.13",
    }

    sent.clear()
    flow_a_55 = replace(flow_a, qty=Decimal("55.00"))
    flow_b_64 = replace(flow_b, qty=Decimal("64.00"), trades=3)
    changed = replace(_scan(move="0.040"), recent_flows=(flow_a_55, flow_b_64))
    second = watch.run_once(fetcher=lambda: changed, sender=sent.append, now=now)

    assert second["sent"] is True
    assert second["reasons"] == ["大口フロー"]
    state = json.loads((tmp_path / watch.STATE_FILE).read_text("utf-8"))
    # A grew by <20 and keeps its old notified baseline. B grew by >=20 and advances.
    assert state["flow_alerted_qty"][f"{flow_a.taker}:buy"] == "43.21"
    assert state["flow_alerted_qty"][f"{flow_b.taker}:buy"] == "64.00"


def test_large_flow_baseline_resets_after_flow_leaves_window(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    now = datetime(2026, 9, 27, 15, 0, tzinfo=UTC)
    flow = scanner.RecentFlowView(
        taker="did:key:z6MkhofStkaUftV6iqiEL9oYckZjfNBYCrybEQ7sp53mfLKm",
        taker_side="buy",
        qty=Decimal("45"),
        trades=1,
        min_px=Decimal("233.00"),
        max_px=Decimal("233.00"),
        latest_ts="2026-09-27T14:59:00Z",
    )
    sent = []
    watch.run_once(
        fetcher=lambda: replace(_scan(move="0.040"), recent_flows=(flow,)),
        sender=sent.append,
        now=now,
    )
    state = json.loads((tmp_path / watch.STATE_FILE).read_text("utf-8"))
    assert state["flow_alerted_qty"]

    sent.clear()
    watch.run_once(
        fetcher=lambda: replace(_scan(move="0.040"), recent_flows=()),
        sender=sent.append,
        now=now,
    )
    state = json.loads((tmp_path / watch.STATE_FILE).read_text("utf-8"))
    assert state["flow_alerted_qty"] == {}

    sent.clear()
    reappeared = replace(flow, qty=Decimal("41"))
    result = watch.run_once(
        fetcher=lambda: replace(_scan(move="0.040"), recent_flows=(reappeared,)),
        sender=sent.append,
        now=now,
    )
    assert result["sent"] is True
    assert result["reasons"] == ["大口フロー"]


def test_legacy_single_flow_state_migrates_without_duplicate_alert(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    flow = scanner.RecentFlowView(
        taker="did:key:z6MkhofStkaUftV6iqiEL9oYckZjfNBYCrybEQ7sp53mfLKm",
        taker_side="buy",
        qty=Decimal("43.21"),
        trades=1,
        min_px=Decimal("233.58"),
        max_px=Decimal("233.58"),
        latest_ts="2026-09-27T14:59:00Z",
    )
    legacy = watch._default_state()
    legacy.update(
        activated=True,
        last_flow_key=f"{flow.taker}:buy",
        last_flow_qty="43.21",
    )
    (tmp_path / watch.STATE_FILE).write_text(json.dumps(legacy), "utf-8")
    sent = []

    result = watch.run_once(
        fetcher=lambda: replace(_scan(move="0.040"), recent_flows=(flow,)),
        sender=sent.append,
        now=datetime(2026, 9, 27, 15, 0, tzinfo=UTC),
    )

    assert result["sent"] is False
    state = json.loads((tmp_path / watch.STATE_FILE).read_text("utf-8"))
    assert state["flow_alerted_qty"][f"{flow.taker}:buy"] == "43.21"


def test_flow_below_threshold_does_not_alert(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    flow = scanner.RecentFlowView(
        taker="did:key:z6MktKSLKLKHwEfLbYT4kP1cxSCdaKhCNuvEu9xJnuYb9bLP",
        taker_side="buy",
        qty=Decimal("39.99"),
        trades=4,
        min_px=Decimal("223.50"),
        max_px=Decimal("223.90"),
        latest_ts="2026-09-27T14:59:00Z",
    )
    sent = []
    result = watch.run_once(
        fetcher=lambda: replace(_scan(move="0.040"), recent_flows=(flow,)),
        sender=sent.append,
        now=datetime(2026, 9, 27, 15, 0, tzinfo=UTC),
    )

    # First-ever watcher run still emits the normal activation notice, but it
    # must not claim a large-flow alert below the threshold.
    assert result["sent"] is True
    assert result["reasons"] == ["監視開始"]
    assert "大口フロー" not in sent[0]


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
