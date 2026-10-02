import json
from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace

from flop_agent import close1_candidate_scanner as scanner
from flop_agent import close1_standalone_watch as watch


def candidate(i, *, qty="4", flat="0.20"):
    return scanner.CandidateView(
        room="close1-offers", seq=i, trade_id=f"c{i}", taker_side="buy",
        qty=Decimal(qty), px=Decimal("225"), until=9999,
        base_fee=Decimal("9"), required_cash=Decimal("909"),
        dynamic_top3_price=None, dynamic_condition=None, move_percent_from_mark=None,
        visible_leader_coverage=3, visible_leaders=3, warning="test",
        maker=f"maker-{i}", base_fee_flat_move_percent=Decimal(flat),
    )


def basket(i, *, qty="10"):
    leg = SimpleNamespace(trade_id=f"b{i}-leg")
    return SimpleNamespace(
        taker_side="sell", legs=(leg,), qty=Decimal(qty),
        dynamic_victory_move_percent=None, move_percent_from_mark=None,
        base_fee_flat_move_percent=Decimal("0.30"),
    )

def scan(*, candidates=(), baskets=()):
    leaders = tuple(
        scanner.LeaderView(f"leader-{i}", Decimal("100"), Decimal("0"), True, "stable")
        for i in range(3)
    )
    return scanner.CandidateScan(
        sweep=100, reference=Decimal("225"), reference_age_seconds=5,
        mark=Decimal("225"), top3_cutoff=Decimal("100"), visible_leaders=leaders,
        verified_offers=len(candidates), sampled_trade_ids=0, rejected_offers=0,
        candidates=tuple(candidates), baskets=tuple(baskets), strategy_gate="ready",
    )


def plan(move="0.14"):
    return SimpleNamespace(
        status="PATH", total_path_move_percent=Decimal(move),
        stage1_close_price=Decimal("250"), stage2_side="sell",
        stage2_max_affordable_qty=Decimal("40"),
        dynamic_victory_price=Decimal("230"),
        dynamic_victory_condition="below",
    )


def test_two_stage_selection_is_bounded_and_balanced():
    singles = [candidate(i, qty=str(i + 1), flat="0.50") for i in range(30)]
    singles[0] = candidate(0, qty="1", flat="0.001")
    baskets = [basket(i, qty=str(50 - i)) for i in range(3)]
    selected = watch._two_stage_candidates(scan(candidates=singles, baskets=baskets))
    assert len(selected) == watch.TWO_STAGE_MAX_EVALS
    keys = [watch._opportunity_key(kind, item) for kind, item in selected]
    assert all(f"basket:b{i}-leg" in keys for i in range(3))
    assert "single:c29" in keys
    assert "single:c0" in keys


def test_two_stage_path_uses_minimum_total_move(monkeypatch):
    current = scan(candidates=[candidate(1), candidate(2), candidate(3)])
    moves = {"c1": "0.14", "c2": "0.11", "c3": "0.13"}
    monkeypatch.setattr(
        watch.close1_two_stage_planner,
        "plan_two_stage_victory",
        lambda c, **_: plan(moves[c.trade_id]),
    )
    best = watch._best_two_stage_path(current)
    assert best is not None
    assert best[1].trade_id == "c2"
    assert best[2].total_path_move_percent == Decimal("0.11")


def test_two_stage_path_is_initial_flat_only(monkeypatch):
    current = scan(candidates=[candidate(1)])
    monkeypatch.setattr(
        watch.close1_two_stage_planner,        "plan_two_stage_victory",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("called")),
    )
    assert watch._best_two_stage_path(
        current, starting_cash="10001", current_position="0"
    ) is None
    assert watch._best_two_stage_path(
        current, starting_cash="10000", current_position="1"
    ) is None


def test_two_stage_no_path_fails_closed(monkeypatch):
    current = scan(candidates=[candidate(1)])
    no = SimpleNamespace(status="NO_PATH", total_path_move_percent=None)
    monkeypatch.setattr(
        watch.close1_two_stage_planner,
        "plan_two_stage_victory",
        lambda *a, **k: no,
    )
    assert watch._best_two_stage_path(current) is None


def test_two_stage_signal_thresholds_and_critical_band():
    c = candidate(1)
    assert watch._two_stage_signal(("single", c, plan("0.151")), {}) is False
    assert watch._two_stage_signal(("single", c, plan("0.150")), {}) is True
    state = {
        "last_two_stage_alert_key": "single:c1",        "last_two_stage_alert_move_abs": "0.14",
    }
    assert watch._two_stage_signal(("single", c, plan("0.13")), state) is False
    assert watch._two_stage_signal(("single", c, plan("0.119")), state) is True
    critical = {
        "last_two_stage_alert_key": "single:c1",
        "last_two_stage_alert_move_abs": "0.11",
    }
    assert watch._two_stage_signal(("single", c, plan("0.099")), critical) is True


def test_two_stage_key_change_requires_real_improvement():
    old = {
        "last_two_stage_alert_key": "single:c1",
        "last_two_stage_alert_move_abs": "0.14",
    }
    c2 = candidate(2)
    assert watch._two_stage_signal(("single", c2, plan("0.139")), old) is False
    assert watch._two_stage_signal(("single", c2, plan("0.134")), old) is True


def test_run_once_persists_two_stage_telemetry_and_dedupes(monkeypatch, tmp_path):
    monkeypatch.setattr(watch.resident, "resident_dir", lambda: tmp_path)
    monkeypatch.setattr(watch.close1_account_reconciliation, "state_path", lambda: tmp_path / "close1-own-account.json")
    current = scan(candidates=[candidate(1)])
    holder = {"plan": plan("0.14")}
    monkeypatch.setattr(
        watch,
        "_best_two_stage_path",
        lambda *a, **k: ("single", current.candidates[0], holder["plan"]),
    )
    sent = []
    now = datetime(2026, 10, 1, 0, 0, tzinfo=UTC)
    first = watch.run_once(
        fetcher=lambda: current, sender=sent.append, now=now, two_stage_enabled=True
    )
    assert "2段階勝ち筋接近" in first["reasons"]
    assert "2段階(base-fee only)" in sent[-1]
    assert "取引承認ではありません" in sent[-1]
    saved = json.loads(watch.state_path().read_text("utf-8"))
    assert saved["last_two_stage_key"] == "single:c1"
    assert saved["last_two_stage_move_abs"] == "0.14"
    assert saved["last_two_stage_alert_move_abs"] == "0.14"

    sent.clear()
    holder["plan"] = plan("0.13")
    second = watch.run_once(
        fetcher=lambda: current, sender=sent.append, now=now, two_stage_enabled=True
    )
    assert "2段階勝ち筋接近" not in second["reasons"]

    holder["plan"] = plan("0.115")
    third = watch.run_once(
        fetcher=lambda: current, sender=sent.append, now=now, two_stage_enabled=True
    )
    assert "2段階勝ち筋接近" in third["reasons"]


def test_two_stage_baseline_resets_outside_watch_band(monkeypatch, tmp_path):
    monkeypatch.setattr(watch.resident, "resident_dir", lambda: tmp_path)
    monkeypatch.setattr(watch.close1_account_reconciliation, "state_path", lambda: tmp_path / "close1-own-account.json")
    current = scan(candidates=[candidate(1)])
    holder = {"plan": plan("0.14")}
    monkeypatch.setattr(
        watch,
        "_best_two_stage_path",
        lambda *a, **k: ("single", current.candidates[0], holder["plan"]),
    )
    now = datetime(2026, 10, 1, 0, 0, tzinfo=UTC)
    watch.run_once(
        fetcher=lambda: current, sender=lambda _: None, now=now, two_stage_enabled=True
    )
    holder["plan"] = plan("0.16")
    watch.run_once(
        fetcher=lambda: current, sender=lambda _: None, now=now, two_stage_enabled=True
    )
    saved = json.loads(watch.state_path().read_text("utf-8"))
    assert saved["last_two_stage_alert_move_abs"] is None

    holder["plan"] = plan("0.149")
    result = watch.run_once(
        fetcher=lambda: current, sender=lambda _: None, now=now, two_stage_enabled=True
    )
    assert "2段階勝ち筋接近" in result["reasons"]


def test_missing_two_stage_path_preserves_alert_baseline():
    state = watch._default_state()
    state["activated"] = True
    state["last_two_stage_alert_key"] = "single:c1"
    state["last_two_stage_alert_move_abs"] = "0.14"
    watch._remember_scan(
        state,
        scan(candidates=[candidate(1)]),
        datetime(2026, 10, 1, 0, 0, tzinfo=UTC),
        [],
        None,
    )
    assert state["last_two_stage_alert_key"] == "single:c1"
    assert state["last_two_stage_alert_move_abs"] == "0.14"
