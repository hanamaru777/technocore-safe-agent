from datetime import UTC, datetime, timedelta
from decimal import Decimal

from flop_agent import close1_candidate_scanner, close1_discord_progress, close_call, discord_control


DID_A = "did:key:z6MkeU5vNqNxwtmAsf8ZyeLGG5KyUSbT94cTXomQpQXZp9Ta"
DID_B = "did:key:z6MksG1pdiesyoNmqzkh7Dqxu89GjejSR9bo34p7qocuB2i9"
NOW = datetime(2026, 9, 26, 4, 0, tzinfo=UTC)


def snapshot(*, sweep=192, age=10, cutoff="96.00", leader="104.00"):
    return close_call.LiveSnapshot(
        sweep=sweep,
        reference=Decimal("224.55"),
        reference_age_seconds=age,
        reference_fresh_for_strategy=age <= close_call.SAFE_MAX_REFERENCE_AGE_SECONDS,
        owners=950000,
        pnl_top=((DID_A, Decimal(leader)), (DID_B, Decimal("98.00")), (DID_A, Decimal(cutoff))),
        top3_cutoff=Decimal(cutoff),
        longs=26000,
        shorts=27000,
        open_notional=Decimal("1047000.00"),
    )


def candidate_scan(*, move="0.015", side="buy", gate="ready"):
    leaders = tuple(
        close1_candidate_scanner.LeaderView(
            did=did,
            score=Decimal("210"),
            position=Decimal("-42"),
            stable=True,
            reason="stable",
        )
        for did in (DID_A, DID_B, DID_A)
    )
    candidate = close1_candidate_scanner.CandidateView(
        room="close1-offers",
        seq=123,
        trade_id="watch-1",
        taker_side=side,
        qty=Decimal("4"),
        px=Decimal("227.40"),
        until=205,
        base_fee=Decimal("9.096"),
        required_cash=Decimal("918.696"),
        dynamic_top3_price=Decimal("229.67"),
        dynamic_condition="above" if side == "buy" else "below",
        move_percent_from_mark=Decimal(move),
        visible_leader_coverage=3,
        visible_leaders=3,
        warning="visible-leader projection with conservative zero-score floor; clawback",
    )
    return close1_candidate_scanner.CandidateScan(
        sweep=202,
        reference=Decimal("224.55"),
        reference_age_seconds=10,
        mark=Decimal("226.28"),
        top3_cutoff=Decimal("210"),
        visible_leaders=leaders,
        verified_offers=1,
        sampled_trade_ids=0,
        rejected_offers=0,
        candidates=(candidate,),
        strategy_gate=gate,
    )


def isolate_state(monkeypatch, tmp_path):
    path = tmp_path / "close1-progress.json"
    monkeypatch.setattr(close1_discord_progress, "state_path", lambda: path)
    return path


def test_first_periodic_poll_sends_monitoring_notice(monkeypatch, tmp_path):
    isolate_state(monkeypatch, tmp_path)
    calls = []
    notices = close1_discord_progress.periodic_notices(
        now=NOW,
        fetcher=lambda: calls.append(True) or snapshot(),
    )
    assert len(calls) == 1
    assert len(notices) == 1
    assert "監視開始" in notices[0]
    assert "reference: 224.55" in notices[0]
    assert "visible top3 cutoff: +96.00 POLF" in notices[0]
    assert "binding取引は個別承認後のみ" in notices[0]


def test_poll_is_throttled_to_five_minutes(monkeypatch, tmp_path):
    isolate_state(monkeypatch, tmp_path)
    close1_discord_progress.periodic_notices(now=NOW, fetcher=lambda: snapshot())
    calls = []
    notices = close1_discord_progress.periodic_notices(
        now=NOW + timedelta(minutes=4),
        fetcher=lambda: calls.append(True) or snapshot(sweep=193),
    )
    assert calls == []
    assert notices == []


def test_same_state_gets_thirty_minute_progress_notice(monkeypatch, tmp_path):
    isolate_state(monkeypatch, tmp_path)
    close1_discord_progress.periodic_notices(now=NOW, fetcher=lambda: snapshot())
    notices = close1_discord_progress.periodic_notices(
        now=NOW + timedelta(minutes=30),
        fetcher=lambda: snapshot(sweep=198),
    )
    assert len(notices) == 1
    assert "30分定期" in notices[0]


def test_freshness_transition_notifies_immediately(monkeypatch, tmp_path):
    isolate_state(monkeypatch, tmp_path)
    close1_discord_progress.periodic_notices(now=NOW, fetcher=lambda: snapshot(age=10))
    notices = close1_discord_progress.periodic_notices(
        now=NOW + timedelta(minutes=5),
        fetcher=lambda: snapshot(sweep=193, age=305),
    )
    assert len(notices) == 1
    assert "安全状態変化" in notices[0]
    assert "freshness STOP" in notices[0]
    assert "DO_NOT_TRADE" in notices[0]


def test_material_top3_change_notifies(monkeypatch, tmp_path):
    isolate_state(monkeypatch, tmp_path)
    close1_discord_progress.periodic_notices(now=NOW, fetcher=lambda: snapshot(cutoff="96.00"))
    notices = close1_discord_progress.periodic_notices(
        now=NOW + timedelta(minutes=5),
        fetcher=lambda: snapshot(sweep=193, cutoff="107.00", leader="120.00"),
    )
    assert len(notices) == 1
    assert "top3水準変化" in notices[0]
    assert "visible top3 cutoff: +107.00 POLF" in notices[0]


def test_repeated_fetch_failure_is_fail_closed_and_bounded(monkeypatch, tmp_path):
    isolate_state(monkeypatch, tmp_path)

    def fail():
        raise RuntimeError("simulated")

    notices = []
    for index in range(7):
        notices = close1_discord_progress.periodic_notices(
            now=NOW + timedelta(minutes=5 * index),
            fetcher=fail,
        )
    assert len(notices) == 1
    assert "30分以上連続で取得失敗" in notices[0]
    assert "取引・署名・POSTは行っていません" in notices[0]


def test_manual_status_failure_never_executes_action():
    message = close1_discord_progress.status_message(
        fetcher=lambda: (_ for _ in ()).throw(RuntimeError("offline"))
    )
    assert "status unavailable" in message
    assert "取引・署名・POSTは行っていません" in message


def test_discord_close1_command_is_authenticated_and_read_only(monkeypatch):
    monkeypatch.setattr(
        close1_discord_progress,
        "status_message",
        lambda: "CLOSE1 READ ONLY",
    )
    control = discord_control.Control({"123"}, "456")
    result = control.command("123", "/close1", "456")
    assert result["ok"] is True
    assert result["message"] == "CLOSE1 READ ONLY"

    denied = control.command("999", "/close1", "456")
    assert denied["ok"] is False
    assert denied["error"] == "unauthorized"


def test_manual_status_surfaces_candidate_scanner_without_binding_action():
    message = close1_discord_progress.status_message(
        fetcher=lambda: snapshot(),
        candidate_fetcher=lambda: candidate_scan(),
    )
    assert "strategy scanner: ready" in message
    assert "best WATCH: BUY 4 @ 227.40" in message
    assert "visible-top3推定" in message
    assert "個別承認が必要" in message


def test_candidate_near_threshold_notifies_before_thirty_minutes(monkeypatch, tmp_path):
    isolate_state(monkeypatch, tmp_path)
    close1_discord_progress.periodic_notices(
        now=NOW,
        fetcher=lambda: snapshot(),
        candidate_fetcher=lambda: candidate_scan(move="0.030"),
    )
    notices = close1_discord_progress.periodic_notices(
        now=NOW + timedelta(minutes=5),
        fetcher=lambda: snapshot(sweep=193),
        candidate_fetcher=lambda: candidate_scan(move="0.015"),
    )
    assert len(notices) == 1
    assert "候補接近" in notices[0]
    assert "現在mark比 +1.50%" in notices[0]


def test_candidate_does_not_spam_every_five_minutes(monkeypatch, tmp_path):
    isolate_state(monkeypatch, tmp_path)
    close1_discord_progress.periodic_notices(
        now=NOW,
        fetcher=lambda: snapshot(),
        candidate_fetcher=lambda: candidate_scan(move="0.015"),
    )
    notices = close1_discord_progress.periodic_notices(
        now=NOW + timedelta(minutes=5),
        fetcher=lambda: snapshot(sweep=193),
        candidate_fetcher=lambda: candidate_scan(move="0.014"),
    )
    assert notices == []


def test_material_candidate_improvement_notifies(monkeypatch, tmp_path):
    isolate_state(monkeypatch, tmp_path)
    close1_discord_progress.periodic_notices(
        now=NOW,
        fetcher=lambda: snapshot(),
        candidate_fetcher=lambda: candidate_scan(move="0.018"),
    )
    notices = close1_discord_progress.periodic_notices(
        now=NOW + timedelta(minutes=5),
        fetcher=lambda: snapshot(sweep=193),
        candidate_fetcher=lambda: candidate_scan(move="0.012"),
    )
    assert len(notices) == 1
    assert "候補接近" in notices[0]


def test_scanner_failure_does_not_break_progress_notice(monkeypatch, tmp_path):
    isolate_state(monkeypatch, tmp_path)

    def fail_scan():
        raise RuntimeError("scanner-offline")

    notices = close1_discord_progress.periodic_notices(
        now=NOW,
        fetcher=lambda: snapshot(),
        candidate_fetcher=fail_scan,
    )
    assert len(notices) == 1
    assert "監視開始" in notices[0]
    assert "strategy scanner: unavailable (RuntimeError)" in notices[0]
    assert "visible top3 cutoff: +96.00 POLF" in notices[0]


def test_candidate_signal_requires_ready_gate(monkeypatch, tmp_path):
    isolate_state(monkeypatch, tmp_path)
    close1_discord_progress.periodic_notices(
        now=NOW,
        fetcher=lambda: snapshot(),
        candidate_fetcher=lambda: candidate_scan(move="0.030"),
    )
    notices = close1_discord_progress.periodic_notices(
        now=NOW + timedelta(minutes=5),
        fetcher=lambda: snapshot(sweep=193),
        candidate_fetcher=lambda: candidate_scan(move="0.010", gate="leader_coverage_incomplete"),
    )
    assert notices == []
