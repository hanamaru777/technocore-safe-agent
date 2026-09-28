"""Standalone read-only Close Call watcher.

Runs as a short-lived oneshot, reads only public contest rooms through the
candidate scanner, and posts a compact Discord notice only when strategy-relevant
conditions change. It has no signing or Technocore/FLOP write path.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Callable

from . import close1_candidate_scanner, observer, resident

SCHEMA_VERSION = 1
STATE_FILE = "close1-standalone-watch.json"
OWNER_DID = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
AVAILABLE_CASH = "10000"
CURRENT_POSITION = "0"

PRICE_SHOCK = Decimal("0.0075")
TOP3_DELTA = Decimal("10")
CANDIDATE_NEAR = Decimal("0.03")
CANDIDATE_IMPROVEMENT = Decimal("0.005")
FLOW_SHOCK_QTY = Decimal("40")
FLOW_SHOCK_IMPROVEMENT = Decimal("20")
HURDLE_ACCEL = Decimal("50")
HURDLE_ACCEL_IMPROVEMENT = Decimal("50")

DISCORD_API = "https://discord.com/api/v10"
DISCORD_LIMIT = 2000


def state_path() -> Path:
    return resident.resident_dir() / STATE_FILE


def _default_state() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "activated": False,
        "last_success_at": None,
        "last_sweep": None,
        "last_reference": None,
        "last_top3_cutoff": None,
        "last_candidate_side": None,
        "last_candidate_move_abs": None,
        "last_candidate_trade_id": None,
        "last_flow_key": None,
        "last_flow_qty": None,
        "flow_alerted_qty": {},
        "last_hurdle_alert_delta": None,
        "last_alert_at": None,
        "last_error": None,
    }


def _load_state() -> dict:
    path = state_path()
    if not path.exists():
        return _default_state()
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return _default_state()
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        return _default_state()
    result = _default_state()
    result.update(value)
    return result


def _save_state(value: dict) -> None:
    observer.atomic_json_write(state_path(), value, compact=True)


def _decimal(value: object) -> Decimal | None:
    if value is None:
        return None
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    return result if result.is_finite() else None


def _opportunity_key(kind: str, candidate) -> str:
    if kind == "single":
        return f"single:{candidate.trade_id}"
    return "basket:" + ",".join(leg.trade_id for leg in candidate.legs)


def _opportunity_rank_move(candidate) -> tuple[int, Decimal, str]:
    if candidate.move_percent_from_mark is not None:
        return 0, abs(candidate.move_percent_from_mark), "dynamic_top3"
    if candidate.base_fee_flat_move_percent is not None:
        return 1, abs(candidate.base_fee_flat_move_percent), "flat_target_fallback"
    return 2, Decimal("999"), "unranked"


def _best_opportunity(scan: close1_candidate_scanner.CandidateScan):
    rows = []
    for candidate in scan.candidates:
        rows.append(("single", candidate))
    for basket in scan.baskets:
        rows.append(("basket", basket))
    rows.sort(key=lambda item: (
        _opportunity_rank_move(item[1])[0],
        _opportunity_rank_move(item[1])[1],
        -item[1].qty,
        0 if item[0] == "basket" else 1,
    ))
    return rows[0] if rows else None


def _candidate_signal(scan: close1_candidate_scanner.CandidateScan, state: dict) -> bool:
    if scan.strategy_gate != "ready":
        return False
    opportunity = _best_opportunity(scan)
    if opportunity is None:
        return False
    kind, candidate = opportunity
    if candidate.move_percent_from_mark is None:
        return False
    move_abs = abs(candidate.move_percent_from_mark)
    if move_abs > CANDIDATE_NEAR:
        return False

    previous_move = _decimal(state.get("last_candidate_move_abs"))
    previous_side = state.get("last_candidate_side")
    previous_key = state.get("last_candidate_trade_id")
    current_key = _opportunity_key(kind, candidate)
    if previous_move is None or previous_side != candidate.taker_side:
        return True
    if previous_move > CANDIDATE_NEAR:
        return True
    if previous_move - move_abs >= CANDIDATE_IMPROVEMENT:
        return True
    return previous_key != current_key and move_abs <= previous_move


def _price_shock(scan: close1_candidate_scanner.CandidateScan, state: dict) -> bool:
    previous = _decimal(state.get("last_reference"))
    if previous is None or previous <= 0:
        return False
    return abs(scan.reference - previous) / previous >= PRICE_SHOCK


def _top3_shift(scan: close1_candidate_scanner.CandidateScan, state: dict) -> bool:
    current = scan.top3_cutoff
    previous = _decimal(state.get("last_top3_cutoff"))
    return bool(current is not None and previous is not None and abs(current - previous) >= TOP3_DELTA)


def _large_flows(scan: close1_candidate_scanner.CandidateScan):
    rows = [
        flow
        for flow in scan.recent_flows
        if flow.taker != OWNER_DID and flow.qty >= FLOW_SHOCK_QTY
    ]
    return tuple(rows[:3])


def _flow_key(flow) -> str:
    return f"{flow.taker}:{flow.taker_side}"


def _flow_alerted_qty(state: dict) -> dict[str, Decimal]:
    raw = state.get("flow_alerted_qty")
    result: dict[str, Decimal] = {}
    if isinstance(raw, dict):
        for key, value in raw.items():
            if not isinstance(key, str):
                continue
            parsed = _decimal(value)
            if parsed is not None and parsed >= 0:
                result[key] = parsed

    # Backward-compatible migration from the single-flow state already
    # deployed in Production.
    old_key = state.get("last_flow_key")
    old_qty = _decimal(state.get("last_flow_qty"))
    if isinstance(old_key, str) and old_qty is not None and old_qty >= 0:
        result.setdefault(old_key, old_qty)
    return result


def _flow_signals(scan: close1_candidate_scanner.CandidateScan, state: dict):
    alerted = _flow_alerted_qty(state)
    signals = []
    for flow in _large_flows(scan):
        previous = alerted.get(_flow_key(flow))
        if previous is None or flow.qty - previous >= FLOW_SHOCK_IMPROVEMENT:
            signals.append(flow)
    return tuple(signals)


def _hurdle_accel_signal(scan: close1_candidate_scanner.CandidateScan, state: dict) -> bool:
    current = scan.top3_delta_10m
    if current is None or current < HURDLE_ACCEL:
        return False
    previous_alert = _decimal(state.get("last_hurdle_alert_delta"))
    if previous_alert is None:
        return True
    return current - previous_alert >= HURDLE_ACCEL_IMPROVEMENT


def _alert_reasons(scan: close1_candidate_scanner.CandidateScan, state: dict) -> list[str]:
    reasons: list[str] = []
    if state.get("activated") is not True:
        reasons.append("監視開始")
    if _price_shock(scan, state):
        reasons.append("5分価格急変")
    if _top3_shift(scan, state):
        reasons.append("TOP3変化")
    if _hurdle_accel_signal(scan, state):
        reasons.append("TOP3急騰")
    if _candidate_signal(scan, state):
        reasons.append("勝ち筋候補接近")
    if _flow_signals(scan, state):
        reasons.append("大口フロー")
    return reasons


def _render(scan: close1_candidate_scanner.CandidateScan, reasons: list[str]) -> str:
    stable = sum(
        1
        for leader in scan.visible_leaders
        if leader.stable and leader.position is not None
    )
    cutoff = f"{scan.top3_cutoff:+f}" if scan.top3_cutoff is not None else "n/a"
    lines = [
        f"🟦 Close Call standalone監視 — {' / '.join(reasons)}",
        f"sweep: {scan.sweep}",
        f"reference: {scan.reference} / age {scan.reference_age_seconds}s / mark {scan.mark}",
        f"visible top3 cutoff: {cutoff} POLF",
        (
            "top3 10m delta: "
            + (f"{scan.top3_delta_10m:+f} POLF" if scan.top3_delta_10m is not None else "n/a")
        ),
        (
            "flat target score: "
            + (f"{scan.flat_target_score:+f} POLF" if scan.flat_target_score is not None else "n/a")
        ),
        f"leader envelope: stable {stable}/{len(scan.visible_leaders)}",
        f"strategy gate: {scan.strategy_gate} / verified offers {scan.verified_offers}",
    ]

    large_flows = _large_flows(scan)
    for index, flow in enumerate(large_flows, start=1):
        lines.append(
            f"recent gross taker flow #{index}: "
            f"{flow.taker_side.upper()} {flow.qty} contracts / {flow.trades} trades "
            f"/ px {flow.min_px}-{flow.max_px} / taker {flow.taker}"
        )
    if large_flows:
        lines.append("gross flowは新規ポジション量とは限りません。PnL反映前の早期警戒です。")

    opportunity = _best_opportunity(scan)
    if opportunity is None:
        lines.append("best WATCH: 現在、資金・鮮度・署名条件を満たす公開候補なし")
    else:
        kind, candidate = opportunity
        if kind == "basket":
            prefix = (
                f"BASKET {candidate.taker_side.upper()} {candidate.qty} "
                f"@ weighted {candidate.weighted_px.quantize(Decimal('0.01'))} "
                f"/ legs {len(candidate.legs)} / until {candidate.until}"
            )
        else:
            prefix = (
                f"{candidate.taker_side.upper()} {candidate.qty} @ {candidate.px}"
                f" / until {candidate.until}"
            )
        if candidate.dynamic_top3_price is None or candidate.move_percent_from_mark is None:
            _, _, rank_source = _opportunity_rank_move(candidate)
            if rank_source == "flat_target_fallback":
                lines.append(
                    f"best WATCH: {prefix} / dynamic top3未確定"
                    " / ranking=flat target fallback"
                )
            else:
                lines.append(f"best WATCH: {prefix} / dynamic top3未確定")
        else:
            relation = ">=" if candidate.dynamic_condition == "above" else "<="
            move = candidate.move_percent_from_mark * Decimal("100")
            lines.extend([
                f"best WATCH: {prefix}",
                f"visible-top3推定: final S {relation} "
                f"{candidate.dynamic_top3_price.quantize(Decimal('0.01'))}"
                f" / mark比 {move:+.2f}%",
                f"base fee: {candidate.base_fee} / required cash: {candidate.required_cash}",
            ])
            if kind == "basket":
                leg_text = ", ".join(
                    f"{leg.trade_id}:{leg.qty}@{leg.px}" for leg in candidate.legs[:8]
                )
                if len(candidate.legs) > 8:
                    leg_text += f", +{len(candidate.legs) - 8} more"
                lines.append(f"basket legs: {leg_text}")
                lines.append("basketは複数の別trade。各legごとにexact承認が必要です。")

        if (
            candidate.flat_target_score is not None
            and candidate.base_fee_flat_exit_price is not None
            and candidate.base_fee_flat_move_percent is not None
        ):
            exit_action = "SELL >=" if candidate.taker_side == "buy" else "BUY <="
            flat_move = candidate.base_fee_flat_move_percent * Decimal("100")
            lines.append(
                "途中利確目安(base-fee only): "
                f"flat +{candidate.flat_target_score} POLF ⇒ "
                f"{exit_action} {candidate.base_fee_flat_exit_price.quantize(Decimal('0.01'))} "
                f"/ entry比 {flat_move:+.2f}%"
            )
            lines.append("この途中利確価格はclawback未反映の楽観下限です。")

    lines.extend([
        "shadow leaders込み。leader/future trades・未観測account・clawbackで条件は変動します。",
        "取引は未実行。binding actionはexact tradeごとの個別承認が必要です。",
    ])
    return "\n".join(lines)


def _discord_post(message: str) -> None:
    token = os.environ.get("DISCORD_BOT_TOKEN", "")
    channel = os.environ.get("DISCORD_CHANNEL_ID", "")
    if not token:
        raise RuntimeError("discord_token_missing")
    if not channel.isdecimal():
        raise RuntimeError("discord_channel_invalid")
    if len(message) > DISCORD_LIMIT:
        raise RuntimeError("discord_message_too_long")

    body = json.dumps(
        {
            "content": message,
            "flags": 4,
            "allowed_mentions": {"parse": []},
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{DISCORD_API}/channels/{channel}/messages",
        data=body,
        headers={
            "Authorization": f"Bot {token}",
            "Content-Type": "application/json",
            "User-Agent": "technocore-safe-agent-close1-watch/1",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status = int(getattr(response, "status", 0) or 0)
            if not 200 <= status < 300:
                raise RuntimeError(f"discord_http_{status}")
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"discord_http_{error.code}") from error
    except urllib.error.URLError as error:
        raise RuntimeError("discord_network_error") from error


def _remember_scan(
    state: dict,
    scan: close1_candidate_scanner.CandidateScan,
    current: datetime,
    reasons: list[str],
) -> None:
    opportunity = _best_opportunity(scan)
    if opportunity is None:
        kind = None
        candidate = None
    else:
        kind, candidate = opportunity
    large_flows = _large_flows(scan)
    current_keys = {_flow_key(flow) for flow in large_flows}
    alerted = {
        key: qty
        for key, qty in _flow_alerted_qty(state).items()
        if key in current_keys
    }
    signaled = _flow_signals(scan, state) if "大口フロー" in reasons else ()
    for flow in signaled:
        alerted[_flow_key(flow)] = flow.qty

    if signaled:
        # Preserve the legacy single-flow fields during the migration window.
        primary = signaled[0]
        flow_key = _flow_key(primary)
        flow_qty = str(primary.qty)
    else:
        old_flow_key = state.get("last_flow_key")
        if isinstance(old_flow_key, str) and old_flow_key in current_keys:
            flow_key = old_flow_key
            flow_qty = state.get("last_flow_qty")
        else:
            # If the flow leaves the active ten-minute window, clear the
            # compatibility fields too so a later wave can alert as new.
            flow_key = None
            flow_qty = None
    if scan.top3_delta_10m is None or scan.top3_delta_10m < HURDLE_ACCEL:
        hurdle_alert_delta = None
    elif "TOP3急騰" in reasons:
        hurdle_alert_delta = str(scan.top3_delta_10m)
    else:
        hurdle_alert_delta = state.get("last_hurdle_alert_delta")

    state.update(
        activated=True,
        last_success_at=current.isoformat(),
        last_sweep=scan.sweep,
        last_reference=str(scan.reference),
        last_top3_cutoff=str(scan.top3_cutoff) if scan.top3_cutoff is not None else None,
        last_candidate_side=candidate.taker_side if candidate is not None else None,
        last_candidate_move_abs=(
            str(abs(candidate.move_percent_from_mark))
            if candidate is not None and candidate.move_percent_from_mark is not None
            else None
        ),
        last_candidate_trade_id=(
            _opportunity_key(kind, candidate)
            if candidate is not None and kind is not None
            else None
        ),
        last_flow_key=flow_key,
        last_flow_qty=flow_qty,
        flow_alerted_qty={key: str(value) for key, value in alerted.items()},
        last_hurdle_alert_delta=hurdle_alert_delta,
        last_error=None,
    )


def run_once(
    *,
    fetcher: Callable[[], close1_candidate_scanner.CandidateScan] | None = None,
    sender: Callable[[str], None] | None = None,
    now: datetime | None = None,
) -> dict:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("close1_watch_timestamp_timezone_required")
    current = current.astimezone(UTC)

    state = _load_state()
    fetch = fetcher or (
        lambda: close1_candidate_scanner.fetch_candidate_scan(
            our_did=OWNER_DID,
            available_cash=AVAILABLE_CASH,
            current_position=CURRENT_POSITION,
        )
    )
    send = sender or _discord_post

    try:
        scan = fetch()
    except Exception as error:
        state["last_error"] = f"fetch:{type(error).__name__}"
        _save_state(state)
        return {"status": "fetch_error", "sent": False}

    reasons = _alert_reasons(scan, state)
    if reasons:
        try:
            send(_render(scan, reasons))
        except Exception as error:
            # Do not advance the alert baselines. The next timer run retries.
            state["last_error"] = f"send:{type(error).__name__}"
            _save_state(state)
            return {"status": "send_error", "sent": False, "sweep": scan.sweep}
        state["last_alert_at"] = current.isoformat()

    _remember_scan(state, scan, current, reasons)
    _save_state(state)
    return {
        "status": scan.strategy_gate,
        "sent": bool(reasons),
        "sweep": scan.sweep,
        "reasons": reasons,
    }


def main() -> None:
    result = run_once()
    reasons = ",".join(result.get("reasons", [])) or "-"
    print(
        "CLOSE1_STANDALONE="
        f"{result.get('status')} sent={'yes' if result.get('sent') else 'no'} "
        f"sweep={result.get('sweep', '-')} reasons={reasons}"
    )


if __name__ == "__main__":
    main()
