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


def _best_candidate(scan: close1_candidate_scanner.CandidateScan):
    return scan.candidates[0] if scan.candidates else None


def _candidate_signal(scan: close1_candidate_scanner.CandidateScan, state: dict) -> bool:
    if scan.strategy_gate != "ready":
        return False
    candidate = _best_candidate(scan)
    if candidate is None or candidate.move_percent_from_mark is None:
        return False
    move_abs = abs(candidate.move_percent_from_mark)
    if move_abs > CANDIDATE_NEAR:
        return False

    previous_move = _decimal(state.get("last_candidate_move_abs"))
    previous_side = state.get("last_candidate_side")
    previous_trade_id = state.get("last_candidate_trade_id")
    if previous_move is None or previous_side != candidate.taker_side:
        return True
    if previous_move > CANDIDATE_NEAR:
        return True
    if previous_move - move_abs >= CANDIDATE_IMPROVEMENT:
        return True
    return previous_trade_id != candidate.trade_id and move_abs <= previous_move


def _price_shock(scan: close1_candidate_scanner.CandidateScan, state: dict) -> bool:
    previous = _decimal(state.get("last_reference"))
    if previous is None or previous <= 0:
        return False
    return abs(scan.reference - previous) / previous >= PRICE_SHOCK


def _top3_shift(scan: close1_candidate_scanner.CandidateScan, state: dict) -> bool:
    current = scan.top3_cutoff
    previous = _decimal(state.get("last_top3_cutoff"))
    return bool(current is not None and previous is not None and abs(current - previous) >= TOP3_DELTA)


def _alert_reasons(scan: close1_candidate_scanner.CandidateScan, state: dict) -> list[str]:
    reasons: list[str] = []
    if state.get("activated") is not True:
        reasons.append("監視開始")
    if _price_shock(scan, state):
        reasons.append("5分価格急変")
    if _top3_shift(scan, state):
        reasons.append("TOP3変化")
    if _candidate_signal(scan, state):
        reasons.append("勝ち筋候補接近")
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
        f"leader envelope: stable {stable}/{len(scan.visible_leaders)}",
        f"strategy gate: {scan.strategy_gate} / verified offers {scan.verified_offers}",
    ]

    candidate = _best_candidate(scan)
    if candidate is None:
        lines.append("best WATCH: 現在、資金・鮮度・署名条件を満たす公開候補なし")
    elif candidate.dynamic_top3_price is None or candidate.move_percent_from_mark is None:
        lines.append(
            f"best WATCH: {candidate.taker_side.upper()} {candidate.qty} @ {candidate.px}"
            f" / until {candidate.until} / dynamic top3未確定"
        )
    else:
        relation = ">=" if candidate.dynamic_condition == "above" else "<="
        move = candidate.move_percent_from_mark * Decimal("100")
        lines.extend([
            f"best WATCH: {candidate.taker_side.upper()} {candidate.qty} @ {candidate.px}"
            f" / until {candidate.until}",
            f"visible-top3推定: final S {relation} "
            f"{candidate.dynamic_top3_price.quantize(Decimal('0.01'))}"
            f" / mark比 {move:+.2f}%",
            f"base fee: {candidate.base_fee} / required cash: {candidate.required_cash}",
        ])

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


def _remember_scan(state: dict, scan: close1_candidate_scanner.CandidateScan, current: datetime) -> None:
    candidate = _best_candidate(scan)
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
        last_candidate_trade_id=candidate.trade_id if candidate is not None else None,
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

    _remember_scan(state, scan, current)
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
