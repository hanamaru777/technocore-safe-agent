"""Read-only Close Call progress notices for the existing Discord control plane."""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Callable

from . import close1_candidate_scanner, close_call, observer, resident

LOG = logging.getLogger(__name__)

SCHEMA_VERSION = 1
STATE_FILE = "close1-discord-progress.json"
POLL_INTERVAL_SECONDS = 5 * 60
STATUS_INTERVAL_SECONDS = 30 * 60
TOP3_MATERIAL_DELTA = Decimal("10")
CANDIDATE_NEAR_THRESHOLD = Decimal("0.02")
CANDIDATE_IMPROVEMENT_DELTA = Decimal("0.005")
OWNER_DID = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
ASSUMED_AVAILABLE_CASH = "10000"
ASSUMED_CURRENT_POSITION = "0"


def state_path() -> Path:
    return resident.resident_dir() / STATE_FILE


def _default_state() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "last_attempt_at": None,
        "last_success_at": None,
        "last_notice_at": None,
        "last_fresh": None,
        "last_top3_cutoff": None,
        "last_sweep": None,
        "failure_count": 0,
        "failure_started_at": None,
        "last_failure_notice_at": None,
        "last_candidate_side": None,
        "last_candidate_move_abs": None,
        "last_candidate_notice_at": None,
    }


def _load_state() -> dict:
    path = state_path()
    if not path.exists():
        return _default_state()
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        LOG.warning("Close Call Discord progress state unreadable; rebuilding presentation state")
        return _default_state()
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        return _default_state()
    result = _default_state()
    result.update(data)
    return result


def _save_state(state: dict) -> None:
    try:
        observer.atomic_json_write(state_path(), state, compact=True)
    except OSError:
        LOG.exception("Close Call Discord progress state could not be persisted")


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    parsed = observer.parse_time(value)
    if parsed is None:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _elapsed(current: datetime, value: object) -> float | None:
    parsed = _parse_time(value)
    if parsed is None:
        return None
    return (current - parsed.astimezone(UTC)).total_seconds()


def _decimal_or_none(value: object) -> Decimal | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = Decimal(value)
    except Exception:
        return None
    return parsed if parsed.is_finite() else None


def _leader_score(snapshot: close_call.LiveSnapshot) -> Decimal | None:
    return snapshot.pnl_top[0][1] if snapshot.pnl_top else None


def _candidate_fetch() -> close1_candidate_scanner.CandidateScan:
    return close1_candidate_scanner.fetch_candidate_scan(
        our_did=OWNER_DID,
        available_cash=ASSUMED_AVAILABLE_CASH,
        current_position=ASSUMED_CURRENT_POSITION,
    )


def _best_candidate(scan: close1_candidate_scanner.CandidateScan):
    return scan.candidates[0] if scan.candidates else None


def _candidate_lines(
    scan: close1_candidate_scanner.CandidateScan | None,
    *,
    error: Exception | None = None,
) -> list[str]:
    if scan is None:
        reason = type(error).__name__ if error is not None else "not-run"
        return [f"strategy scanner: unavailable ({reason}) / 進捗監視は継続"]

    stable = sum(
        1
        for leader in scan.visible_leaders
        if leader.stable and leader.position is not None
    )
    lines = [
        f"strategy scanner: {scan.strategy_gate} / leaders {stable}/{len(scan.visible_leaders)} / verified offers {scan.verified_offers}",
    ]
    candidate = _best_candidate(scan)
    if candidate is None:
        lines.append("best WATCH: 現在、資金・鮮度・署名条件を満たす公開候補なし")
    elif candidate.dynamic_top3_price is None or candidate.move_percent_from_mark is None:
        lines.append(
            f"best WATCH: {candidate.taker_side.upper()} {candidate.qty} @ {candidate.px} "
            f"/ until {candidate.until} / dynamic top3 未確定"
        )
    else:
        relation = ">=" if candidate.dynamic_condition == "above" else "<="
        move_pct = candidate.move_percent_from_mark * Decimal("100")
        lines.append(
            f"best WATCH: {candidate.taker_side.upper()} {candidate.qty} @ {candidate.px} "
            f"/ until {candidate.until}"
        )
        lines.append(
            f"visible-top3推定: final S {relation} {candidate.dynamic_top3_price.quantize(Decimal('0.01'))} "
            f"/ 現在mark比 {move_pct:+.2f}%"
        )
    lines.extend([
        "前提: 当方 10,000 POLF / position 0（初回settle前のread-only仮定）",
        "取引: WATCHのみ。binding実行はexact tradeごとの個別承認が必要。",
    ])
    return lines


def _candidate_signal(
    scan: close1_candidate_scanner.CandidateScan | None,
    state: dict,
) -> bool:
    if scan is None or scan.strategy_gate != "ready":
        return False
    candidate = _best_candidate(scan)
    if candidate is None or candidate.move_percent_from_mark is None:
        return False
    move_abs = abs(candidate.move_percent_from_mark)
    if move_abs > CANDIDATE_NEAR_THRESHOLD:
        return False
    previous_side = state.get("last_candidate_side")
    previous_move = _decimal_or_none(state.get("last_candidate_move_abs"))
    if previous_side != candidate.taker_side or previous_move is None:
        return True
    if previous_move > CANDIDATE_NEAR_THRESHOLD:
        return True
    return previous_move - move_abs >= CANDIDATE_IMPROVEMENT_DELTA


def _remember_candidate(
    scan: close1_candidate_scanner.CandidateScan | None,
    state: dict,
) -> None:
    candidate = _best_candidate(scan) if scan is not None else None
    if candidate is None or candidate.move_percent_from_mark is None:
        state["last_candidate_side"] = None
        state["last_candidate_move_abs"] = None
        return
    state["last_candidate_side"] = candidate.taker_side
    state["last_candidate_move_abs"] = str(abs(candidate.move_percent_from_mark))


def render_snapshot(
    snapshot: close_call.LiveSnapshot,
    *,
    reason: str = "定期進捗",
    candidate_scan: close1_candidate_scanner.CandidateScan | None = None,
    candidate_error: Exception | None = None,
) -> str:
    leader = _leader_score(snapshot)
    cutoff = snapshot.top3_cutoff
    freshness = "PASS" if snapshot.reference_fresh_for_strategy else "STOP"
    decision = (
        "戦略監視継続。exact trade候補はChatGPT側で別評価し、binding取引は個別承認後のみ。"
        if snapshot.reference_fresh_for_strategy
        else "DO_NOT_TRADE。基準価格がローカル安全基準120秒を超えています。"
    )
    lines = [
        f"🟦 Close Call 進捗 — {reason}",
        f"sweep: {snapshot.sweep}",
        f"NVDA reference: {snapshot.reference} / age {snapshot.reference_age_seconds}s / freshness {freshness}",
        f"visible leader: {('+' + str(leader)) if leader is not None else 'n/a'} POLF",
        f"visible top3 cutoff: {('+' + str(cutoff)) if cutoff is not None else 'n/a'} POLF",
        f"positions: long {snapshot.longs} / short {snapshot.shorts} / open {snapshot.open_notional} POLF",
        *_candidate_lines(candidate_scan, error=candidate_error),
        f"現在判断: {decision}",
    ]
    return "\n".join(lines)


def status_message(
    *,
    fetcher: Callable[[], close_call.LiveSnapshot] | None = None,
    candidate_fetcher: Callable[[], close1_candidate_scanner.CandidateScan] | None = None,
) -> str:
    fetch = fetcher or close_call.fetch_live_snapshot
    try:
        snapshot = fetch()
    except Exception as error:
        return (
            "🟡 Close Call status unavailable (read-only)\n"
            f"reason: {type(error).__name__}\n"
            "取引・署名・POSTは行っていません。"
        )

    scan = None
    scan_error = None
    should_fetch_candidate = candidate_fetcher is not None or fetcher is None
    if should_fetch_candidate:
        try:
            scan = (candidate_fetcher or _candidate_fetch)()
        except Exception as error:
            scan_error = error
    return render_snapshot(
        snapshot,
        reason="手動確認",
        candidate_scan=scan,
        candidate_error=scan_error,
    )


def periodic_notices(
    *,
    now: datetime | None = None,
    fetcher: Callable[[], close_call.LiveSnapshot] | None = None,
    candidate_fetcher: Callable[[], close1_candidate_scanner.CandidateScan] | None = None,
) -> list[str]:
    """Return compact notices; never signs, posts, or changes contest state."""
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("close1_discord_timestamp_timezone_required")
    current = current.astimezone(UTC)
    state = _load_state()

    since_attempt = _elapsed(current, state.get("last_attempt_at"))
    if since_attempt is not None and since_attempt < POLL_INTERVAL_SECONDS:
        return []

    state["last_attempt_at"] = current.isoformat()
    fetch = fetcher or close_call.fetch_live_snapshot
    try:
        snapshot = fetch()
    except Exception as error:
        state["failure_count"] = int(state.get("failure_count", 0) or 0) + 1
        if _parse_time(state.get("failure_started_at")) is None:
            state["failure_started_at"] = current.isoformat()
        notices: list[str] = []
        failure_elapsed = _elapsed(current, state.get("failure_started_at"))
        since_failure_notice = _elapsed(current, state.get("last_failure_notice_at"))
        if (
            failure_elapsed is not None
            and failure_elapsed >= STATUS_INTERVAL_SECONDS
            and (since_failure_notice is None or since_failure_notice >= STATUS_INTERVAL_SECONDS)
        ):
            notices.append(
                "🟡 Close Call read-only監視が30分以上連続で取得失敗\n"
                f"reason: {type(error).__name__}\n"
                "既存FLOP Agentは継続。取引・署名・POSTは行っていません。"
            )
            state["last_failure_notice_at"] = current.isoformat()
        _save_state(state)
        return notices

    scan = None
    scan_error = None
    should_fetch_candidate = candidate_fetcher is not None or fetcher is None
    if should_fetch_candidate:
        try:
            scan = (candidate_fetcher or _candidate_fetch)()
        except Exception as error:
            scan_error = error

    previous_fresh = state.get("last_fresh")
    previous_cutoff = _decimal_or_none(state.get("last_top3_cutoff"))
    since_notice = _elapsed(current, state.get("last_notice_at"))
    cutoff = snapshot.top3_cutoff

    reasons: list[str] = []
    if state.get("last_notice_at") is None:
        reasons.append("監視開始")
    elif isinstance(previous_fresh, bool) and previous_fresh != snapshot.reference_fresh_for_strategy:
        reasons.append("安全状態変化")
    if previous_cutoff is not None and cutoff is not None:
        if abs(cutoff - previous_cutoff) >= TOP3_MATERIAL_DELTA:
            reasons.append("top3水準変化")
    if since_notice is None or since_notice >= STATUS_INTERVAL_SECONDS:
        reasons.append("30分定期")
    candidate_signal = _candidate_signal(scan, state)
    if candidate_signal:
        reasons.append("候補接近")

    notices = []
    if reasons:
        notices.append(render_snapshot(
            snapshot,
            reason=" / ".join(dict.fromkeys(reasons)),
            candidate_scan=scan,
            candidate_error=scan_error,
        ))
        state["last_notice_at"] = current.isoformat()
        if candidate_signal:
            state["last_candidate_notice_at"] = current.isoformat()

    _remember_candidate(scan, state)
    state.update(
        last_success_at=current.isoformat(),
        last_fresh=snapshot.reference_fresh_for_strategy,
        last_top3_cutoff=str(cutoff) if cutoff is not None else None,
        last_sweep=snapshot.sweep,
        failure_count=0,
        failure_started_at=None,
    )
    _save_state(state)
    return notices
