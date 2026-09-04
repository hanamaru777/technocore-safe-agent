"""Optional, outbound-only Discord control plane for local Resident state."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import unicodedata
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from . import autopilot, observer, resident, tclk_watch

LOG = logging.getLogger(__name__)
URL_RE = re.compile(r"https?://\S+", re.I)
MENTION_RE = re.compile(r"<@!?&?\d+>|@everyone|@here", re.I)
DISPLAY_TZ = ZoneInfo(os.environ.get("DISCORD_DISPLAY_TIMEZONE", "Asia/Tokyo"))
NORMAL_DIGEST_SECONDS = 6 * 60 * 60
GAP_NOTICE_THRESHOLD = 3
GAP_NOTICE_COOLDOWN_SECONDS = 60 * 60
OBSERVER_DEGRADED_NOTICE_SECONDS = 5 * 60
UI_STATE_FILE = "discord-ui-state.json"
INTERACTION_HISTORY_LIMIT = 1000
INTERACTION_DISPLAY_LIMIT = 10
AUDIT_READ_CHUNK_BYTES = 64 * 1024
DISCORD_MESSAGE_LIMIT = 2000
CATEGORY_LABELS = {"direct_inbound": "直接受信", "help_request": "具体的な支援依頼", "specific_question": "具体的な質問", "technical_collaboration": "技術コラボ候補", "artifact_contribution": "Contribution候補", "interesting_returning_agent": "再会した有用Agent", "new_high_quality_agent": "新しい有用Agent", "conversation": "署名付き直接リクエスト"}
PRIORITY_LABELS = {"critical": "緊急", "high": "高", "medium": "中", "low": "低"}
HEALTH_INCIDENT_LABELS = {"autopilot_off": "Autopilot OFF", "autopilot_paused": "Autopilot 一時停止", "resident_stale": "Resident監視遅延", "observer_health_other": "Observer監視異常"}
_INTERACTION_CACHE_KEY: tuple | None = None


def short(value: object, limit: int = 500) -> str: return str(value).replace("\n", " ")[:limit]
def safe_excerpt(value: object, limit: int = 180) -> str:
    text = URL_RE.sub("[URL省略]", str(value)); text = MENTION_RE.sub("[mention省略]", text).replace("@", "＠")
    text = "".join(" " if unicodedata.category(char) in {"Zl", "Zp", "Zs"} else "" if unicodedata.category(char) in {"Cc", "Cf", "Cs", "Co"} else char for char in text)
    return re.sub(r"\s+", " ", text).strip()[:limit]
def short_fingerprint(value: object) -> str:
    text = str(value or "unknown"); return text[:8] if text else "unknown"


def discord_message_chunks(value: str, limit: int = DISCORD_MESSAGE_LIMIT) -> list[str]:
    if limit < 1: raise ValueError("Discord message limit must be positive")
    chunks: list[str] = []; current = ""
    for line in value.splitlines(keepends=True) or [value]:
        while line:
            space = limit - len(current)
            if space == 0: chunks.append(current); current = ""; space = limit
            part, line = line[:space], line[space:]; current += part
            if len(current) == limit: chunks.append(current); current = ""
    if current or not chunks: chunks.append(current)
    return chunks


def _parse_time(value: object) -> datetime | None: return observer.parse_time(value) if isinstance(value, str) else None
def human_time(value: object) -> str:
    stamp = _parse_time(value)
    if not stamp: return "時刻不明"
    if stamp.tzinfo is None: stamp = stamp.replace(tzinfo=UTC)
    local = stamp.astimezone(DISPLAY_TZ); return f"{local:%m/%d %H:%M} {local.tzname() or ''}".strip()
def human_age(value: object, current: datetime | None = None) -> str:
    stamp = _parse_time(value)
    if not stamp: return "不明"
    if stamp.tzinfo is None: stamp = stamp.replace(tzinfo=UTC)
    current = current or datetime.now(UTC); seconds = max(0, int((current - stamp.astimezone(UTC)).total_seconds()))
    if seconds < 60: return f"{seconds}秒前"
    if seconds < 3600: return f"{seconds // 60}分前"
    if seconds < 86400: return f"{seconds // 3600}時間前"
    return f"{seconds // 86400}日前"
def signal_label(value: object, *, noise: bool = False) -> str | None:
    if not isinstance(value, (int, float)): return None
    score = max(0.0, min(1.0, float(value)))
    if noise: return "低" if score <= 0.20 else "中" if score <= 0.50 else "高"
    return "高" if score >= 0.67 else "中" if score >= 0.34 else "低"


def ui_state_path() -> Path: return resident.resident_dir() / UI_STATE_FILE
def default_ui_state() -> dict:
    return {"schema_version": 1, "digest_baseline": None, "last_gap_count": None, "pending_gap_delta": 0, "last_gap_notice_at": None, "last_health_problem": None, "health_incident_keys": [], "observer_degraded_since": None, "observer_degraded_alerted": False, "interactions": [], "notified_interactions": []}
def load_ui_state() -> dict:
    path = ui_state_path()
    if not path.exists(): return default_ui_state()
    try: data = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError): LOG.warning("Discord UI state was unreadable; rebuilding presentation-only state"); return default_ui_state()
    if not isinstance(data, dict) or data.get("schema_version") != 1: return default_ui_state()
    legacy_problem = data.get("last_health_problem"); has_incident_keys = "health_incident_keys" in data; has_observer_incident = "observer_degraded_alerted" in data
    for key, value in default_ui_state().items(): data.setdefault(key, value)
    if not has_incident_keys:
        legacy_text = legacy_problem if isinstance(legacy_problem, str) else ""; keys = []
        if "Autopilot OFF" in legacy_text: keys.append("autopilot_off")
        elif "Autopilot 一時停止" in legacy_text: keys.append("autopilot_paused")
        if "最終監視 " in legacy_text: keys.append("resident_stale")
        if "監視状態 " in legacy_text and "監視状態 degraded" not in legacy_text: keys.append("observer_health_other")
        data["health_incident_keys"] = keys
    if not has_observer_incident and legacy_problem == "監視状態 degraded": data["observer_degraded_alerted"] = True
    return data
def save_ui_state(state: dict) -> None: observer.atomic_json_write(ui_state_path(), state, compact=True)


def _observer_metrics() -> dict:
    """Prefer the tiny Observer heartbeat; parsing the multi-MB state is a fallback only."""
    try:
        payload = json.loads(observer.heartbeat_path().read_text("utf-8")); metrics = payload.get("metrics", {})
        if payload.get("schema_version") == 1 and isinstance(metrics, dict):
            return {"unique_dids_discovered": int(metrics.get("unique_dids_discovered", 0)), "returning_did_encounters": int(metrics.get("returning_did_encounters", 0)), "message_gaps": int(metrics.get("message_gaps", 0))}
    except (OSError, json.JSONDecodeError, TypeError, ValueError): pass
    try: state = observer.load_state()
    except RuntimeError: return {"unique_dids_discovered": 0, "returning_did_encounters": 0, "message_gaps": 0}
    metrics = state.get("metrics", {}); return {"unique_dids_discovered": int(metrics.get("unique_dids_discovered", 0)), "returning_did_encounters": int(metrics.get("returning_did_encounters", 0)), "message_gaps": int(metrics.get("message_gaps", 0))}


def _find_message(observed: dict, fingerprint: str, room: object, seq: object) -> dict | None:
    agent = observed.get("agents", {}).get(fingerprint, {}) if isinstance(observed, dict) else {}
    for message in agent.get("facts", {}).get("recent_messages", []):
        if message.get("room") == room and message.get("seq") == seq: return message
    return None
def _is_controlled_test_intent(intent: dict) -> bool: return intent.get("category") == "controlled_e2e" or intent.get("safety_decision") == "controlled_pause_only_e2e"
def rendered_outbound_text(intent: dict) -> str | None:
    fields = {"id", "source_candidate_id", "source_did", "fingerprint", "room", "seq", "category", "topic", "public_evidence_ids", "created_at", "expires_at", "safety_decision"}
    if not isinstance(intent, dict) or not fields <= set(intent): return None
    try: return autopilot.render({key: intent[key] for key in fields})
    except RuntimeError: return None
def verified_outbound_text(auto_state: dict, intent: dict, receipt: dict) -> str | None:
    text = rendered_outbound_text(intent)
    if text is None: return None
    text_hash = hashlib.sha256(text.encode()).hexdigest()
    if receipt.get("text_hash") == text_hash: return text
    for item in auto_state.get("rate_history", []):
        if item.get("text_hash") == text_hash and item.get("fingerprint") == intent.get("fingerprint") and item.get("room") == intent.get("room"): return text
    return None


def _resident_file_revision() -> tuple:
    try:
        info = resident.state_path().stat(); return (str(resident.state_path()), info.st_mtime_ns, info.st_size)
    except OSError: return (str(resident.state_path()), 0, 0)
def _auto_interaction_revision(auto_state: dict) -> str:
    rows = []
    for intent_id, receipt in auto_state.get("receipts", {}).items():
        intent = auto_state.get("outbox", {}).get(intent_id, {}); rows.append((intent_id, receipt.get("at") if isinstance(receipt, dict) else None, intent.get("status") if isinstance(intent, dict) else None))
    return hashlib.sha256(json.dumps(sorted(rows), separators=(",", ":")).encode()).hexdigest()[:20]


def sync_interactions() -> list[dict]:
    """Refresh only when Resident or receipt state changed; keep the 15s idle path tiny."""
    global _INTERACTION_CACHE_KEY
    ui = load_ui_state()
    try: auto_state = autopilot.load()
    except RuntimeError: auto_state = {"outbox": {}, "receipts": {}, "rate_history": []}
    cache_key = (*_resident_file_revision(), _auto_interaction_revision(auto_state))
    if cache_key == _INTERACTION_CACHE_KEY: return [item for item in ui.get("interactions", []) if isinstance(item, dict)]
    records = {item.get("id"): item for item in ui.get("interactions", []) if isinstance(item, dict) and item.get("id")}
    try: local = resident.load_state()
    except RuntimeError: local = {"candidates": {}}
    observed: dict | None = None
    for item in local.get("candidates", {}).values():
        signals = item.get("signals", {})
        if signals.get("direct_public_signed") is not True and item.get("category") != "direct_inbound": continue
        identifier = f"in:{item.get('candidate_id', '')}"
        if identifier in records: continue
        if observed is None:
            try: observed = observer.load_state()
            except RuntimeError: observed = {"agents": {}}
        message = _find_message(observed, str(item.get("fingerprint", "")), item.get("room"), item.get("seq")); context_text = item.get("context", {}).get("excerpt", ""); summary = (message or {}).get("text") or context_text or f"署名付き直接リクエスト topic={signals.get('conversation_topic', '不明')}"
        records[identifier] = {"id": identifier, "direction": "受信", "at": (message or {}).get("ts") or item.get("created_at"), "fingerprint": item.get("fingerprint"), "did": item.get("did"), "room": item.get("room"), "seq": item.get("seq"), "kind": CATEGORY_LABELS.get(item.get("category"), "署名付き直接リクエスト"), "summary": safe_excerpt(summary, 240), "conversation_id": item.get("candidate_id")}
    for intent_id, receipt in auto_state.get("receipts", {}).items():
        intent = auto_state.get("outbox", {}).get(intent_id)
        if not isinstance(intent, dict) or _is_controlled_test_intent(intent): continue
        identifier = f"out:{intent_id}"; actual_text = verified_outbound_text(auto_state, intent, receipt); record = records.get(identifier, {})
        record.update({"id": identifier, "direction": "送信", "at": receipt.get("at"), "fingerprint": intent.get("fingerprint"), "did": intent.get("source_did"), "room": intent.get("room"), "seq": intent.get("seq"), "kind": "自動返信", "summary": actual_text if actual_text is not None else record.get("summary", "送信済み（正確な本文は保持されていません）"), "exact_text": actual_text is not None, "conversation_id": intent.get("source_candidate_id")}); records[identifier] = record
    ordered = sorted(records.values(), key=lambda item: _parse_time(item.get("at")) or datetime.min.replace(tzinfo=UTC))[-INTERACTION_HISTORY_LIMIT:]
    if ordered != ui.get("interactions", []): ui["interactions"] = ordered; save_ui_state(ui)
    _INTERACTION_CACHE_KEY = cache_key; return ordered


def candidate_excerpt(item: dict) -> str:
    context = item.get("context", {})
    if context.get("excerpt"): return safe_excerpt(context.get("excerpt"), 180)
    try: observed = observer.load_state()
    except RuntimeError: return ""
    message = _find_message(observed, str(item.get("fingerprint", "")), item.get("room"), item.get("seq")); return safe_excerpt((message or {}).get("text", ""), 180)
def candidate_context_excerpt(item: dict) -> str:
    context = item.get("context", {})
    if not isinstance(context, dict) or not isinstance(context.get("excerpt"), str): return "保存済みcontextなし"
    return safe_excerpt(context["excerpt"], 560) or "保存済みcontextなし"
def candidate_reason(item: dict) -> str:
    signals = item.get("signals", {})
    if signals.get("direct_public_signed") is True: return "あなたのDID宛の署名付きリクエストを検出"
    if item.get("priority") == "critical": return "緊急度の高い受信を検出"
    return f"{CATEGORY_LABELS.get(item.get('category'), '対応候補')}として検出"
def candidate_outbound_preview(item: dict) -> tuple[str | None, str, str | None]:
    expiry = _parse_time(item.get("expires_at"))
    if expiry is None or expiry <= datetime.now(UTC): return None, "candidate_expired", None
    allowed, reason, topic = autopilot.eligible_approved_candidate(item)
    if not allowed or topic is None: return None, reason, topic
    try: return autopilot.render(autopilot.make_intent(item, topic, reason)), reason, topic
    except RuntimeError: return None, "preview_unavailable", topic


def candidate_message(item: dict) -> str:
    signals = item.get("signals", {}); useful = signal_label(signals.get("useful_agent_probability")); noise = signal_label(signals.get("spam_noise_probability"), noise=True); icon = "🔴" if item.get("priority") == "critical" else "🟡"
    lines = [f"{icon} FLOP Agent 確認あり", "", f"候補理由: {candidate_reason(item)}", f"category: {item.get('category', '不明')} / priority: {item.get('priority', '不明')}", f"時刻: {human_time(item.get('created_at'))}", f"相手: {item.get('fingerprint', 'unknown')} | {item.get('room', '?')} #{item.get('seq', '?')}"]
    excerpt = candidate_excerpt(item)
    if excerpt: lines.append(f"要点（抜粋）: {excerpt}")
    lines.append(f"判定対象全文: {candidate_context_excerpt(item)}")
    if useful is not None or noise is not None:
        parts = []
        if useful is not None: parts.append(f"有用度 {useful}")
        if noise is not None: parts.append(f"ノイズ {noise}")
        lines.append("判定: " + " / ".join(parts))
    preview, reason, topic = candidate_outbound_preview(item); lines.append(f"resolved topic: {topic or 'なし'}")
    if reason == "reply_semantics_unsupported": lines.append("reply relevance: unsupported（固定replyでは質問内容を十分に回答できないため自動投稿対象外）")
    elif reason == "redundant_reply": lines.append("reply relevance: redundant（相手が既に固定replyの主要内容を述べているため自動投稿対象外）")
    elif reason == "no_incremental_value": lines.append("reply relevance: no incremental value（固定replyで新しい有用情報を追加できないため自動投稿対象外）")
    else: lines.append(f"safety: {reason}")
    lines.append("送信予定本文: " + (preview if preview is not None else "表示不可（安全条件を満たさないか確認不能）")); candidate_id = item.get("candidate_id", ""); next_step = f"次にやること: /reply-approved {candidate_id} SEND" if item.get("status") == "approved" else f"次にやること: /approve {candidate_id}（承認だけでは投稿しません）"; lines.extend(["", next_step]); return "\n".join(lines)


def _tclk_offer_message(item: dict) -> str:
    expiry = datetime.fromtimestamp(int(item.get("expires_ms", 0)) / 1000, tz=UTC) if isinstance(item.get("expires_ms"), int) else None; job = "/".join(part for part in (safe_excerpt(item.get("job_proto"), 48), safe_excerpt(item.get("job_id"), 64)) if part)
    return "\n".join(["🔒 tclk/1 opportunity (read-only)", f"ID: {safe_excerpt(item.get('id'), 70)}", f"counterpart: {short_fingerprint(item.get('counterpart_fingerprint'))}", f"frame: {safe_excerpt(item.get('frame_type'), 24)}", f"job: {job or 'unknown'}", f"amount / asset: {safe_excerpt(item.get('amount'), 48)} / {safe_excerpt(item.get('asset'), 48)}", f"rail: {safe_excerpt(item.get('rail'), 24)} (PaperRail only; no real-value rail)", f"expires: {human_time(expiry.isoformat()) if expiry else 'unknown'}", f"terms (untrusted): {safe_excerpt(item.get('terms'), 280) or '-'}", "status: read-only; not accepted. No accept, offer, or receipt was posted."])
def tclk_opportunities_message() -> str:
    status = tclk_watch.runtime_status()
    if status.get("ready") is not True: return f"🔴 tclk runtime unavailable/degraded ({status.get('reason', 'unknown')}). No offer state was changed."
    try: rows = tclk_watch.opportunities(observer.load_state())[:5]
    except RuntimeError: rows = []
    if not rows: return "🔒 tclk/1 opportunities (read-only)\n\nNo validated signed PaperRail offers are stored locally. Nothing was accepted."
    lines = ["🔒 tclk/1 opportunities (read-only)", "", f"validated offers: {len(rows)} (showing up to 5)"]
    for item in rows: lines.extend(["", _tclk_offer_message(item)])
    return "\n".join(lines)
def tclk_offer_message(offer_id: str) -> str:
    status = tclk_watch.runtime_status()
    if status.get("ready") is not True: return f"🔴 tclk runtime unavailable/degraded ({status.get('reason', 'unknown')}). No offer state was changed."
    try: item = tclk_watch.offer(observer.load_state(), offer_id)
    except RuntimeError: item = None
    return _tclk_offer_message(item) if item is not None else "No validated read-only tclk/1 offer found for that ID."


def outbound_interaction_message(item: dict, inbound: dict | None = None) -> str:
    received = safe_excerpt((inbound or {}).get("summary", ""), 180); sent = item.get("summary") if item.get("exact_text") else "送信済み（正確な本文は保持されていません）"; received_line = f"受信: {received}\n" if received else ""
    return ("🔵 FLOP Agent 自動返信完了\n\n" f"時刻: {human_time(item.get('at'))}\n" f"相手: {short_fingerprint(item.get('fingerprint'))} | {item.get('room', '?')} #{item.get('seq', '?')}\n" f"{received_line}" f"送信: {sent}\n\n" f"履歴を見る: /history {item.get('fingerprint') or ''}").rstrip()

def _latest_post_at(auto_state: dict) -> str | None:
    values = [item.get("at") for item in filtered_rate_history(auto_state) if _parse_time(item.get("at"))]; return max(values, key=lambda value: _parse_time(value) or datetime.min.replace(tzinfo=UTC), default=None)
def filtered_rate_history(auto_state: dict) -> list[dict]:
    controlled_fingerprints = {item.get("fingerprint") for item in auto_state.get("outbox", {}).values() if isinstance(item, dict) and _is_controlled_test_intent(item) and item.get("fingerprint")}
    return [item for item in auto_state.get("rate_history", []) if isinstance(item, dict) and item.get("fingerprint") not in controlled_fingerprints]


def _recent_audit_records(cutoff: datetime, auto_state: dict | None = None) -> list[dict]:
    """Prefer bounded decision state; legacy files are streamed only when needed."""
    if auto_state is not None and isinstance(auto_state.get("recent_decisions"), list):
        decisions: dict[str, dict] = {}
        for item in auto_state["recent_decisions"]:
            if not isinstance(item, dict) or (_parse_time(item.get("at")) or datetime.min.replace(tzinfo=UTC)) <= cutoff: continue
            candidate = item.get("source_candidate")
            if isinstance(candidate, str) and candidate: decisions[candidate] = item
        return list(decisions.values())
    path = autopilot.audit_path()
    try:
        if not path.is_file() or path.is_symlink(): return []
        with path.open("rb") as handle:
            position = handle.seek(0, 2); remainder = b""; decisions: dict[str, dict] = {}
            while position > 0:
                size = min(AUDIT_READ_CHUNK_BYTES, position); position -= size; handle.seek(position); parts = (handle.read(size) + remainder).split(b"\n"); remainder = parts.pop(0) if position else b""
                if position == 0 and remainder: parts.insert(0, remainder); remainder = b""
                for raw in reversed(parts):
                    try: item = json.loads(raw.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError): continue
                    if not isinstance(item, dict): continue
                    at = _parse_time(item.get("at"))
                    if at is None: continue
                    if at <= cutoff: return list(reversed(list(decisions.values())))
                    candidate = item.get("source_candidate")
                    if not isinstance(candidate, str) or not candidate or candidate in decisions: continue
                    if item.get("action") not in {"intent_created", "ignored", "blocked"}: continue
                    if item.get("action") == "ignored" and item.get("why") == "candidate_not_pending": continue
                    decisions[candidate] = item
    except OSError: return []
    return list(reversed(list(decisions.values())))


def _reason_label(reason: object) -> str:
    labels = {"sender_not_previously_approved": "初回DIDのためreview-only", "candidate_not_pending": "対象はすでに処理済み", "generic_or_noise": "汎用・ノイズ候補を除外", "no_public_concrete_evidence": "公開の具体的根拠なし", "conversation_not_verified": "署名付き直接リクエスト未確認", "non_public_or_owned_room": "公開room以外は対象外", "daily_limit": "24時間上限", "room_limit": "room別上限", "did_limit": "相手別cooldown", "category_not_allowlisted": "許可対象外"}; return labels.get(str(reason), "安全条件により対象外")


def activity_snapshot(*, sync_timeline: bool = True, include_trust: bool = True) -> dict:
    snapshot = _health_snapshot(); current = datetime.now(UTC); cutoff = current - timedelta(hours=24); posts = [item for item in filtered_rate_history(snapshot["auto_state"]) if (_parse_time(item.get("at")) or datetime.min.replace(tzinfo=UTC)) > cutoff]
    timeline = sync_interactions() if sync_timeline else load_ui_state().get("interactions", []); interactions = [item for item in timeline if isinstance(item, dict) and (_parse_time(item.get("at")) or datetime.min.replace(tzinfo=UTC)) > cutoff]
    audit = _recent_audit_records(cutoff, snapshot["auto_state"]); eligible = [item for item in audit if item.get("action") == "intent_created" and item.get("eligible") is True]; ignored = [item for item in audit if item.get("action") == "ignored"]; blocked = [item for item in audit if item.get("action") == "blocked"]
    reasons: dict[str, int] = {}
    for item in [*ignored, *blocked]:
        reason = item.get("rate_limit") if item.get("action") == "blocked" else item.get("why"); label = _reason_label(reason); reasons[label] = reasons.get(label, 0) + 1
    if not posts:
        if not snapshot["auto"].get("enabled"): zero_reason = "Autopilot OFF"
        elif snapshot["auto"].get("paused"): zero_reason = "Autopilot 一時停止"
        elif snapshot["auto"].get("queued", 0): zero_reason = "queue処理待ち"
        elif reasons: zero_reason = max(reasons, key=reasons.get)
        elif not eligible: zero_reason = "対象なし（監視は継続中）"
        else: zero_reason = "対象はあるが安全条件・上限を確認中"
    else: zero_reason = None
    received = [item for item in interactions if item.get("direction") == "受信"]; sent = [item for item in interactions if item.get("direction") == "送信"]; counterparts = {item.get("fingerprint") for item in interactions if item.get("fingerprint")}
    trusted = trusted_relationships() if include_trust else []; trust_rows = trust_candidates() if include_trust else []; bootstrap = bootstrap_pending_approvals() if include_trust else []
    return {"snapshot": snapshot, "posts": len(posts), "eligible": len(eligible), "ignored": len(ignored), "blocked": len(blocked), "reasons": reasons, "zero_reason": zero_reason, "received": received, "sent": sent, "counterparts": len(counterparts), "interactions": interactions, "latest_post": _latest_post_at(snapshot["auto_state"]), "trusted": trusted, "trust_candidates": trust_rows, "bootstrap_pending": bootstrap}


def trust_candidates(limit: int = 5) -> list[dict]:
    state = resident.load_state(); now_value = datetime.now(UTC); rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}; category_rank = {"conversation": 4, "specific_question": 3, "help_request": 3, "technical_collaboration": 3, "artifact_contribution": 2}; selected, seen, seen_cores = [], set(), set()
    for item in sorted(state.get("candidates", {}).values(), key=lambda value: (category_rank.get(value.get("category"), 0), rank.get(value.get("priority"), 0), value.get("created_at", "")), reverse=True):
        expires = _parse_time(item.get("expires_at"))
        if item.get("status") != "pending" or expires is None or expires <= now_value or item.get("fingerprint") in seen: continue
        allowed, _, _ = autopilot.eligible(item); preview, _, _ = candidate_outbound_preview(item); core_text = candidate_core_text(item)
        if not allowed or preview is None or not core_text or core_text in seen_cores or autopilot.sender_trusted_for_autopilot(item, state): continue
        seen.add(item.get("fingerprint")); seen_cores.add(core_text); selected.append(item)
        if len(selected) >= limit: break
    return selected
def candidate_core_text(item: dict) -> str:
    context = item.get("context", {}); text = context.get("excerpt", "") if isinstance(context, dict) else ""; text = URL_RE.sub(" ", str(text).lower()); text = re.sub(r"\s*[-—]\s*[a-z0-9]{4,}\s*$", "", text); return re.sub(r"[^a-z0-9]+", " ", text).strip()[:280]
def trusted_relationships() -> list[dict]:
    state = resident.load_state()
    try: return autopilot.active_trusted_relationships(state, autopilot.load())
    except RuntimeError: return []
def bootstrap_pending_approvals() -> list[dict]:
    state = resident.load_state()
    try: auto = autopilot.load()
    except RuntimeError: auto = autopilot.default_state()
    pending = []
    for item in state.get("candidates", {}).values():
        if item.get("status") != "approved": continue
        history = state.get("relationships", {}).get(item.get("fingerprint"), {}).get("approval_rejection_history", []); approved = any(isinstance(record, dict) and record.get("candidate_id") == item.get("candidate_id") and record.get("decision") == "approved" for record in history)
        if approved and not autopilot.durable_publication_at(str(item.get("candidate_id", "")), str(item.get("fingerprint", "")), state, auto): pending.append(item)
    return pending

def trust_candidates_message() -> str:
    rows = trust_candidates()
    if not rows: return "🤝 trust候補\n現在、safeな初回trust候補はありません。監視は継続中です。"
    lines = ["🤝 初回trust候補（投稿はしません）"]
    for item in rows:
        preview, _, _ = candidate_outbound_preview(item); lines.extend(["", f"{item.get('candidate_id')} | {short_fingerprint(item.get('fingerprint'))} | {item.get('room')} #{item.get('seq')}", f"{CATEGORY_LABELS.get(item.get('category'), '候補')} / {PRIORITY_LABELS.get(item.get('priority'), '中')}", f"理由: {candidate_reason(item)}", f"要点: {safe_excerpt(candidate_excerpt(item), 100)}", f"送信予定: {safe_excerpt(preview, 100) if preview else '詳細は /candidate で確認'}", f"次: /approve {item.get('candidate_id')}"])
    return "\n".join(lines)
def trusted_message() -> str:
    rows = trusted_relationships(); waiting = bootstrap_pending_approvals(); lines = [f"🤝 active trusted counterpart: {len(rows)}"]; lines.extend(f"- {short_fingerprint(item['fingerprint'])} / active {human_time(item['at'])}" for item in rows[:5])
    if waiting: lines.append("初回返信待ち: " + ", ".join(short_fingerprint(item.get("fingerprint")) for item in waiting[:3]))
    elif not rows: lines.append("初回trustは /trust-candidates から確認できます。")
    return "\n".join(lines)


def _health_snapshot() -> dict:
    status = resident.resident_status()
    try: auto_state = autopilot.load(); auto = autopilot.status(auto_state)
    except RuntimeError: auto_state, auto = {"rate_history": []}, {"enabled": False, "paused": True, "queued": 0, "receipts": 0}
    health = status.get("health", {}).get("current", "unknown") if isinstance(status.get("health"), dict) else "unknown"; last_refresh = status.get("last_refresh_at"); age = human_age(last_refresh); stamp = _parse_time(last_refresh); stale = not stamp or (datetime.now(UTC) - stamp.astimezone(UTC)).total_seconds() > 180
    critical = int(status.get("critical_candidates", 0)); direct = int(status.get("direct_candidates", 0)); problems = []
    if health != "ok": problems.append(f"監視状態 {health}")
    if not auto.get("enabled"): problems.append("Autopilot OFF")
    elif auto.get("paused"): problems.append("Autopilot 一時停止")
    if stale: problems.append(f"最終監視 {age}")
    return {"resident": status, "auto_state": auto_state, "auto": auto, "health": health, "last_refresh": last_refresh, "last_refresh_age": age, "critical": critical, "direct": direct, "problems": problems}
def immediate_health_incidents(snapshot: dict) -> dict[str, str]:
    incidents: dict[str, str] = {}
    if snapshot["health"] not in {"ok", "degraded"}: incidents["observer_health_other"] = f"監視状態 {snapshot['health']}"
    if not snapshot["auto"].get("enabled"): incidents["autopilot_off"] = "Autopilot OFF"
    elif snapshot["auto"].get("paused"): incidents["autopilot_paused"] = "Autopilot 一時停止"
    if any(problem.startswith("最終監視 ") for problem in snapshot["problems"]): incidents["resident_stale"] = f"最終監視 {snapshot['last_refresh_age']}"
    return incidents


def status_message() -> str:
    activity = activity_snapshot(sync_timeline=False, include_trust=False); snapshot = activity["snapshot"]; interactions = activity["interactions"]; latest_interaction = interactions[-1] if interactions else None; needs_attention = bool(snapshot["problems"] or snapshot["critical"] or snapshot["direct"] or snapshot["auto"].get("queued", 0)); icon = "🔴" if snapshot["problems"] else "🟡" if needs_attention else "🟢"; title = "異常" if snapshot["problems"] else "確認あり" if needs_attention else "正常"; auto_label = "ON" if snapshot["auto"].get("enabled") and not snapshot["auto"].get("paused") else "停止/一時停止"
    lines = [f"{icon} FLOP Agent {title}", f"監視: {'監視中' if snapshot['health'] == 'ok' else '監視状態 ' + str(snapshot['health'])}", f"Autopilot: {auto_label} / 直近24h 自動投稿 {activity['posts']}/6（上限・目標ではありません）", f"queue: {snapshot['auto'].get('queued', 0)} / eligible {activity['eligible']} / ignored {activity['ignored']} / blocked {activity['blocked']}", f"要対応: 緊急 {snapshot['critical']} / 直接リクエスト {snapshot['direct']}", f"最終監視: {snapshot['last_refresh_age']}", f"最終投稿: {human_age(activity['latest_post']) if activity['latest_post'] else 'なし'}"]
    if latest_interaction: lines.append(f"最終やりとり: {short_fingerprint(latest_interaction.get('fingerprint'))} / {latest_interaction.get('direction')} / {human_age(latest_interaction.get('at'))}")
    if activity["reasons"]: lines.append("主な非投稿理由: " + max(activity["reasons"], key=activity["reasons"].get))
    if activity["zero_reason"]: lines.append(f"0投稿の理由: {activity['zero_reason']}")
    if snapshot["problems"]: lines.append("異常: " + " / ".join(snapshot["problems"])); lines.append("結論: 対応が必要です。詳細は /status を再確認してください。")
    elif needs_attention: lines.append("結論: 確認事項があります。直接リクエストまたはqueueを確認してください。")
    else: lines.append("結論: 対応不要。そのまま稼働中。")
    return "\n".join(lines)
def history_message(filter_value: str | None = None, limit: int = INTERACTION_DISPLAY_LIMIT) -> str:
    records = sync_interactions()
    if filter_value:
        token = filter_value.lower(); records = [item for item in records if token in str(item.get("fingerprint", "")).lower() or token in str(item.get("did", "")).lower()]
    records = records[-limit:]
    if not records: return "🧾 最近のやりとり\nまだ直接のやりとり記録はありません。\n※監視しただけの他Agent会話は含めず、自分のDIDが関与した直接受信・自動返信だけを記録します。"
    lines = ["🧾 最近のやりとり"]
    for item in records: lines.extend(["", f"{human_time(item.get('at'))} | {item.get('direction')} | {short_fingerprint(item.get('fingerprint'))}", f"{item.get('room', '?')} #{item.get('seq', '?')} | {item.get('kind', 'やりとり')}", f"内容: {item.get('summary', '') if item.get('direction') == '送信' and item.get('exact_text') else safe_excerpt(item.get('summary', ''), 240)}"])
    return "\n".join(lines)
def activity_message() -> str:
    activity = activity_snapshot(); snapshot = activity["snapshot"]; recent = activity["interactions"][-3:]; lines = ["📊 FLOP Agent 24時間活動", f"監視: {'監視中' if snapshot['health'] == 'ok' else '監視状態 ' + str(snapshot['health'])}", f"自動投稿: {activity['posts']}/6（上限・目標ではありません）", f"eligible {activity['eligible']} / ignored {activity['ignored']} / blocked {activity['blocked']}", f"直接受信 {len(activity['received'])} / 直接送信 {len(activity['sent'])} / 相手 {activity['counterparts']}人", f"queue: {snapshot['auto'].get('queued', 0)} / 最終投稿: {human_age(activity['latest_post']) if activity['latest_post'] else 'なし'}"]
    if activity["reasons"]: lines.append("主なblocked/ignored理由: " + max(activity["reasons"], key=activity["reasons"].get))
    if activity["zero_reason"]: lines.append(f"0投稿の理由: {activity['zero_reason']}")
    if snapshot["auto"].get("enabled") and not snapshot["auto"].get("paused") and not activity["trusted"] and (activity["trust_candidates"] or activity["bootstrap_pending"]): lines.append("初回trust設定が必要: /trust-candidates（故障ではありません）")
    if recent:
        lines.append("直近のやりとり:")
        for item in recent:
            content = item.get("summary", "") if item.get("direction") == "送信" and item.get("exact_text") else safe_excerpt(item.get("summary", ""), 80); lines.append(f"- {short_fingerprint(item.get('fingerprint'))} / {item.get('direction')} / {content}")
    else: lines.append("直近の直接やりとり: なし")
    return "\n".join(lines)


class Control:
    def __init__(self, allowed_ids: set[str] | None = None, channel_id: str | None = None) -> None:
        self.allowed_ids = allowed_ids if allowed_ids is not None else {item.strip() for item in os.environ.get("DISCORD_ALLOWED_USER_IDS", "").split(",") if item.strip()}; self.channel_id = channel_id if channel_id is not None else os.environ.get("DISCORD_CHANNEL_ID", "")
    def command(self, user_id: str, text: str, channel_id: str | None = None) -> dict:
        if channel_id is not None and channel_id != self.channel_id: return {"ok": False, "error": "wrong_channel", "message": "Control access denied."}
        if user_id not in self.allowed_ids: return {"ok": False, "error": "unauthorized", "message": "Control access denied."}
        parts = text.strip().split()
        if not parts: return {"ok": False, "error": "empty", "message": "Use /help for local control commands."}
        action, args = parts[0], parts[1:]
        if action == "/status": return {"ok": True, "data": {}, "message": status_message()}
        if action == "/activity" and not args: return {"ok": True, "data": {}, "message": activity_message()}
        if action == "/tclk-opportunities" and not args: return {"ok": True, "data": {}, "message": tclk_opportunities_message()}
        if action == "/tclk" and len(args) == 1: return {"ok": True, "data": {}, "message": tclk_offer_message(args[0])}
        if action == "/trust-candidates" and not args: return {"ok": True, "data": {}, "message": trust_candidates_message()}
        if action == "/trusted" and not args: return {"ok": True, "data": {}, "message": trusted_message()}
        if action == "/history" and len(args) <= 1: return {"ok": True, "data": {}, "message": history_message(args[0] if args else None)}
        if action == "/resident-status": data = resident.resident_status(); return {"ok": True, "data": data, "message": f"状態: agents={data['agents_known']} pending={data['useful_candidates']} gaps={data['message_gaps']}"}
        if action == "/intel": data = observer.intelligence_report(); return {"ok": True, "data": data, "message": f"Intel: agents={data['facts']['observed_unique_external_dids']} returning={data['facts']['returning_dids']} inbound={data['facts']['inbound_mailbox']}"}
        if action == "/opportunities": data = observer.opportunities(); return {"ok": True, "data": data, "message": f"Local opportunities: {len(data['opportunities'])} (all content remains untrusted)."}
        if action == "/agents": data = observer.list_agents(); return {"ok": True, "data": data, "message": f"Known external agents: {len(data['agents'])}."}
        if action == "/agent" and len(args) == 1: data = observer.get_agent(args[0]); return {"ok": True, "data": data, "message": f"Agent {short(data['agent']['fingerprint'], 32)} | rooms={len(data['agent']['facts']['rooms'])}."}
        if action == "/candidate" and len(args) == 1: data = resident.candidate(args[0]); return {"ok": True, "data": data, "message": candidate_message(data['candidate'])}
        if action == "/approve" and len(args) == 1: data = resident.feedback(args[0], "approved"); return {"ok": True, "data": data, "message": f"Approval registered locally for {short_fingerprint(data.get('fingerprint'))}. Autonomous write trust is not active yet, and this candidate was not posted. To stage this exact first reply: /reply-approved {data['candidate_id']} SEND. Normal Autopilot trust activates only after this reply is posted and ACKed."}
        if action == "/reply-approved" and len(args) == 2:
            if args[1] != "SEND": return {"ok": False, "error": "confirmation_required", "message": "No intent staged. Use exact uppercase SEND only after review."}
            data = autopilot.stage_approved_reply(args[0]); return {"ok": True, "data": data, "message": f"STAGED: {data['intent_id']}. Discord did not sign or post; the isolated Signer will process it asynchronously."}
        if action == "/reject" and len(args) == 2: data = resident.feedback(args[0], "rejected", args[1]); return {"ok": True, "data": data, "message": f"Rejected locally: {data['candidate_id']}."}
        if action == "/pause": return {"ok": True, "data": resident.pause(True), "message": "Candidate generation paused; observation continues."}
        if action == "/resume": return {"ok": True, "data": resident.pause(False), "message": "Candidate generation resumed."}
        if action == "/learning": data = resident.feedback_status(); return {"ok": True, "data": data, "message": f"Learning: approved={data['approved']} rejected={data['rejected']} expired={data['expired']}."}
        if action == "/autopilot-status": data = autopilot.status(); return {"ok": True, "data": data, "message": f"Autopilot: enabled={data['enabled']} paused={data['paused']} queued={data['queued']}."}
        if action == "/autopilot-queue": data = autopilot.queue(); return {"ok": True, "data": data, "message": f"Autopilot queue: {len(data['outbox'])} structured public intents."}
        if action == "/autopilot-pause": return {"ok": True, "data": autopilot.pause(True), "message": "Autopilot outbox generation paused."}
        if action == "/autopilot-resume": return {"ok": True, "data": autopilot.pause(False), "message": "Autopilot outbox generation resumed locally; Discord cannot publish."}
        if action == "/help": return {"ok": True, "data": {}, "message": "普段使うコマンド: /status /activity /trust-candidates /trusted /history [相手ID] /candidate <id> /tclk-opportunities /tclk <id> | 緊急停止: /autopilot-pause | 詳細: /help-debug"}
        if action == "/help-debug": return {"ok": True, "data": {}, "message": "Debug: /resident-status /intel /opportunities /agents /agent <id> /approve <id> /reject <id> <reason> /pause /resume /learning /autopilot-status /autopilot-queue /autopilot-resume"}
        return {"ok": False, "error": "unsupported", "message": "Unsupported control command. Use /help."}
    def notifications(self) -> list[dict]:
        summary = resident.resident_status()
        if not int(summary.get("critical_candidates", 0)) and not int(summary.get("direct_candidates", 0)): return []
        state = resident.load_state(); notices = []; current = datetime.now(UTC); old_times = list(state.get("notification_times", [])); recent = [entry for entry in old_times if (observer.parse_time(entry.get("at")) or current) > current - timedelta(hours=1)]; state["notification_times"] = recent; capacity = max(0, 3 - len(recent)); changed = recent != old_times
        for item in state["candidates"].values():
            if capacity <= 0: break
            if item.get("status") != "pending" or item.get("candidate_id") in state["notifications"]: continue
            signals = item.get("signals", {}); actionable = item.get("priority") == "critical" or signals.get("direct_public_signed") is True
            if not actionable: continue
            state["notifications"].append(item["candidate_id"]); state["notification_times"].append({"candidate_id": item["candidate_id"], "at": current.isoformat()}); notices.append(item); capacity -= 1; changed = True
        if changed: resident.save_state(state)
        return notices
    def ensure_baseline(self) -> None:
        interactions = sync_interactions(); ui = load_ui_state()
        if ui.get("digest_baseline") is None: ui["digest_baseline"] = {**_observer_metrics(), "at": datetime.now(UTC).isoformat()}
        if ui.get("last_gap_count") is None: ui["last_gap_count"] = _observer_metrics()["message_gaps"]
        if not ui.get("notified_interactions"): ui["notified_interactions"] = [item["id"] for item in interactions if item.get("direction") == "送信"][-INTERACTION_HISTORY_LIMIT:]
        save_ui_state(ui)
    def system_notices(self) -> list[str]:
        snapshot = _health_snapshot(); metrics = _observer_metrics(); ui = load_ui_state(); notices = []; current_gap = metrics["message_gaps"]; previous_gap = ui.get("last_gap_count"); now_value = datetime.now(UTC)
        if previous_gap is None: ui["last_gap_count"] = current_gap
        elif current_gap > previous_gap: ui["pending_gap_delta"] = int(ui.get("pending_gap_delta", 0)) + (current_gap - previous_gap); ui["last_gap_count"] = current_gap
        elif current_gap < previous_gap: ui["last_gap_count"] = current_gap; ui["pending_gap_delta"] = 0
        pending_gap = int(ui.get("pending_gap_delta", 0)); last_gap_notice = _parse_time(ui.get("last_gap_notice_at"))
        if last_gap_notice and last_gap_notice.tzinfo is None: last_gap_notice = last_gap_notice.replace(tzinfo=UTC)
        cooldown_elapsed = not last_gap_notice or (now_value - last_gap_notice.astimezone(UTC)).total_seconds() >= GAP_NOTICE_COOLDOWN_SECONDS
        if pending_gap >= GAP_NOTICE_THRESHOLD and cooldown_elapsed:
            notices.append("🟡 FLOP Agent 通信欠落を複数検出\n\n" f"未通知gap: +{pending_gap}\n" f"最終監視: {snapshot['last_refresh_age']}\n" "単発gapは6時間レポートへ集約し、連続時だけ通知しています。\n\n" "次にやること: /status"); ui["pending_gap_delta"] = 0; ui["last_gap_notice_at"] = now_value.isoformat()
        incidents = immediate_health_incidents(snapshot); current_keys = set(incidents); observer_degraded = snapshot["health"] == "degraded"; observer_since = _parse_time(ui.get("observer_degraded_since")); observer_alerted = ui.get("observer_degraded_alerted") is True; observer_recovered = False
        if observer_degraded:
            if observer_since is None: ui["observer_degraded_since"] = now_value.isoformat()
            elif not observer_alerted and (now_value - observer_since.astimezone(UTC)).total_seconds() >= OBSERVER_DEGRADED_NOTICE_SECONDS:
                notices.append("🔴 FLOP Agent 異常\n\n監視状態 degraded が5分以上継続しています。\n" f"最終正常監視の確認: {snapshot['last_refresh_age']}\n\n次にやること: /status"); ui["observer_degraded_alerted"] = True
        else: observer_recovered = observer_alerted; ui["observer_degraded_since"] = None; ui["observer_degraded_alerted"] = False
        previous_keys = {key for key in ui.get("health_incident_keys", []) if key in HEALTH_INCIDENT_LABELS}; new_keys = current_keys - previous_keys; resolved_keys = previous_keys - current_keys
        if new_keys:
            problem = " / ".join(incidents[key] for key in sorted(new_keys)); notices.append("🔴 FLOP Agent 異常\n\n" f"{problem}\n" f"最終正常監視の確認: {snapshot['last_refresh_age']}\n\n次にやること: /status")
        if (resolved_keys or observer_recovered) and not current_keys and not observer_degraded: notices.append("🟢 FLOP Agent 監視復旧\n\nObserver監視状態が正常へ戻りました。\n結論: 対応不要。そのまま稼働中。" if observer_recovered and not resolved_keys else "🟢 FLOP Agent 復旧\n\n監視とAutopilotが正常状態へ戻りました。\n結論: 対応不要。そのまま稼働中。")
        ui["health_incident_keys"] = sorted(current_keys); ui["last_health_problem"] = " / ".join(incidents[key] for key in sorted(current_keys)) or None; save_ui_state(ui); return notices
    def interaction_notices(self) -> list[str]:
        interactions = sync_interactions(); ui = load_ui_state(); notified = set(ui.get("notified_interactions", [])); notices = []
        for item in interactions:
            identifier = item.get("id")
            if not identifier or item.get("direction") != "送信" or identifier in notified: continue
            notified.add(identifier); inbound = next((record for record in interactions if record.get("direction") == "受信" and record.get("conversation_id") == item.get("conversation_id")), None); notices.append(outbound_interaction_message(item, inbound))
        ordered_ids = [item.get("id") for item in interactions if item.get("id") in notified]; ui["notified_interactions"] = ordered_ids[-INTERACTION_HISTORY_LIMIT:]; save_ui_state(ui); return notices
    def digest(self) -> str:
        activity = activity_snapshot(); snapshot = activity["snapshot"]; current_metrics = _observer_metrics(); ui = load_ui_state(); baseline = ui.get("digest_baseline") or {**current_metrics, "at": datetime.now(UTC).isoformat()}; new_agents = max(0, current_metrics["unique_dids_discovered"] - int(baseline.get("unique_dids_discovered", 0))); returning = max(0, current_metrics["returning_did_encounters"] - int(baseline.get("returning_did_encounters", 0))); new_gaps = max(0, current_metrics["message_gaps"] - int(baseline.get("message_gaps", 0))); interactions = activity["interactions"]; recent = interactions[-3:]; ui["digest_baseline"] = {**current_metrics, "at": datetime.now(UTC).isoformat()}; ui["pending_gap_delta"] = 0; save_ui_state(ui); attention = snapshot["critical"] + snapshot["direct"]
        if snapshot["problems"]: icon, title, conclusion = "🔴", "異常", "対応が必要です。/status を確認してください。"
        elif attention or new_gaps: icon, title, conclusion = "🟡", "確認あり", "確認事項があります。/status を確認してください。"
        else: icon, title, conclusion = "🟢", "正常", "対応不要。そのまま稼働中。"
        interaction_line = "直近のやりとり: " + " / ".join(f"{short_fingerprint(item.get('fingerprint'))} {item.get('direction')} {safe_excerpt(item.get('summary', ''), 60)}" for item in recent) + "\n詳細: /history\n" if recent else "直近の直接やりとり: なし（詳細: /history）\n"
        return f"{icon} FLOP Agent 6時間レポート（{title}）\n直近6時間: 新規Agent +{new_agents} / 再会 +{returning}\n活動: 直近24h 自動投稿 {activity['posts']}/6（上限・目標ではありません） / 直接受信 {len(activity['received'])}\n要対応: {attention} / 新しいgap +{new_gaps} / queue {snapshot['auto'].get('queued', 0)}\n最終監視: {snapshot['last_refresh_age']}\n投稿しなかった主因: {activity['zero_reason'] or '投稿あり'}\n" + interaction_line + f"結論: {conclusion}"


def validate_environment() -> tuple[str, str, set[str]]:
    token, channel = os.environ.get("DISCORD_BOT_TOKEN"), os.environ.get("DISCORD_CHANNEL_ID", ""); allowed = {item.strip() for item in os.environ.get("DISCORD_ALLOWED_USER_IDS", "").split(",") if item.strip()}
    if not token: raise RuntimeError("Discord token is missing")
    if not channel.isdecimal(): raise RuntimeError("Discord channel ID must be numeric")
    if not allowed or not all(item.isdecimal() for item in allowed): raise RuntimeError("Discord allowed user IDs must be non-empty numeric IDs")
    return token, channel, allowed
async def notification_worker(channel, control: Control, stop: asyncio.Event) -> None:
    while not stop.is_set():
        for notice in await asyncio.to_thread(control.system_notices): await channel.send(notice, suppress_embeds=True)
        for item in await asyncio.to_thread(control.notifications): await channel.send(candidate_message(item), suppress_embeds=True)
        for notice in await asyncio.to_thread(control.interaction_notices): await channel.send(notice, suppress_embeds=True)
        try: await asyncio.wait_for(stop.wait(), timeout=15)
        except TimeoutError: pass
async def digest_worker(channel, control: Control, stop: asyncio.Event) -> None:
    while not stop.is_set():
        configured = resident.load_config().get("discord_digest_interval_seconds", NORMAL_DIGEST_SECONDS); interval = max(NORMAL_DIGEST_SECONDS, int(configured))
        try: await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError: await channel.send(await asyncio.to_thread(control.digest), suppress_embeds=True)


def main() -> None:
    token, channel_id, allowed = validate_environment()
    try: import discord
    except ImportError as error: raise SystemExit("Install the optional discord dependency to run this gateway") from error
    intents = discord.Intents.default(); intents.message_content = True; bot = discord.Client(intents=intents); control = Control(allowed, channel_id); stop = asyncio.Event()
    @bot.event
    async def on_ready():
        channel = bot.get_channel(int(channel_id))
        if channel is None: raise RuntimeError("configured Discord channel is unavailable")
        if getattr(bot, "resident_workers_started", False): return
        bot.resident_workers_started = True; await asyncio.to_thread(control.ensure_baseline); LOG.info("Discord control started; message-content intent must be enabled in the Discord developer portal"); asyncio.create_task(notification_worker(channel, control, stop)); asyncio.create_task(digest_worker(channel, control, stop))
    @bot.event
    async def on_message(message):
        if message.author.bot or str(message.channel.id) != channel_id: return
        result = await asyncio.to_thread(control.command, str(message.author.id), message.content, str(message.channel.id))
        for chunk in discord_message_chunks(result["message"]): await message.channel.send(chunk, suppress_embeds=True)
    bot.run(token)


if __name__ == "__main__": main()
