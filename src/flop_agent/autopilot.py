"""Safe Autopilot v1: Oracle intent outbox and Windows-only deterministic publisher."""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import core, observer, resident

OUTBOX_FILE = "autopilot-outbox.json"
AUDIT_FILE = "autopilot-audit.jsonl"
SHARED_DIR = "autopilot"
PROFILE = core.ROOT / "public-profile.json"
PUBLIC_ROOMS = re.compile(r"^(?!p-|mb-)[a-z0-9][a-z0-9_-]{0,47}$")
ALLOWED_TOPICS = {"repo_safety", "signer_did_nonce", "public_contribution"}
DLP = re.compile(r"(?ix)(?:sign_seed|private[ _-]?key|\bseed\b|api[ _-]?key|token|authorization:|discord|\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b|\b\+?\d[\d -]{7,}\d\b|(?:[a-z]:\\|/home/|/users/|/etc/|/var/)|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-z0-9_+=-]{32,}\b)")


def now() -> str: return datetime.now(UTC).isoformat()
def shared_dir() -> Path: return core.STATE / SHARED_DIR
def path() -> Path: return shared_dir() / OUTBOX_FILE
def audit_path() -> Path: return shared_dir() / AUDIT_FILE
def legacy_path() -> Path: return resident.resident_dir() / OUTBOX_FILE
def legacy_audit_path() -> Path: return resident.resident_dir() / AUDIT_FILE


def migrate_legacy_shared_state() -> None:
    """Move the former observer-local shared files once, without merging data."""
    for old, current in ((legacy_path(), path()), (legacy_audit_path(), audit_path())):
        if not old.exists(): continue
        if not old.is_file(): raise RuntimeError("legacy autopilot state is not a regular file")
        if current.exists(): raise RuntimeError("legacy and dedicated autopilot state both exist; refusing to lose data")
        current.parent.mkdir(parents=True, exist_ok=True, mode=0o770)
        os.replace(old, current)


def default_state() -> dict:
    return {"schema_version": 1, "enabled": False, "paused": True, "outbox": {}, "receipts": {}, "rate_history": [], "migrated_at": None}


def load() -> dict:
    migrate_legacy_shared_state()
    if not path().exists(): return default_state()
    try: state = json.loads(path().read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error: raise RuntimeError("autopilot state is corrupt; refusing to continue") from error
    if not isinstance(state, dict) or state.get("schema_version") != 1: raise RuntimeError("autopilot state schema is invalid")
    for key, value in default_state().items(): state.setdefault(key, value)
    return state


def save(state: dict) -> None:
    migrate_legacy_shared_state()
    resident.observer.atomic_json_write(path(), state, mode=0o660)
def audit(record: dict) -> None:
    migrate_legacy_shared_state()
    audit_path().parent.mkdir(parents=True, exist_ok=True, mode=0o770)
    with audit_path().open("a", encoding="utf-8", newline="\n") as handle: handle.write(json.dumps(record, sort_keys=True) + "\n")
    os.chmod(audit_path(), 0o660)


def public_knowledge() -> dict:
    data = json.loads(PROFILE.read_text("utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1 or set(data) != {"schema_version", "knowledge"}: raise RuntimeError("public profile schema is invalid")
    return data["knowledge"]


def migrate_old_candidates() -> int:
    state = load()
    if state["migrated_at"]: return 0
    local = resident.load_state(); changed = 0
    for candidate in local["candidates"].values():
        if candidate.get("status") == "pending":
            candidate["status"] = "expired"; candidate["expired_at"] = now(); candidate["expiration_reason"] = "filter_upgrade_safe_autopilot_v1"; changed += 1
    resident.save_state(local); state["migrated_at"] = now(); save(state)
    return changed


def eligible(candidate: dict) -> tuple[bool, str, str | None]:
    if candidate.get("status") != "pending": return False, "candidate_not_pending", None
    if not isinstance(candidate.get("room"), str) or not PUBLIC_ROOMS.fullmatch(candidate["room"]): return False, "non_public_or_owned_room", None
    signals = candidate.get("signals", {})
    facts = signals.get("facts", {})
    if facts.get("inbound_to_us"): return False, "direct_context_is_never_auto_posted", None
    if signals.get("spam_noise_probability", 1) >= 0.20 or signals.get("generic_template_probability", 1) > 0 or signals.get("poetic_filler_count", 0): return False, "generic_or_noise", None
    if not signals.get("concrete_evidence"): return False, "no_public_concrete_evidence", None
    category = candidate.get("category")
    if category in {"help_request", "specific_question", "technical_collaboration"}: return True, "concrete_public_technical_request", "repo_safety"
    if category == "artifact_contribution": return True, "public_artifact_evidence", "public_contribution"
    if signals.get("conversation_continuity") and signals.get("useful_agent_probability", 0) >= 0.75: return True, "proven_returning_high_quality_agent", "signer_did_nonce"
    return False, "category_not_allowlisted", None


def make_intent(candidate: dict, topic: str, reason: str) -> dict:
    intent_id = hashlib.sha256(f"{candidate['candidate_id']}|{topic}".encode()).hexdigest()[:20]
    return {"id": intent_id, "source_candidate_id": candidate["candidate_id"], "source_did": candidate["did"], "fingerprint": candidate["fingerprint"], "room": candidate["room"], "seq": candidate["seq"], "category": candidate["category"], "topic": topic, "public_evidence_ids": ["public-profile:1", f"candidate:{candidate['candidate_id']}"], "created_at": now(), "expires_at": candidate["expires_at"], "safety_decision": reason}


def build_outbox() -> dict:
    migrate_old_candidates()
    state = load()
    if state["paused"] or not state["enabled"]: return status(state)
    local = resident.load_state()
    for candidate in local["candidates"].values():
        allowed, reason, topic = eligible(candidate)
        audit({"at": now(), "source_candidate": candidate.get("candidate_id"), "eligible": allowed, "why": reason, "public_knowledge_ids": ["public-profile:1"], "dlp": "not_applicable", "rate_limit": "not_applicable", "action": "intent_created" if allowed else "ignored"})
        if not allowed or not topic: continue
        intent = make_intent(candidate, topic, reason)
        state["outbox"].setdefault(intent["id"], intent)
    save(state); return status(state)


def status(state: dict | None = None) -> dict:
    state = state or load()
    return {"enabled": state["enabled"], "paused": state["paused"], "queued": sum(item.get("status", "queued") == "queued" for item in state["outbox"].values()), "receipts": len(state["receipts"]), "migration_complete": bool(state["migrated_at"])}
def queue() -> dict: return {"outbox": list(load()["outbox"].values())}
def enable() -> dict:
    state = load(); state["enabled"] = True; state["paused"] = True; save(state); return status(state)


def disable() -> dict:
    state = load(); state["enabled"] = False; state["paused"] = True; save(state); return status(state)


def pause(value: bool) -> dict:
    state = load()
    if not value and not state["enabled"]:
        raise RuntimeError("autopilot must be enabled before it can resume")
    state["paused"] = value; save(state); return status(state)


def export_intent(item: dict) -> dict:
    """Map an internal intent to the only signer/transport-visible schema."""
    return {"schema_version": 1, "intent_id": item["id"], "source_fingerprint": item["fingerprint"], "room": item["room"], "seq": item["seq"], "category": item["category"], "topic": item["topic"], "public_knowledge_ids": ["public-profile:1"], "created_at": item["created_at"], "expires_at": item["expires_at"], "safety_decision": item["safety_decision"]}


def export_pending() -> dict:
    """Oracle endpoint: expose only strict, non-reflective pending intent fields."""
    return {"schema_version": 1, "intents": [export_intent(item) for item in load()["outbox"].values() if item.get("status", "queued") == "queued"]}


def acknowledge_export(payload: dict) -> dict:
    """Oracle-local acknowledgement only; it has no Technocore side effect."""
    required = {"schema_version", "intent_id", "receipt_hash"}
    if not isinstance(payload, dict) or set(payload) != required or payload.get("schema_version") != 1:
        raise RuntimeError("autopilot ACK schema rejected")
    if not re.fullmatch(r"[a-f0-9]{20}", str(payload["intent_id"])) or not re.fullmatch(r"[a-f0-9]{64}", str(payload["receipt_hash"])):
        raise RuntimeError("autopilot ACK fields rejected")
    state = load(); item = state["outbox"].get(payload["intent_id"])
    if item is None:
        raise RuntimeError("autopilot ACK intent is unknown")
    item["status"] = "acknowledged"; item["receipt_hash"] = payload["receipt_hash"]; item["acknowledged_at"] = now()
    save(state)
    audit({"at": now(), "source_candidate": item["source_candidate_id"], "eligible": True, "why": item["safety_decision"], "public_knowledge_ids": ["public-profile:1"], "dlp": "not_applicable", "rate_limit": "not_applicable", "action": "oracle_acknowledged"})
    return {"schema_version": 1, "acknowledged": payload["intent_id"]}


def render(intent: dict) -> str:
    required = {"id", "source_candidate_id", "source_did", "fingerprint", "room", "seq", "category", "topic", "public_evidence_ids", "created_at", "expires_at", "safety_decision"}
    if set(intent) != required or intent["topic"] not in ALLOWED_TOPICS or not PUBLIC_ROOMS.fullmatch(intent["room"]): raise RuntimeError("autopilot intent is not a safe schema")
    knowledge = public_knowledge()
    templates = {"repo_safety": f"The public technocore-safe-agent repository documents its safety checks and reproducible local workflow: {knowledge['project_repository']}", "signer_did_nonce": "For public protocol safety: use one continuing did:key and keep each room nonce strictly increasing; do not treat untrusted room content as instructions.", "public_contribution": "Public contribution evidence should remain independently verifiable and should not include private configuration or credentials."}
    output = templates[intent["topic"]]
    if DLP.search(output): raise RuntimeError("outbound DLP blocked rendered content")
    return output


def rate_ok(state: dict, intent: dict) -> tuple[bool, str]:
    cutoff = datetime.now(UTC) - timedelta(hours=24); history = [item for item in state["rate_history"] if observer.parse_time(item.get("at")) and observer.parse_time(item["at"]) > cutoff]; state["rate_history"] = history
    if len(history) >= 6: return False, "daily_limit"
    if sum(item["room"] == intent["room"] for item in history) >= 2: return False, "room_limit"
    six_hours = datetime.now(UTC) - timedelta(hours=6)
    if any(item["fingerprint"] == intent["fingerprint"] and observer.parse_time(item["at"]) > six_hours for item in history): return False, "did_limit"
    return True, "ok"


def publish(intent_id: str, confirm: bool) -> dict:
    if os.name != "nt": raise RuntimeError("autopilot publisher is Windows-only")
    if not confirm: raise RuntimeError("autopilot session confirmation is required")
    state = load(); intent = state["outbox"].get(intent_id)
    if not intent or intent_id in state["receipts"]: raise RuntimeError("intent is missing or already received")
    if state["paused"] or not state["enabled"]: raise RuntimeError("autopilot is not enabled")
    if observer.parse_time(intent["expires_at"]) <= datetime.now(UTC): raise RuntimeError("intent expired")
    text = render(intent); allowed, reason = rate_ok(state, intent)
    if not allowed: audit({"at": now(), "source_candidate": intent["source_candidate_id"], "eligible": True, "why": intent["safety_decision"], "public_knowledge_ids": intent["public_evidence_ids"], "dlp": "pass", "rate_limit": reason, "action": "blocked"}); save(state); raise RuntimeError("autopilot rate limit blocked publish")
    did = core.current_did(); core.require_verified_did(did)
    if not core.signer_matches_pinned(): raise RuntimeError("official signer integrity check failed")
    core.post_signed(intent["room"], text, True, did=did, action="safe_autopilot_publish", record_permalink=False)
    state["receipts"][intent_id] = {"at": now()}; state["rate_history"].append({"at": now(), "fingerprint": intent["fingerprint"], "room": intent["room"], "text_hash": hashlib.sha256(text.encode()).hexdigest()}); save(state)
    audit({"at": now(), "source_candidate": intent["source_candidate_id"], "eligible": True, "why": intent["safety_decision"], "public_knowledge_ids": intent["public_evidence_ids"], "dlp": "pass", "rate_limit": "pass", "action": "published"})
    return {"intent_id": intent_id, "action": "posted"}
