"""Versioned, local-only source registry for narrow FLOP/Technocore onboarding help.

Runtime code never fetches registry URLs or room-provided URLs.  The registry is
reviewed and pinned in Git; signed previews reuse the exact deterministic renderer
already loaded by the isolated production Signer.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import core, observer

REGISTRY_PATH = core.ROOT / "knowledge" / "registry-v1.json"
AUDIT_NAME = "knowledge-use-audit.json"
AUDIT_LIMIT = 1000
TCLK_RE = re.compile(r"\b(?:tclk|paperrail|htlc|ptlc)\b", re.I)


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    parsed = observer.parse_time(value)
    if parsed is None:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _validate_source(source: object) -> dict:
    if not isinstance(source, dict) or set(source) != {"source_id", "authority", "repo", "commit", "path"}:
        raise RuntimeError("knowledge source schema is invalid")
    if source["authority"] not in {"official", "project_approved"}:
        raise RuntimeError("knowledge source authority is invalid")
    if not isinstance(source["source_id"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,80}", source["source_id"]):
        raise RuntimeError("knowledge source id is invalid")
    if not isinstance(source["repo"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", source["repo"]):
        raise RuntimeError("knowledge source repo is invalid")
    if not isinstance(source["commit"], str) or not re.fullmatch(r"[a-f0-9]{40}", source["commit"]):
        raise RuntimeError("knowledge source commit is invalid")
    if not isinstance(source["path"], str) or not source["path"] or source["path"].startswith(("/", ".")) or ".." in Path(source["path"]).parts:
        raise RuntimeError("knowledge source path is invalid")
    return source


def load_registry() -> dict:
    try:
        data = json.loads(REGISTRY_PATH.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("knowledge registry is unavailable") from error
    if not isinstance(data, dict) or set(data) != {"schema_version", "registry_id", "checked_at", "topics"}:
        raise RuntimeError("knowledge registry schema is invalid")
    if data["schema_version"] != 1 or data["registry_id"] != "flop-onboarding-knowledge-v1" or _parse_time(data["checked_at"]) is None:
        raise RuntimeError("knowledge registry metadata is invalid")
    if not isinstance(data["topics"], dict) or not 1 <= len(data["topics"]) <= 32:
        raise RuntimeError("knowledge topic registry is invalid")
    for topic, item in data["topics"].items():
        if not re.fullmatch(r"[a-z0-9_]{2,48}", str(topic)) or not isinstance(item, dict):
            raise RuntimeError("knowledge topic schema is invalid")
        expected = {"renderer_topic", "signable", "freshness", "ttl_days", "sources"}
        if "read_only_text" in item:
            expected.add("read_only_text")
        if set(item) != expected:
            raise RuntimeError("knowledge topic fields are invalid")
        if item["freshness"] not in {"stable", "time_sensitive"} or not isinstance(item["signable"], bool):
            raise RuntimeError("knowledge topic policy is invalid")
        if item["freshness"] == "stable" and item["ttl_days"] is not None:
            raise RuntimeError("stable knowledge cannot have a ttl")
        if item["freshness"] == "time_sensitive" and (not isinstance(item["ttl_days"], int) or not 1 <= item["ttl_days"] <= 30):
            raise RuntimeError("time-sensitive knowledge ttl is invalid")
        renderer_topic = item["renderer_topic"]
        if item["signable"] and (not isinstance(renderer_topic, str) or renderer_topic != topic):
            raise RuntimeError("signable knowledge must use the existing same-id renderer")
        if not item["signable"] and renderer_topic is not None:
            raise RuntimeError("read-only knowledge must not declare a signer renderer")
        if "read_only_text" in item and (not isinstance(item["read_only_text"], str) or not item["read_only_text"] or len(item["read_only_text"]) > 700):
            raise RuntimeError("knowledge read-only answer is invalid")
        sources = item["sources"]
        if not isinstance(sources, list) or not 1 <= len(sources) <= 8:
            raise RuntimeError("knowledge sources are invalid")
        ids = [_validate_source(source)["source_id"] for source in sources]
        if len(ids) != len(set(ids)):
            raise RuntimeError("knowledge source ids must be unique per topic")
    return data


def topic_status(topic: str, *, current: datetime | None = None) -> dict:
    registry = load_registry()
    item = registry["topics"].get(topic)
    if not isinstance(item, dict):
        return {"topic": topic, "known": False, "verified": False, "reason": "topic_not_registered"}
    checked = _parse_time(registry["checked_at"])
    assert checked is not None
    current = current or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    stale = item["freshness"] == "time_sensitive" and current > checked + timedelta(days=item["ttl_days"])
    return {
        "topic": topic,
        "known": True,
        "verified": not stale,
        "reason": "stale_source" if stale else "verified",
        "registry_id": registry["registry_id"],
        "checked_at": registry["checked_at"],
        "freshness": item["freshness"],
        "ttl_days": item["ttl_days"],
        "signable": bool(item["signable"] and not stale),
        "source_ids": [source["source_id"] for source in item["sources"]],
        "sources": item["sources"],
    }


def signable_now(topic: str, *, current: datetime | None = None) -> bool:
    try:
        status = topic_status(topic, current=current)
    except RuntimeError:
        return False
    return bool(status.get("known") and status.get("verified") and status.get("signable"))


def preview(topic: str, *, current: datetime | None = None) -> str:
    status = topic_status(topic, current=current)
    if not status.get("verified"):
        raise RuntimeError("knowledge source is stale or unverified")
    registry = load_registry()
    item = registry["topics"][topic]
    if not item["signable"]:
        text = item.get("read_only_text")
        if not isinstance(text, str) or not text:
            raise RuntimeError("knowledge topic has no safe preview")
        return text

    # Import lazily to avoid a module cycle: autopilot itself consults this
    # registry as an eligibility guard.
    from . import autopilot

    now_value = current or datetime.now(UTC)
    if now_value.tzinfo is None:
        now_value = now_value.replace(tzinfo=UTC)
    intent = {
        "id": "0" * 20,
        "source_candidate_id": "knowledge-preview",
        "source_did": "did:key:public",
        "fingerprint": "0" * 16,
        "room": "lobby",
        "seq": 0,
        "category": "specific_question",
        "topic": topic,
        "public_evidence_ids": ["public-profile:1"],
        "created_at": now_value.isoformat(),
        "expires_at": (now_value + timedelta(hours=1)).isoformat(),
        "safety_decision": "concrete_public_technical_request",
    }
    return autopilot.render(intent)


def candidate_topic(candidate: dict) -> tuple[str | None, str]:
    context = candidate.get("context", {})
    text = context.get("excerpt") if isinstance(context, dict) else None
    if not isinstance(text, str) or not text.strip():
        return None, "no_candidate_excerpt"

    from . import autopilot

    if autopilot.UNSUPPORTED_PUBLIC_FACT_RE.search(text):
        return None, "unsupported_current_or_reward_fact"
    if TCLK_RE.search(text):
        return "tclk_alpha", "matched_tclk_public_status"
    resolved, reason = autopilot.resolve_candidate_topic(text)
    if resolved and resolved in load_registry()["topics"]:
        return resolved, reason
    signals = candidate.get("signals", {})
    if isinstance(signals, dict) and signals.get("conversation_topic") == "agent_use_case":
        return "agent_use_case", "signed_agent_use_case"
    return None, "no_source_backed_topic"


def candidate_knowledge(candidate: dict, *, current: datetime | None = None) -> dict:
    topic, reason = candidate_topic(candidate)
    if topic is None:
        return {"topic": None, "verified": False, "reason": reason, "preview": None, "source_ids": []}
    status = topic_status(topic, current=current)
    result = {**status, "reason": status["reason"] if not status["verified"] else reason, "preview": None}
    if status["verified"]:
        result["preview"] = preview(topic, current=current)
    return result


def audit_path() -> Path:
    return core.STATE / "knowledge" / AUDIT_NAME


def _load_audit() -> dict:
    path = audit_path()
    if not path.exists():
        return {"schema_version": 1, "records": []}
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("knowledge audit is corrupt") from error
    if not isinstance(data, dict) or set(data) != {"schema_version", "records"} or data["schema_version"] != 1 or not isinstance(data["records"], list):
        raise RuntimeError("knowledge audit schema is invalid")
    return data


def _save_audit(data: dict) -> None:
    path = audit_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    observer.atomic_json_write(path, data, mode=0o640)


def sync_acknowledged_usage() -> dict:
    """Record source provenance for acknowledged replies without touching Signer state."""
    from . import autopilot

    auto = autopilot.load()
    audit = _load_audit()
    seen = {str(record.get("intent_id")) for record in audit["records"] if isinstance(record, dict)}
    added = 0
    for intent_id, intent in auto.get("outbox", {}).items():
        if not isinstance(intent, dict) or intent_id in seen:
            continue
        if intent.get("status") != "acknowledged" and intent_id not in auto.get("receipts", {}):
            continue
        topic = str(intent.get("topic", ""))
        try:
            status = topic_status(topic)
        except RuntimeError:
            continue
        if not status.get("verified") or not status.get("signable"):
            continue
        required = {"id", "source_candidate_id", "source_did", "fingerprint", "room", "seq", "category", "topic", "public_evidence_ids", "created_at", "expires_at", "safety_decision"}
        if not required <= set(intent):
            continue
        try:
            rendered = autopilot.render({key: intent[key] for key in required})
        except RuntimeError:
            continue
        audit["records"].append({
            "intent_id": intent_id,
            "topic": topic,
            "source_ids": status["source_ids"],
            "registry_id": status["registry_id"],
            "answer_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
            "acknowledged_at": intent.get("acknowledged_at") or auto.get("receipts", {}).get(intent_id, {}).get("at"),
        })
        seen.add(intent_id)
        added += 1
    audit["records"] = audit["records"][-AUDIT_LIMIT:]
    if added:
        _save_audit(audit)
    return {"records": len(audit["records"]), "added": added}


def summary(*, current: datetime | None = None) -> dict:
    registry = load_registry()
    rows = [topic_status(topic, current=current) for topic in sorted(registry["topics"])]
    return {
        "registry_id": registry["registry_id"],
        "checked_at": registry["checked_at"],
        "topics": len(rows),
        "verified": sum(bool(row["verified"]) for row in rows),
        "signable": sum(bool(row.get("signable")) for row in rows),
        "stale": [row["topic"] for row in rows if not row["verified"]],
        "rows": rows,
    }
