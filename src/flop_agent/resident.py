"""Seedless Resident Agent quality, relationship, and approval state.

This module is local-only. It never fetches URLs, invokes a shell, or writes to
Technocore. Publishing is explicitly delegated to the existing Windows signer path.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import conversation_planner, core, observer

SCHEMA_VERSION = 1
STATE_FILE = "resident-state.json"
CONFIG_FILE = "resident-config.json"
DEFAULT_CONFIG = {"schema_version": SCHEMA_VERSION, "candidate_cooldown_seconds": 21600, "candidate_ttl_seconds": 604800, "refresh_interval_seconds": 30, "discord_digest_interval_seconds": 3600, "generic_templates": ["notic(ed|ing) your", "notic(ed|ing) recent activity", "curious if", "collaboration synergy"], "quality_threshold": 0.35}
REJECT_REASONS = {"spam", "generic", "not_relevant", "wrong_agent", "bad_draft", "too_frequent", "unsafe", "other"}


def now() -> str: return datetime.now(UTC).isoformat()
def resident_dir() -> Path: observer.observer_dir().mkdir(parents=True, exist_ok=True); return observer.observer_dir()
def state_path() -> Path: return resident_dir() / STATE_FILE
def config_path() -> Path: return resident_dir() / CONFIG_FILE


def default_state() -> dict:
    return {"schema_version": SCHEMA_VERSION, "created_at": now(), "updated_at": now(), "relationships": {}, "candidates": {}, "feedback": [], "learning": {"weights": {}, "history": []}, "control": {"paused": False}, "notifications": [], "notification_times": [], "metrics": {"noise_ignored": 0}, "cached_observer": {"health": {}, "cursors": {}, "message_gaps": 0, "discovery_queue": 0, "agents_known": 0, "returning_agents": 0, "inbound": 0}, "published": [], "daemon": {"started_at": now(), "last_refresh_at": None}}


def local_json(path: Path, default: dict) -> dict:
    if not path.exists(): return default
    try: data = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error: raise RuntimeError("resident state is corrupt; refusing to continue") from error
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION: raise RuntimeError("resident state schema is invalid")
    return data


def load_config() -> dict:
    if not config_path().exists(): observer.atomic_json_write(config_path(), DEFAULT_CONFIG)
    data = local_json(config_path(), DEFAULT_CONFIG)
    config = {**DEFAULT_CONFIG, **data}
    if not isinstance(config["candidate_cooldown_seconds"], int) or not 60 <= config["candidate_cooldown_seconds"] <= 2592000: raise RuntimeError("resident cooldown config is invalid")
    if not isinstance(config["candidate_ttl_seconds"], int) or not 300 <= config["candidate_ttl_seconds"] <= 2592000: raise RuntimeError("resident ttl config is invalid")
    if not isinstance(config["refresh_interval_seconds"], int) or not 5 <= config["refresh_interval_seconds"] <= 3600: raise RuntimeError("resident refresh interval config is invalid")
    if not isinstance(config["discord_digest_interval_seconds"], int) or not 60 <= config["discord_digest_interval_seconds"] <= 86400: raise RuntimeError("Discord digest interval config is invalid")
    return config


def load_state() -> dict:
    state = local_json(state_path(), default_state())
    for key, value in default_state().items(): state.setdefault(key, value)
    return state


def save_state(state: dict) -> None: state["updated_at"] = now(); observer.atomic_json_write(state_path(), state)


def normalized(text: str) -> str: return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]", " ", text.lower())).strip()
def garbled(text: str) -> bool:
    visible = [char for char in text if not char.isspace()]
    return bool(visible) and sum(not char.isalnum() and char not in ".,!?;:/_-" for char in visible) / len(visible) > 0.45


CONCRETE_RE = re.compile(r"\b(repo|repository|issue|patch|artifact|error|test|bug|traceback|commit|pr|pull request|api|protocol)\b|https://", re.I)
POETIC_RE = re.compile(r"\b(dreams?|stories?|melodies?|patterns?|philosoph(?:y|ical)|journey|wonder|resonance)\b", re.I)


def message_frequencies(agents: list[dict]) -> dict[str, int]:
    frequencies: dict[str, int] = {}
    for agent in agents:
        for item in agent["facts"].get("recent_messages", []):
            value = normalized(item.get("text", ""))
            if value: frequencies[value] = frequencies.get(value, 0) + 1
    return frequencies


def quality(agent: dict, all_agents: list[dict], config: dict, frequencies: dict[str, int] | None = None) -> dict:
    messages = [item.get("text", "") for item in agent["facts"].get("recent_messages", [])]
    norm = [normalized(text) for text in messages if normalized(text)]
    duplicate = len(norm) - len(set(norm))
    template = sum(any(re.search(pattern, text, re.I) for pattern in config["generic_templates"]) for text in messages)
    frequencies = frequencies or message_frequencies(all_agents)
    cluster = sum(max(0, frequencies.get(value, 0) - 1) for value in set(norm))
    garbled_count = sum(garbled(text) for text in messages)
    specific = sum(bool(CONCRETE_RE.search(text)) for text in messages)
    poetic = sum(bool(POETIC_RE.search(text)) for text in messages)
    technical = [word for word in ("api", "python", "test", "protocol", "commit", "bug", "error") if any(re.search(rf"\b{word}\b", text, re.I) for text in messages)]
    continuity = bool(agent["inferences"].get("repeat_seen"))
    facts = agent["facts"]
    noise = min(1.0, (duplicate + template + poetic + garbled_count + cluster * 0.5) / max(1, len(messages)))
    score = 0.30 + min(0.08, 0.02 * max(0, len(facts.get("rooms", [])) - 1)) + (0.15 if continuity else 0) + min(0.25, 0.09 * specific) - min(0.60, 0.12 * (duplicate + template + poetic + garbled_count) + 0.04 * cluster)
    return {"generic_template_probability": min(1.0, template / max(1, len(messages))), "spam_noise_probability": noise, "useful_agent_probability": max(0.0, min(1.0, score)), "technical_depth_indicators": technical, "conversation_continuity": continuity, "artifact_evidence_indicators": specific, "concrete_evidence": bool(specific), "poetic_filler_count": poetic, "facts": {"signed_message_count": facts.get("signed_count", 0), "rooms_count": len(facts.get("rooms", [])), "encounter_count": facts.get("seen_count", 0), "unique_message_count": len(set(norm)), "duplicate_count": duplicate, "near_duplicate_cluster_count": cluster, "garbled_count": garbled_count, "inbound_to_us": facts.get("interaction_with_us", False)}}


def relationship(state: dict, agent: dict, assessment: dict) -> dict:
    record = state["relationships"].setdefault(agent["fingerprint"], {"did": agent["did"], "relationship_state": "unknown", "first_seen": agent["facts"]["first_seen"], "last_seen": agent["facts"]["last_seen"], "last_interaction": None, "rooms": [], "important_messages": [], "topics": [], "role_candidates": [], "contribution_candidates": [], "questions": [], "help_requests": [], "interaction_history": [], "our_previous_action": None, "approval_rejection_history": []})
    messages = [item.get("text", "")[:280] for item in agent["facts"].get("recent_messages", []) if item.get("text")]
    record["last_seen"] = agent["facts"]["last_seen"]; record["rooms"] = agent["facts"]["rooms"]
    record["important_messages"] = messages[-20:]
    record["topics"] = assessment["technical_depth_indicators"]
    record["questions"] = [text for text in messages if "?" in text][-20:]
    record["help_requests"] = [text for text in messages if re.search(r"\b(help|assist|support)\b", text, re.I)][-20:]
    record["role_candidates"] = agent["inferences"].get("role_candidates", []); record["contribution_candidates"] = agent["inferences"].get("contribution_url_candidates", [])
    if assessment["useful_agent_probability"] >= 0.5: record["relationship_state"] = "interesting"
    elif record["relationship_state"] == "unknown": record["relationship_state"] = "observed"
    if assessment["conversation_continuity"]: record["relationship_state"] = "recurring"
    return record


def category_for(kinds: set[str], assessment: dict) -> tuple[str, str] | None:
    if assessment["spam_noise_probability"] >= 0.45: return None
    if "inbound_mailbox_message" in kinds: return "direct_inbound", "critical"
    if "help_candidate" in kinds and assessment["concrete_evidence"]: return "help_request", "high"
    if "question_candidate" in kinds and assessment["concrete_evidence"]: return "specific_question", "high"
    if "collaboration_candidate" in kinds and assessment["useful_agent_probability"] >= 0.35: return "technical_collaboration", "medium"
    if "contribution_candidate" in kinds and assessment["useful_agent_probability"] >= 0.35: return "artifact_contribution", "medium"
    if assessment["conversation_continuity"] and assessment["useful_agent_probability"] >= 0.5: return "interesting_returning_agent", "low"
    if assessment["useful_agent_probability"] >= 0.65: return "new_high_quality_agent", "low"
    return None


def draft(agent: dict, event: dict, category: str) -> str:
    point = event.get("text_excerpt", "")[:180]
    if category == "help_request": return f"I saw your specific help request: {point}. I can share a focused observation or test result if you name the exact constraint."
    if category == "specific_question": return f"Your question mentions: {point}. I do not want to guess; what concrete result or constraint would be most useful?"
    if category == "technical_collaboration": return f"Your collaboration point is specific: {point}. A small, verifiable next step with room/sequence context would make coordination easier."
    if category == "artifact_contribution": return f"The artifact/contribution reference is noted: {point}. Please keep any claim independently verifiable without assuming identity or reward."
    return f"I noted the concrete context: {point}. I can follow up with a focused, useful observation rather than a generic greeting."


def expire_candidates(state: dict, current: datetime | None = None) -> None:
    current = current or datetime.now(UTC)
    for item in state["candidates"].values():
        if item.get("status") != "pending": continue
        expiry = observer.parse_time(item.get("expires_at"))
        if expiry and expiry <= current:
            item["status"] = "expired"; item["expired_at"] = now(); item["expiration_reason"] = "candidate_ttl_elapsed"


def cooldown_active(state: dict, did: str, current: datetime, seconds: int) -> bool:
    timestamps = []
    for item in state["candidates"].values():
        if item.get("did") == did:
            timestamps.extend(item.get(key) for key in ("published_at", "feedback_at", "created_at") if item.get(key))
    latest = max((observer.parse_time(value) for value in timestamps), default=None)
    return bool(latest and (current - latest).total_seconds() < seconds)


def write_heartbeat(state: dict, status: str = "ok") -> None:
    observer.atomic_json_write(observer.observer_dir() / "resident-heartbeat.json", {"schema_version": 1, "updated_at": now(), "last_refresh_at": state["daemon"]["last_refresh_at"], "status": status}, compact=True)


def refresh(observed_state: dict | None = None) -> dict:
    config, state = load_config(), load_state()
    current = datetime.now(UTC); expire_candidates(state, current)
    paused = bool(state["control"].get("paused"))
    if paused:
        state["daemon"]["last_refresh_at"] = now(); save_state(state); write_heartbeat(state); return resident_status(state)
    observed = observed_state if observed_state is not None else observer.load_state()
    own_did = observer.verified_did(); agents = [agent for agent in observed["agents"].values() if agent["did"] != own_did]
    frequencies = message_frequencies(agents)
    assessments = {agent["did"]: quality(agent, agents, config, frequencies) for agent in agents}
    state["metrics"]["noise_ignored"] = sum(item["spam_noise_probability"] >= 0.45 for item in assessments.values())
    state["cached_observer"] = {"health": observed["health"], "cursors": observed["cursors"], "message_gaps": observed["metrics"]["message_gaps"], "discovery_queue": len(observed["discovery_queue"]), "agents_known": len(observed["agents"]), "returning_agents": observed["metrics"]["unique_returning_dids"], "inbound": observed["metrics"]["inbound_mailbox_messages"]}
    for agent in agents: relationship(state, agent, assessments[agent["did"]])
    if paused:
        state["daemon"]["last_refresh_at"] = now(); save_state(state); return resident_status(state, observed)
    grouped: dict[tuple, list[dict]] = {}
    for event in observed["opportunities"]:
        if event.get("did") and event["did"] != own_did: grouped.setdefault((event["did"], event["room"], event.get("seq")), []).append(event)
    for (did, room, seq), events in grouped.items():
        agent = next((item for item in agents if item["did"] == did), None)
        if not agent: continue
        # A direct public message is handled by the deterministic conversation
        # planner below.  Do not let a generic opportunity consume its cooldown.
        if any(conversation_planner.plan(room=room, sender_did=did, signed=True, text=event.get("text_excerpt", ""), own_did=own_did) for event in events):
            continue
        assessment, kinds = assessments[did], {event["kind"] for event in events}
        decision = category_for(kinds, assessment)
        if not decision: continue
        category, priority = decision; candidate_id = hashlib.sha256(f"{did}|{room}|{seq}|{category}".encode()).hexdigest()[:16]
        if candidate_id in state["candidates"]: continue
        if priority != "critical" and cooldown_active(state, did, current, config["candidate_cooldown_seconds"]): continue
        event = events[0]
        candidate = {"candidate_id": candidate_id, "did": did, "fingerprint": agent["fingerprint"], "room": room, "seq": seq, "permalink": core.human_permalink(room, seq) if isinstance(seq, int) else None, "category": category, "priority": priority, "ranking_weight": float(state["learning"]["weights"].get(category, 1.0)), "why": f"{category} after quality filtering", "signals": assessment, "context": {"excerpt": event.get("text_excerpt", "")[:280], "untrusted": True}, "suggested_action": "review and optionally approve; approval does not post", "draft_reply": draft(agent, event, category), "created_at": now(), "expires_at": (current + timedelta(seconds=config["candidate_ttl_seconds"])).isoformat(), "status": "pending"}
        state["candidates"][candidate_id] = candidate
        relationship_record = state["relationships"].get(agent["fingerprint"])
        if relationship_record:
            relationship_record["interaction_history"].append({"kind": "candidate_created", "candidate_id": candidate_id, "at": now()})
            relationship_record["interaction_history"] = relationship_record["interaction_history"][-50:]
    # Public conversation is intentionally separate from heuristic opportunities:
    # only signed messages explicitly addressing our public DID are mapped to a
    # fixed topic.  The original untrusted message is never used as reply text.
    for agent in agents:
        for message in agent["facts"].get("recent_messages", []):
            plan = conversation_planner.plan(room=message.get("room", ""), sender_did=agent["did"], signed=message.get("signed") is True, text=message.get("text", ""), own_did=own_did)
            if not plan or not isinstance(message.get("seq"), int): continue
            candidate_id = hashlib.sha256(f"{agent['did']}|{message['room']}|{message['seq']}|{plan['topic']}".encode()).hexdigest()[:16]
            if candidate_id in state["candidates"] or cooldown_active(state, agent["did"], current, config["candidate_cooldown_seconds"]): continue
            assessment = assessments[agent["did"]]
            state["candidates"][candidate_id] = {"candidate_id": candidate_id, "did": agent["did"], "fingerprint": agent["fingerprint"], "room": message["room"], "seq": message["seq"], "permalink": core.human_permalink(message["room"], message["seq"]), "category": plan["category"], "priority": "medium", "ranking_weight": 1.0, "why": "signed public direct request mapped to an allowlisted topic", "signals": {"conversation_topic": plan["topic"], "direct_public_signed": True, "facts": {"inbound_to_us": False}}, "context": {"excerpt": message["text"][:280], "untrusted": True}, "suggested_action": "fixed-template reply only; no untrusted text is rendered", "draft_reply": "", "created_at": now(), "expires_at": (current + timedelta(seconds=config["candidate_ttl_seconds"])).isoformat(), "status": "pending", "safety_decision": plan["safety_decision"]}
    state["daemon"]["last_refresh_at"] = now(); save_state(state); write_heartbeat(state)
    return resident_status(state, observed)


def candidate(candidate_id: str) -> dict:
    item = load_state()["candidates"].get(candidate_id)
    if not item: raise RuntimeError("candidate was not found")
    return {"untrusted_data": True, "candidate": item}
def list_candidates() -> dict:
    refresh()
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "ignore": 0}
    items = list(load_state()["candidates"].values())
    return {"candidates": sorted(items, key=lambda item: (rank[item["priority"]] * item.get("ranking_weight", 1.0), item["created_at"]), reverse=True)}


def feedback(candidate_id: str, decision: str, reason: str | None = None) -> dict:
    if decision not in {"approved", "rejected"}: raise ValueError("invalid feedback decision")
    if decision == "rejected" and reason not in REJECT_REASONS: raise ValueError("invalid rejection reason")
    state = load_state(); item = state["candidates"].get(candidate_id)
    if not item or item["status"] != "pending": raise RuntimeError("candidate is not pending")
    item["status"] = decision; item["feedback_reason"] = reason; item["feedback_at"] = now()
    record = {"candidate_id": candidate_id, "decision": decision, "reason": reason, "at": now()}; state["feedback"].append(record)
    rel = state["relationships"].get(item["fingerprint"])
    if rel:
        rel["approval_rejection_history"].append(record); rel["our_previous_action"] = decision; rel["last_interaction"] = now(); rel["relationship_state"] = "contacted" if decision == "approved" else rel["relationship_state"]
        rel["interaction_history"].append({"kind": decision, "candidate_id": candidate_id, "at": now()}); rel["interaction_history"] = rel["interaction_history"][-50:]
    weights = state["learning"]["weights"]; old = float(weights.get(item["category"], 1.0)); delta = 0.05 if decision == "approved" else -0.05
    weights[item["category"]] = max(0.5, min(1.5, round(old + delta, 3))); state["learning"]["history"].append({"category": item["category"], "old": old, "new": weights[item["category"]], "reason": reason, "at": now()})
    save_state(state); return item
def reset_learning() -> dict:
    state = load_state(); state["learning"] = {"weights": {}, "history": []}; save_state(state); return state["learning"]
def feedback_status() -> dict:
    state = load_state(); expire_candidates(state); save_state(state); return {"learning": state["learning"], "approved": sum(item["status"] == "approved" for item in state["candidates"].values()), "rejected": sum(item["status"] == "rejected" for item in state["candidates"].values()), "expired": sum(item["status"] == "expired" for item in state["candidates"].values())}
def pause(value: bool) -> dict:
    state = load_state(); state["control"]["paused"] = value; save_state(state); return state["control"]


def resident_status(state: dict | None = None, observed: dict | None = None) -> dict:
    """Return cached state only; never refresh, score agents, or read the network."""
    state = state or load_state()
    cached = state.get("cached_observer", {})
    if observed is not None:
        cached = {"health": observed["health"], "cursors": observed["cursors"], "message_gaps": observed["metrics"]["message_gaps"], "discovery_queue": len(observed["discovery_queue"]), "agents_known": len(observed["agents"]), "returning_agents": observed["metrics"]["unique_returning_dids"], "inbound": observed["metrics"]["inbound_mailbox_messages"]}
    candidates = list(state["candidates"].values())
    return {"read_only": True, "uptime_started_at": state["daemon"]["started_at"], "health": cached.get("health", {}), "last_refresh_at": state["daemon"]["last_refresh_at"], "cursors": cached.get("cursors", {}), "message_gaps": cached.get("message_gaps", 0), "discovery_queue": cached.get("discovery_queue", 0), "agents_known": cached.get("agents_known", 0), "useful_candidates": sum(item["status"] == "pending" for item in candidates), "noise_ignored": state.get("metrics", {}).get("noise_ignored", 0), "returning_agents": cached.get("returning_agents", 0), "inbound": cached.get("inbound", 0), "approved": sum(item["status"] == "approved" for item in candidates), "rejected": sum(item["status"] == "rejected" for item in candidates), "expired": sum(item["status"] == "expired" for item in candidates), "published": len(state["published"]), "paused": state["control"]["paused"], "discord_status": "not_connected"}


def publish_approved(candidate_id: str, confirm: bool) -> dict:
    if os.name != "nt": raise RuntimeError("publish-approved is Windows secure-signer only")
    item = candidate(candidate_id)["candidate"]
    if not confirm: raise RuntimeError("publish-approved requires final confirmation")
    if observer.parse_time(item.get("expires_at")) and observer.parse_time(item["expires_at"]) <= datetime.now(UTC):
        raise RuntimeError("expired candidate cannot be published")
    if item["status"] != "approved": raise RuntimeError("candidate must be approved before publishing")
    did = core.current_did(); core.require_verified_did(did)
    record = core.post_signed(item["room"], item["draft_reply"], confirm, did=did, action="approved_candidate_publish")
    state = load_state(); state["candidates"][candidate_id]["status"] = "published"; state["candidates"][candidate_id]["published_at"] = now(); state["published"].append({"candidate_id": candidate_id, "at": now(), "permalink": record["permalink"]}); save_state(state); return record


def export_state() -> str:
    """Export a strict public-state allowlist, never arbitrary local-state files."""
    allowed = [(core.STATE / "verified-did.json", "verified-did.json"), (observer.state_path(), "observer/observer-state.json"), (observer.config_path(), "observer/observer-config.json"), (state_path(), "observer/resident-state.json"), (config_path(), "observer/resident-config.json")]
    export_dir = core.STATE / "resident-exports"; export_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"); archive = export_dir / f"resident-state-{stamp}.zip"
    manifest = []
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path, name in allowed:
            if not path.exists(): continue
            if any(word in name.lower() for word in ("seed", "secret", "credential", "private", "token")): continue
            data = path.read_bytes(); manifest.append({"name": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}); bundle.writestr(name, data)
        bundle.writestr("manifest.json", json.dumps({"schema_version": 1, "files": manifest}, indent=2))
    return str(archive)
