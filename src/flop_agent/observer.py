"""Read-only, async, restart-safe Technocore observer.

No signing, POST, shell, command execution, or URL-following code is present here.
All network strings stay bounded untrusted data.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import signal
import shutil
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from urllib.parse import quote

import httpx

from . import core

SCHEMA_VERSION = 2
CONFIG_NAME, STATE_NAME, HEARTBEAT_NAME, LOCK_NAME, LOG_NAME = "observer-config.json", "observer-state.json", "observer-heartbeat.json", "observer.lock", "observer.log"
DEFAULT_CONFIG = {"schema_version": SCHEMA_VERSION, "watch_rooms": [], "mailbox": None, "poll_interval_seconds": 15, "long_poll_seconds": 10, "memory_retention": 8, "max_agents": 5000, "max_rooms": 200, "max_discovered_rooms": 1000, "state_flush_interval_seconds": 30, "log_max_bytes": 262144, "log_rotations": 2, "read_budget_per_minute": 30, "room_intervals_seconds": {"lobby": 3, "events": 10, "mailbox": 5, "watch": 15}, "repeat_after_seconds": 3600, "discovery_sample_limit": 5, "discovery_queue_limit": 500, "discovery_max_attempts": 5, "rooms_backfill_interval_seconds": 3600}
URL_RE = re.compile(r"https://[^\s<>()\[\]]+", re.I)
QUESTION_RE = re.compile(r"[?？]|\b(how|question|please)\b", re.I)
HELP_RE = re.compile(r"\b(help|assist|stuck)\b", re.I)
COLLAB_RE = re.compile(r"\b(collab|collaboration|together|looking for|partner)\b", re.I)
CONTRIBUTION_RE = re.compile(r"\b(contribution|contribute|build|project|feedback|share)\b", re.I)
CREATED_ROOM_RE = re.compile(r"^created ([a-z0-9][a-z0-9_-]{0,47})$")


def now() -> str: return datetime.now(UTC).isoformat()
def observer_dir() -> Path: core.STATE.mkdir(exist_ok=True); return core.STATE / "observer"
def config_path() -> Path: return observer_dir() / CONFIG_NAME
def state_path() -> Path: return observer_dir() / STATE_NAME
def heartbeat_path() -> Path: return observer_dir() / HEARTBEAT_NAME


def atomic_json_write(path: Path, value: dict, *, compact: bool = False, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False)
    try:
        with handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, **({"separators": (",", ":")} if compact else {"indent": 2})); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.replace(handle.name, path)
        if mode is not None: os.chmod(path, mode)
    finally:
        if os.path.exists(handle.name): os.unlink(handle.name)


def default_state() -> dict:
    return {"schema_version": SCHEMA_VERSION, "created_at": now(), "updated_at": now(), "compaction_acknowledged": True, "cursors": {}, "bootstrap_tails": {}, "agents": {}, "rooms": {}, "discovery_queue": [], "discovered_rooms": {}, "opportunities": [], "event_ids": [], "returning_dids": [], "error_history": [], "health": {"current": "ok", "rooms": {}}, "metrics": {"unique_dids_discovered": 0, "returning_did_encounters": 0, "unique_returning_dids": 0, "self_messages": 0, "rooms_observed": 0, "questions_detected": 0, "help_candidates": 0, "collab_candidates": 0, "contribution_candidates": 0, "inbound_mailbox_messages": 0, "message_gaps": 0, "estimated_missing_messages": 0, "discovery_queue_dropped": 0, "discovery_samples": 0}}


def read_json(path: Path, *, default: dict | None = None) -> dict:
    if not path.exists():
        if default is None: raise RuntimeError(f"observer file is missing: {path.name}")
        return default
    try: value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error: raise RuntimeError(f"observer state is corrupt; refusing to continue: {path.name}") from error
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION: raise RuntimeError(f"observer state schema is invalid; refusing to continue: {path.name}")
    return value


def load_config() -> dict:
    if not config_path().exists(): atomic_json_write(config_path(), DEFAULT_CONFIG)
    raw = read_json(config_path())
    legacy_default = {**DEFAULT_CONFIG, "memory_retention": 50}
    legacy_default.pop("state_flush_interval_seconds")
    old_auto = {key: value for key, value in legacy_default.items() if key != "rooms_backfill_interval_seconds"}
    old_auto["discovery_queue_limit"] = 100
    previous_auto = {**old_auto, "discovery_queue_limit": 500}
    if raw in (old_auto, previous_auto, legacy_default):
        raw["discovery_queue_limit"] = 500
        raw["memory_retention"] = DEFAULT_CONFIG["memory_retention"]
        raw["state_flush_interval_seconds"] = DEFAULT_CONFIG["state_flush_interval_seconds"]
        atomic_json_write(config_path(), raw)
    config = {**DEFAULT_CONFIG, **raw}
    try:
        rooms_ok = isinstance(config["watch_rooms"], list) and all(core.validate_room(room) == room for room in config["watch_rooms"])
        mailbox_ok = config["mailbox"] is None or core.validate_room(config["mailbox"]) == config["mailbox"]
    except (KeyError, TypeError, ValueError) as error: raise RuntimeError("observer config room settings are invalid") from error
    if not rooms_ok or not mailbox_ok: raise RuntimeError("observer config room settings are invalid")
    for key, low, high in (("poll_interval_seconds", 1, 3600), ("long_poll_seconds", 0, 10), ("memory_retention", 1, 500), ("max_agents", 100, 5000), ("max_rooms", 10, 1000), ("max_discovered_rooms", 100, 2000), ("state_flush_interval_seconds", 5, 3600), ("log_max_bytes", 1024, 10485760), ("log_rotations", 0, 10), ("read_budget_per_minute", 1, 600), ("repeat_after_seconds", 1, 31536000), ("discovery_sample_limit", 0, 50), ("discovery_queue_limit", 1, 1000), ("discovery_max_attempts", 1, 20), ("rooms_backfill_interval_seconds", 60, 86400)):
        if not isinstance(config.get(key), int) or not low <= config[key] <= high: raise RuntimeError(f"observer config {key} is invalid")
    intervals = config.get("room_intervals_seconds")
    if not isinstance(intervals, dict) or set(intervals) != {"lobby", "events", "mailbox", "watch"} or not all(isinstance(v, int) and 1 <= v <= 3600 for v in intervals.values()): raise RuntimeError("observer config room_intervals_seconds is invalid")
    return config


def _agent_priority(agent: dict) -> tuple[int, datetime, int]:
    facts, inference = agent.get("facts", {}), agent.get("inferences", {})
    important = bool(facts.get("interaction_with_us") or inference.get("repeat_seen") or inference.get("contribution_url_candidates") or inference.get("role_candidates"))
    return (1 if important else 0, parse_time(facts.get("last_seen")) or datetime.min.replace(tzinfo=UTC), int(facts.get("seen_count", 0)))


def _trim_mapping(mapping: dict, limit: int, *, priority) -> bool:
    if len(mapping) <= limit: return False
    for key, _ in sorted(mapping.items(), key=lambda item: priority(item[1]))[:len(mapping) - limit]: del mapping[key]
    return True


def compact_state(state: dict, memory_retention: int, *, max_agents: int | None = None, max_rooms: int | None = None, max_discovered_rooms: int | None = None, evict: bool = False) -> bool:
    """Bound only volatile agent-memory fields; retain identity and durable facts."""
    changed = False
    for agent in state.get("agents", {}).values():
        if not isinstance(agent, dict): continue
        facts, inferences = agent.get("facts"), agent.get("inferences")
        if isinstance(facts, dict):
            for field in ("message_refs", "recent_messages"):
                entries = facts.get(field)
                if isinstance(entries, list) and len(entries) > memory_retention:
                    facts[field] = entries[-memory_retention:]; changed = True
            messages = facts.get("recent_messages")
            if isinstance(messages, list):
                for message in messages:
                    if isinstance(message, dict) and isinstance(message.get("text"), str):
                        bounded = excerpt(message["text"])
                        if bounded != message["text"]: message["text"] = bounded; changed = True
        if isinstance(inferences, dict):
            urls = inferences.get("contribution_url_candidates")
            if isinstance(urls, list):
                bounded_urls = [excerpt(url) for url in urls[-memory_retention:] if isinstance(url, str)]
                if urls != bounded_urls: inferences["contribution_url_candidates"] = bounded_urls; changed = True
    if evict:
        for agent in state.get("agents", {}).values():
            facts, inferences = agent.get("facts", {}), agent.get("inferences", {})
            if isinstance(inferences, dict) and isinstance(inferences.get("role_candidates"), list) and len(inferences["role_candidates"]) > 8:
                inferences["role_candidates"] = inferences["role_candidates"][-8:]; changed = True
            if isinstance(facts, dict) and isinstance(facts.get("rooms"), list) and len(facts["rooms"]) > 16:
                facts["rooms"] = facts["rooms"][-16:]; changed = True
        if max_agents is not None: changed = _trim_mapping(state.get("agents", {}), max_agents, priority=lambda agent: _agent_priority(agent)) or changed
        if max_rooms is not None: changed = _trim_mapping(state.get("rooms", {}), max_rooms, priority=lambda room: parse_time(room.get("last_seen")) or datetime.min.replace(tzinfo=UTC)) or changed
        if max_discovered_rooms is not None:
            rooms = state.get("discovered_rooms", {})
            protected = {name for name, record in rooms.items() if isinstance(record, dict) and record.get("sample_status") == "queued"}
            excess = max(0, len(rooms) - max_discovered_rooms)
            for name, _ in sorted(((name, record) for name, record in rooms.items() if name not in protected), key=lambda item: parse_time(item[1].get("sampled_at") or item[1].get("enqueued_at")) or datetime.min.replace(tzinfo=UTC))[:excess]:
                del rooms[name]; changed = True
        if len(state.get("returning_dids", [])) > 1000: state["returning_dids"] = state["returning_dids"][-1000:]; changed = True
    return changed


def load_state(memory_retention: int | None = None) -> dict:
    existed = state_path().exists(); state = read_json(state_path(), default=default_state())
    defaults = default_state()
    if existed and "compaction_acknowledged" not in state: state["compaction_acknowledged"] = False
    for key, value in defaults.items(): state.setdefault(key, value)
    for key, value in defaults["metrics"].items(): state["metrics"].setdefault(key, value)
    compact_state(state, memory_retention if memory_retention is not None else load_config()["memory_retention"])
    return state
def write_heartbeat(state: dict) -> None:
    atomic_json_write(heartbeat_path(), {"schema_version": 1, "updated_at": state["updated_at"], "status": state.get("health", {}).get("current", "degraded"), "agent_count": len(state.get("agents", {}))}, compact=True)


def save_state(state: dict) -> None:
    state["updated_at"] = now(); atomic_json_write(state_path(), state, compact=True); write_heartbeat(state)


class StateWriter:
    """Single bounded writer for the daemon's shared observer state."""
    def __init__(self, state: dict, interval_seconds: int, config: dict | None = None) -> None:
        self.state, self.interval_seconds, self.config, self.dirty, self.write_count = state, interval_seconds, config, False, 0
    def mark_dirty(self) -> None: self.dirty = True
    def flush(self) -> None:
        if self.dirty:
            config = self.config or load_config()
            compact_state(self.state, config["memory_retention"], max_agents=config["max_agents"], max_rooms=config["max_rooms"], max_discovered_rooms=config["max_discovered_rooms"], evict=bool(self.state.get("compaction_acknowledged")))
            save_state(self.state); self.dirty = False; self.write_count += 1
    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try: await asyncio.wait_for(stop.wait(), timeout=self.interval_seconds)
            except TimeoutError: pass
            self.flush()
        self.flush()


def _state_counts(state: dict) -> dict:
    return {"agents": len(state.get("agents", {})), "rooms": len(state.get("rooms", {})), "discovered_rooms": len(state.get("discovered_rooms", {})), "opportunities": len(state.get("opportunities", [])), "event_ids": len(state.get("event_ids", [])), "errors": len(state.get("error_history", []))}


def _estimated_compact_size(state: dict) -> int:
    path = state_path(); path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=".compact-estimate.", suffix=".tmp", delete=False) as handle:
        name = handle.name; json.dump(state, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":")); handle.flush(); os.fsync(handle.fileno())
    try: return os.path.getsize(name)
    finally: os.unlink(name)


def compact_persisted_state(apply: bool = False) -> dict:
    """Explicitly compact a legacy state; apply always creates a unique backup first."""
    path = state_path()
    if not path.is_file(): raise RuntimeError("observer state is missing")
    before_bytes = path.stat().st_size; state, config = load_state(), load_config(); before = _state_counts(state)
    compact_state(state, config["memory_retention"], max_agents=config["max_agents"], max_rooms=config["max_rooms"], max_discovered_rooms=config["max_discovered_rooms"], evict=True)
    state["compaction_acknowledged"] = True
    result = {"dry_run": not apply, "before": {"bytes": before_bytes, **before}, "after": {"estimated_bytes": _estimated_compact_size(state), **_state_counts(state)}, "backup": None}
    if not apply: return result
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"); backup = path.with_name(f"{STATE_NAME}.backup-{stamp}")
    try:
        with path.open("rb") as source, backup.open("xb") as target: shutil.copyfileobj(source, target)
    except FileExistsError as error: raise RuntimeError("observer backup already exists; refusing to overwrite") from error
    save_state(state); result["dry_run"] = False; result["backup"] = str(backup); result["after"]["bytes"] = path.stat().st_size
    return result


def verified_did() -> str | None:
    path = core.STATE / "verified-did.json"
    try: did = json.loads(path.read_text("utf-8")).get("did") if path.exists() else None
    except (OSError, json.JSONDecodeError): did = None
    return did if isinstance(did, str) and did.startswith("did:key:") else None


def discovered_mailbox(did: str | None) -> str | None:
    """Select only newest completed plan metadata for the verified public DID."""
    plans = core.STATE / "proof-plans"
    if not did or not plans.is_dir(): return None
    candidates = []
    for path in plans.glob("*.json"):
        try: plan = json.loads(path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError): continue
        mailbox, checkpoint = plan.get("mailbox"), plan.get("checkpoints", {}).get("mailbox", {})
        if plan.get("did") == did and checkpoint.get("state") == "complete" and isinstance(mailbox, str) and re.fullmatch(r"mb-p-[a-f0-9]{32}", mailbox): candidates.append((str(plan.get("created_at", "")), mailbox))
    return max(candidates)[1] if candidates else None


def selected_mailbox(config: dict) -> str | None: return config["mailbox"] or discovered_mailbox(verified_did())
def observed_rooms(config: dict) -> list[str]:
    mailbox = selected_mailbox(config); return list(dict.fromkeys(["events", "lobby", *([mailbox] if mailbox else []), *config["watch_rooms"]]))


class ObserverLock:
    """OS-level advisory lock; crashes release it automatically on Windows/Linux."""
    def __init__(self) -> None: self.path, self.handle = observer_dir() / LOCK_NAME, None
    def __enter__(self) -> "ObserverLock":
        self.path.parent.mkdir(parents=True, exist_ok=True); self.handle = self.path.open("a+", encoding="utf-8")
        try:
            if os.name == "nt":
                import msvcrt
                self.handle.seek(0)
                if not self.handle.read(1): self.handle.write(" "); self.handle.flush()
                self.handle.seek(0); msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as error:
            self.handle.close(); self.handle = None; raise RuntimeError("observer is already running") from error
        self.handle.seek(0); self.handle.truncate(); json.dump({"pid": os.getpid(), "started_at": now()}, self.handle); self.handle.flush()
        return self
    def __exit__(self, *_: object) -> None:
        if not self.handle: return
        try:
            if os.name == "nt":
                import msvcrt
                self.handle.seek(0); msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally: self.handle.close(); self.handle = None


def append_log(config: dict, record: dict) -> None:
    path, limit, rotations = observer_dir() / LOG_NAME, config["log_max_bytes"], config["log_rotations"]
    if path.exists() and path.stat().st_size >= limit:
        for index in range(rotations, 0, -1):
            source, dest = path.with_suffix(path.suffix + f".{index}"), path.with_suffix(path.suffix + f".{index + 1}")
            if source.exists(): source.unlink() if index == rotations else os.replace(source, dest)
        os.replace(path, path.with_suffix(path.suffix + ".1")) if rotations else path.unlink()
    with path.open("a", encoding="utf-8", newline="\n") as handle: handle.write(json.dumps(record, sort_keys=True) + "\n")


def excerpt(text: str) -> str: return " ".join(text.split())[:280]
def message_did(message: dict) -> str | None:
    sender = message.get("from"); return sender if isinstance(sender, str) and sender.startswith("did:key:") else None
def event_id(kind: str, room: str, seq: int | None, did: str | None, extra: dict | None = None) -> str: return hashlib.sha256(f"{kind}|{room}|{seq}|{did}|{json.dumps(extra or {}, sort_keys=True)}".encode()).hexdigest()[:32]


def emit_event(state: dict, kind: str, room: str, message: dict, did: str | None = None, *, extra: dict | None = None) -> bool:
    seq = message.get("seq") if isinstance(message.get("seq"), int) else None; identifier = event_id(kind, room, seq, did, extra)
    if identifier in state["event_ids"]: return False
    record = {"event_id": identifier, "kind": kind, "room": room, "seq": seq, "ts": message.get("ts"), "did": did, "text_excerpt": excerpt(message.get("text", "")), "untrusted": True, "observed_at": now(), **(extra or {})}
    state["event_ids"].append(identifier); del state["event_ids"][:-2000]; state["opportunities"].append(record); del state["opportunities"][:-500]
    return True
def metric_event(state: dict, metric: str, kind: str, room: str, message: dict, did: str | None = None, *, extra: dict | None = None) -> None:
    if emit_event(state, kind, room, message, did, extra=extra): state["metrics"][metric] += 1
def set_error(state: dict, room: str, kind: str, detail: str = "") -> None:
    record = {"room": room, "kind": kind, "at": now(), "detail": detail[:120]}; state["error_history"].append(record); del state["error_history"][:-100]; state["health"]["current"] = "degraded"; state["health"]["rooms"][room] = {"status": "error", **record}
def set_success(state: dict, room: str) -> None:
    state["health"]["rooms"][room] = {"status": "ok", "at": now()}; state["health"]["current"] = "degraded" if any(v.get("status") == "error" for v in state["health"]["rooms"].values()) else "ok"


def queue_public_room(state: dict, config: dict, room: str, source: str, message: dict, topic: str | None = None) -> None:
    if room.startswith("p-"): return
    try: core.validate_room(room)
    except ValueError: return
    if room in state["discovered_rooms"]: return
    if len(state["discovery_queue"]) >= config["discovery_queue_limit"]:
        metric_event(state, "discovery_queue_dropped", "discovery_queue_drop", source, message, extra={"discovered_room": room, "reason": "queue_limit"})
        return
    record = {"room": room, "event_seq": message.get("seq"), "enqueued_at": now(), "sample_status": "queued", "attempts": 0, "last_attempt_at": None, "last_error": None, "sampled_at": None, "next_attempt_at": None, "source": source, "topic_excerpt": excerpt(topic) if isinstance(topic, str) else "", "untrusted": True}
    state["discovery_queue"].append(room); state["discovered_rooms"][room] = record
    emit_event(state, "new_room", source, message, extra={"discovered_room": room, "source": source})


def queue_discovered_room(state: dict, config: dict, message: dict) -> None:
    if message.get("from") != "server": return
    match = CREATED_ROOM_RE.fullmatch(message.get("text", ""))
    if match: queue_public_room(state, config, match.group(1), "events", message)


def parse_time(value: str | None) -> datetime | None:
    try: return datetime.fromisoformat(value) if value else None
    except (TypeError, ValueError): return None


def process_message(state: dict, config: dict, room: str, message: dict, own_did: str | None, mailbox: str | None) -> None:
    if not isinstance(message.get("seq"), int) or not isinstance(message.get("text"), str): return
    did, text = message_did(message), message["text"]
    if room == "events": queue_discovered_room(state, config, message)
    if room not in state["rooms"]:
        state["rooms"][room] = {"first_seen": now(), "last_seen": now(), "message_count": 0, "signed_count": 0, "unsigned_count": 0}; metric_event(state, "rooms_observed", "new_room", room, message)
    room_state = state["rooms"][room]; room_state["last_seen"] = now(); room_state["message_count"] += 1; room_state["signed_count" if did else "unsigned_count"] += 1
    if not did: room_state["last_unsigned_seen"] = {"seq": message["seq"], "ts": message.get("ts"), "untrusted": True}; return
    if did == own_did: state["metrics"]["self_messages"] += 1; return
    fingerprint = core.did_note_location(did)[2]; agent = state["agents"].get(fingerprint)
    if agent is None:
        if len(state["agents"]) >= config["max_agents"] and state.get("compaction_acknowledged"):
            compact_state(state, config["memory_retention"], max_agents=config["max_agents"] - 1, max_rooms=config["max_rooms"], max_discovered_rooms=config["max_discovered_rooms"], evict=True)
        if len(state["agents"]) >= config["max_agents"]: return
        agent = {"did": did, "fingerprint": fingerprint, "facts": {"first_seen": now(), "last_seen": now(), "last_encounter_at": now(), "seen_count": 0, "rooms": [], "message_refs": [], "recent_messages": [], "signed_count": 0, "unsigned_count": 0, "interaction_with_us": False}, "inferences": {"contribution_url_candidates": [], "role_candidates": [], "repeat_seen": False}}; state["agents"][fingerprint] = agent; metric_event(state, "unique_dids_discovered", "new_did", room, message, did)
    else:
        previous = parse_time(agent["facts"].get("last_encounter_at"))
        if previous and (datetime.now(UTC) - previous).total_seconds() >= config["repeat_after_seconds"]:
            agent["inferences"]["repeat_seen"] = True; metric_event(state, "returning_did_encounters", "returning_did", room, message, did)
            if fingerprint not in state["returning_dids"]: state["returning_dids"].append(fingerprint); state["metrics"]["unique_returning_dids"] += 1
        agent["facts"]["last_encounter_at"] = now()
    facts, inference = agent["facts"], agent["inferences"]; facts["last_seen"] = now(); facts["seen_count"] += 1; facts["signed_count"] += 1
    if room not in facts["rooms"]: facts["rooms"].append(room)
    del facts["rooms"][:-16]
    ref = {"room": room, "seq": message["seq"], "ts": message.get("ts")}
    if ref not in facts["message_refs"]: facts["message_refs"].append(ref); facts["recent_messages"].append({**ref, "text": excerpt(text), "signed": True, "untrusted": True})
    if room == mailbox: facts["interaction_with_us"] = True; metric_event(state, "inbound_mailbox_messages", "inbound_mailbox_message", room, message, did)
    for url in URL_RE.findall(text):
        candidate = excerpt(url)
        if candidate not in inference["contribution_url_candidates"]: inference["contribution_url_candidates"].append(candidate)
    if URL_RE.search(text) or CONTRIBUTION_RE.search(text): metric_event(state, "contribution_candidates", "contribution_candidate", room, message, did)
    if COLLAB_RE.search(text): metric_event(state, "collab_candidates", "collaboration_candidate", room, message, did)
    if HELP_RE.search(text): metric_event(state, "help_candidates", "help_candidate", room, message, did)
    if QUESTION_RE.search(text): metric_event(state, "questions_detected", "question_candidate", room, message, did)
    for role in ("developer", "researcher", "writer", "designer", "operator"):
        if re.search(rf"\b{role}\b", text, re.I) and role not in inference["role_candidates"]: inference["role_candidates"].append(role)
    for field in ("message_refs", "recent_messages"): del facts[field][:-config["memory_retention"]]
    del inference["contribution_url_candidates"][:-config["memory_retention"]]


def process_payload(state: dict, config: dict, room: str, payload: dict | list, own_did: str | None, mailbox: str | None, *, bootstrap: bool) -> None:
    messages = payload.get("messages", payload if isinstance(payload, list) else [])
    if not isinstance(messages, list): set_error(state, room, "invalid_response"); return
    since, valid = state["cursors"].get(room, 0), sorted((m for m in messages if isinstance(m, dict) and isinstance(m.get("seq"), int)), key=lambda m: m["seq"])
    if bootstrap and room not in state["bootstrap_tails"]: state["bootstrap_tails"][room] = {"from_seq": valid[0]["seq"] if valid else None, "to_seq": valid[-1]["seq"] if valid else None, "returned_count": len(valid), "is_tail_only": True, "recorded_at": now()}
    previous, highest, seen = since, since, set()
    for message in valid:
        seq = message["seq"]
        if seq <= since or seq in seen: continue
        seen.add(seq)
        if not bootstrap and seq > previous + 1:
            missing = seq - previous - 1; metric_event(state, "message_gaps", "message_gap", room, message, extra={"missing_from": previous + 1, "missing_to": seq - 1, "estimated_missing": missing}); state["metrics"]["estimated_missing_messages"] += missing
        process_message(state, config, room, message, own_did, mailbox); previous, highest = seq, max(highest, seq)
    if highest > since: state["cursors"][room] = highest


class ReadBudget:
    def __init__(self, per_minute: int) -> None: self.interval, self.next_at, self.lock = 60 / per_minute, 0.0, asyncio.Lock()
    async def acquire(self) -> None:
        async with self.lock:
            delay = self.next_at - time.monotonic()
            if delay > 0: await asyncio.sleep(delay)
            self.next_at = time.monotonic() + self.interval


async def read_room(client: httpx.AsyncClient, room: str, since: int, wait: int) -> tuple[dict | list | None, float | None, str | None]:
    try:
        response = await client.get(f"{core.BASE_URL}/r/{quote(room, safe='')}", params={"format": "json", "since": since, "wait": min(max(wait, 0), 10), "limit": 200}, timeout=20)
        if response.status_code == 429:
            try: retry = max(0.0, float(response.headers.get("Retry-After", "1")))
            except ValueError: retry = 1.0
            return None, retry, "rate_limited"
        response.raise_for_status(); return response.json(), None, None
    except httpx.HTTPError as error: return None, None, type(error).__name__


async def read_rooms(client: httpx.AsyncClient) -> tuple[list[dict] | None, float | None, str | None]:
    """Read only the server's listed public-room index; never follow room topics."""
    try:
        response = await client.get(f"{core.BASE_URL}/rooms", params={"format": "json", "limit": 200}, timeout=20)
        if response.status_code == 429:
            try: retry = max(0.0, float(response.headers.get("Retry-After", "1")))
            except ValueError: retry = 1.0
            return None, retry, "rate_limited"
        response.raise_for_status()
        payload = response.json(); rooms = payload.get("rooms", payload if isinstance(payload, list) else None)
        return rooms if isinstance(rooms, list) else None, None, None if isinstance(rooms, list) else "invalid_response"
    except httpx.HTTPError as error: return None, None, type(error).__name__


async def backfill_into_state(client: httpx.AsyncClient, budget: "ReadBudget", state: dict, config: dict) -> None:
    await budget.acquire(); rooms, retry, error = await read_rooms(client)
    if error: set_error(state, "rooms", error, str(retry or "")); return
    for item in rooms or []:
        if not isinstance(item, dict) or not isinstance(item.get("room"), str) or not isinstance(item.get("last_seq"), int) or not isinstance(item.get("topic"), str): continue
        queue_public_room(state, config, item["room"], "rooms", {"seq": None, "text": item["topic"]}, item["topic"])
    set_success(state, "rooms")


async def discover_backfill_async(client: httpx.AsyncClient | None = None) -> dict:
    with ObserverLock():
        config, state, owned = load_config(), load_state(), client is None
        if owned: client = httpx.AsyncClient()
        try:
            await backfill_into_state(client, ReadBudget(config["read_budget_per_minute"]), state, config)
            save_state(state); return observer_status(config, state)
        finally:
            if owned: await client.aclose()


def discover_backfill() -> dict: return asyncio.run(discover_backfill_async())


async def snapshot_room(client: httpx.AsyncClient, budget: ReadBudget, state: dict, config: dict, room: str, own_did: str | None, mailbox: str | None) -> None:
    await budget.acquire(); payload, retry, error = await read_room(client, room, state["cursors"].get(room, 0), 0)
    if error: set_error(state, room, error, str(retry or "")); return
    process_payload(state, config, room, payload or {}, own_did, mailbox, bootstrap=room not in state["cursors"]); set_success(state, room)


async def consume_discovery_queue(client: httpx.AsyncClient, budget: ReadBudget, state: dict, config: dict, own_did: str | None, mailbox: str | None) -> None:
    """Sample queued public rooms once; acknowledge only a successful read."""
    candidates = list(state["discovery_queue"][:config["discovery_sample_limit"]])
    for room in candidates:
        record = state["discovered_rooms"].get(room)
        if not record or record.get("sample_status") != "queued":
            if room in state["discovery_queue"]: state["discovery_queue"].remove(room)
            continue
        next_attempt = parse_time(record.get("next_attempt_at"))
        if next_attempt and datetime.now(UTC) < next_attempt: continue
        record["attempts"] += 1; record["last_attempt_at"] = now()
        await budget.acquire(); payload, retry, error = await read_room(client, room, state["cursors"].get(room, 0), 0)
        if error:
            record["last_error"] = error
            delay = retry if retry is not None else min(300.0, float(2 ** min(record["attempts"], 8)))
            record["next_attempt_at"] = (datetime.now(UTC) + timedelta(seconds=delay)).isoformat()
            if record["attempts"] >= config["discovery_max_attempts"]:
                record["sample_status"] = "dropped"
                state["discovery_queue"].remove(room)
                metric_event(state, "discovery_queue_dropped", "discovery_queue_drop", "events", {"seq": record["event_seq"], "text": f"created {room}"}, extra={"discovered_room": room, "reason": error})
            continue
        process_payload(state, config, room, payload or {}, own_did, mailbox, bootstrap=room not in state["cursors"])
        set_success(state, room); record["sample_status"] = "sampled"; record["sampled_at"] = now(); record["last_error"] = None; record["next_attempt_at"] = None
        state["discovery_queue"].remove(room); state["metrics"]["discovery_samples"] += 1


async def observe_once_async(client: httpx.AsyncClient | None = None) -> dict:
    with ObserverLock():
        config = load_config(); state, own_did = load_state(config["memory_retention"]), verified_did(); mailbox = selected_mailbox(config); budget, owned = ReadBudget(config["read_budget_per_minute"]), client is None
        if owned: client = httpx.AsyncClient()
        try:
            await asyncio.gather(*(snapshot_room(client, budget, state, config, room, own_did, mailbox) for room in observed_rooms(config)))
            await consume_discovery_queue(client, budget, state, config, own_did, mailbox)
            save_state(state)
            append_log(config, {"kind": "snapshot_complete", "at": state["updated_at"]})
            return observer_status(config, state)
        finally:
            if owned: await client.aclose()


def observe_once() -> dict: return asyncio.run(observe_once_async())
def room_interval(config: dict, room: str, mailbox: str | None) -> int: return config["room_intervals_seconds"]["lobby" if room == "lobby" else "events" if room == "events" else "mailbox" if room == mailbox else "watch"]


async def room_worker(client: httpx.AsyncClient, budget: ReadBudget, state: dict, config: dict, room: str, own_did: str | None, mailbox: str | None, stop: asyncio.Event, writer: StateWriter | None = None) -> None:
    backoff = 0.0
    while not stop.is_set():
        await budget.acquire(); payload, retry, error = await read_room(client, room, state["cursors"].get(room, 0), config["long_poll_seconds"])
        if error: set_error(state, room, error, str(retry or "")); backoff = retry if retry is not None else min(300.0, max(1.0, backoff * 2 or 1.0))
        else: process_payload(state, config, room, payload or {}, own_did, mailbox, bootstrap=room not in state["cursors"]); set_success(state, room); backoff = 0.0
        if writer: writer.mark_dirty()
        try: await asyncio.wait_for(stop.wait(), timeout=backoff or room_interval(config, room, mailbox))
        except TimeoutError: pass


async def discovery_worker(client: httpx.AsyncClient, budget: ReadBudget, state: dict, config: dict, own_did: str | None, mailbox: str | None, stop: asyncio.Event, writer: StateWriter | None = None) -> None:
    while not stop.is_set():
        await consume_discovery_queue(client, budget, state, config, own_did, mailbox)
        if writer: writer.mark_dirty()
        try: await asyncio.wait_for(stop.wait(), timeout=config["poll_interval_seconds"])
        except TimeoutError: pass


async def backfill_worker(client: httpx.AsyncClient, budget: ReadBudget, state: dict, config: dict, stop: asyncio.Event, writer: StateWriter | None = None) -> None:
    while not stop.is_set():
        await backfill_into_state(client, budget, state, config)
        if writer: writer.mark_dirty()
        try: await asyncio.wait_for(stop.wait(), timeout=config["rooms_backfill_interval_seconds"])
        except TimeoutError: pass


async def resident_worker(config: dict, stop: asyncio.Event, state: dict | None = None) -> None:
    """Local-only candidate refresh; deliberately has no network client."""
    from . import resident
    while not stop.is_set():
        try:
            resident.refresh(observed_state=state)
            from . import autopilot
            autopilot.build_outbox()
        except RuntimeError: pass
        try: await asyncio.wait_for(stop.wait(), timeout=resident.load_config()["refresh_interval_seconds"])
        except TimeoutError: pass


async def observe_forever_async(stop: asyncio.Event | None = None, client: httpx.AsyncClient | None = None) -> None:
    stop = stop or asyncio.Event()
    with ObserverLock():
        config = load_config(); state, own_did = load_state(config["memory_retention"]), verified_did(); mailbox = selected_mailbox(config); budget, owned = ReadBudget(config["read_budget_per_minute"]), client is None
        if owned: client = httpx.AsyncClient()
        writer = StateWriter(state, config["state_flush_interval_seconds"], config); writer.mark_dirty()
        writer_task = asyncio.create_task(writer.run(stop))
        try:
            tasks = [asyncio.create_task(room_worker(client, budget, state, config, room, own_did, mailbox, stop, writer)) for room in observed_rooms(config)]
            tasks.append(asyncio.create_task(discovery_worker(client, budget, state, config, own_did, mailbox, stop, writer)))
            tasks.append(asyncio.create_task(backfill_worker(client, budget, state, config, stop, writer)))
            tasks.append(asyncio.create_task(resident_worker(config, stop, state)))
            try: await asyncio.gather(*tasks)
            finally:
                stop.set()
                for task in tasks: task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                await writer_task
        finally:
            if owned: await client.aclose()


def observe_forever(stop: Event | None = None) -> None:
    async_stop = asyncio.Event()
    def request_stop(*_: object) -> None: async_stop.set()
    previous = {}
    for number in (signal.SIGINT, signal.SIGTERM):
        try: previous[number] = signal.signal(number, request_stop)
        except (OSError, ValueError): pass
    try:
        if not (stop and stop.is_set()): asyncio.run(observe_forever_async(async_stop))
    finally:
        for number, handler in previous.items(): signal.signal(number, handler)


def observer_status(config: dict | None = None, state: dict | None = None) -> dict:
    config, state = config or load_config(), state or load_state()
    return {"read_only": True, "schema_version": SCHEMA_VERSION, "rooms": observed_rooms(config), "cursors": state["cursors"], "metrics": state["metrics"], "agent_count": len(state["agents"]), "health": state["health"], "error_history": state["error_history"]}
def list_agents() -> dict:
    state = load_state(); return {"agents": [{"fingerprint": fp, "did": agent["did"], "facts": {k: v for k, v in agent["facts"].items() if k != "recent_messages"}, "inferences": agent["inferences"]} for fp, agent in state["agents"].items()]}
def get_agent(identifier: str) -> dict:
    for fp, agent in load_state()["agents"].items():
        if identifier in (fp, agent["did"]): return {"untrusted_data": True, "agent": agent}
    raise RuntimeError("agent was not found")


def intelligence_report() -> dict:
    """Summarize local observer facts only; this function performs no network access."""
    state, own_did = load_state(), verified_did()
    rooms = state["discovered_rooms"]
    discovery = {status: sum(1 for record in rooms.values() if record.get("sample_status") == status) for status in ("sampled", "queued", "dropped")}
    discovery["retrying"] = sum(1 for record in rooms.values() if record.get("sample_status") == "queued" and record.get("last_error"))
    drop_reasons: dict[str, int] = {}
    for record in state["opportunities"]:
        if record["kind"] == "discovery_queue_drop": drop_reasons[record.get("reason", "unknown")] = drop_reasons.get(record.get("reason", "unknown"), 0) + 1
    grouped: dict[tuple, dict] = {}
    reportable = {"question_candidate", "help_candidate", "collaboration_candidate", "contribution_candidate", "inbound_mailbox_message", "new_did", "returning_did", "new_room", "message_gap"}
    for record in state["opportunities"]:
        if record["kind"] not in reportable: continue
        key = (record["room"], record.get("seq"), record.get("did"), record.get("discovered_room") if record["kind"] == "new_room" else None)
        group = grouped.setdefault(key, {"room": record["room"], "seq": record.get("seq"), "did": record.get("did"), "discovered_room": record.get("discovered_room"), "kinds": [], "text_excerpt": record["text_excerpt"], "untrusted": True})
        if record["kind"] not in group["kinds"]: group["kinds"].append(record["kind"])
    signals_by_did: dict[str, set[str]] = {}
    for group in grouped.values():
        if group["did"] and group["did"] != own_did: signals_by_did.setdefault(group["did"], set()).update(group["kinds"])
    agents = []
    for agent in state["agents"].values():
        if agent["did"] == own_did: continue
        facts, inference, factors = agent["facts"], agent["inferences"], []
        if len(facts["rooms"]) > 1: factors.append({"signal": "multiple_rooms", "fact": len(facts["rooms"])})
        if inference["repeat_seen"]: factors.append({"signal": "returning_encounter", "fact": True})
        for kind, label in (("collaboration_candidate", "collaboration_candidate"), ("help_candidate", "help_interaction"), ("contribution_candidate", "contribution_candidate"), ("inbound_mailbox_message", "inbound_interaction")):
            if kind in signals_by_did.get(agent["did"], set()): factors.append({"signal": label, "fact": True})
        if inference["role_candidates"]: factors.append({"signal": "role_evidence", "inference": inference["role_candidates"]})
        agents.append({"did": agent["did"], "fingerprint": agent["fingerprint"], "facts": {"rooms": facts["rooms"], "first_seen": facts["first_seen"], "last_seen": facts["last_seen"], "interaction_with_us": facts["interaction_with_us"]}, "inferences": {"roles": inference["role_candidates"], "contribution_url_candidates": inference["contribution_url_candidates"]}, "score": {"value": len(factors), "factors": factors}, "untrusted": True})
    agents.sort(key=lambda item: (-item["score"]["value"], item["fingerprint"]))
    return {"read_only": True, "health": state["health"], "facts": {"observed_unique_external_dids": state["metrics"]["unique_dids_discovered"], "rooms_observed": state["metrics"]["rooms_observed"], "discovery": {**discovery, "drop_reasons": drop_reasons}, "returning_dids": state["metrics"]["unique_returning_dids"], "inbound_mailbox": state["metrics"]["inbound_mailbox_messages"], "questions": state["metrics"]["questions_detected"], "help": state["metrics"]["help_candidates"], "collaboration": state["metrics"]["collab_candidates"], "contribution": state["metrics"]["contribution_candidates"], "message_gaps": state["metrics"]["message_gaps"]}, "opportunities": list(grouped.values())[-20:], "interesting_agents": agents[:20]}
def opportunities() -> dict:
    state = load_state(); return {"untrusted_data": True, "opportunities": state["opportunities"], "metrics": state["metrics"]}
