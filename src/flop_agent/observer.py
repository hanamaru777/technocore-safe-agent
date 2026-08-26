"""Read-only, restart-safe Technocore observer.

This module deliberately has no signing, POST, subprocess, URL-following, or command
execution paths.  Every string received from Technocore remains untrusted data.
"""
from __future__ import annotations

import json
import os
import re
import signal
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Any

import httpx

from . import core

SCHEMA_VERSION = 1
CONFIG_NAME = "observer-config.json"
STATE_NAME = "observer-state.json"
LOCK_NAME = "observer.lock"
LOG_NAME = "observer.log"
DEFAULT_CONFIG = {
    "schema_version": SCHEMA_VERSION,
    "watch_rooms": [],
    "mailbox": None,
    "poll_interval_seconds": 15,
    "long_poll_seconds": 10,
    "memory_retention": 50,
    "log_max_bytes": 262144,
    "log_rotations": 2,
}
URL_RE = re.compile(r"https://[^\s<>()\[\]]+", re.IGNORECASE)
QUESTION_RE = re.compile(r"[?？]|\b(help|how|question|please)\b", re.IGNORECASE)
COLLAB_RE = re.compile(r"\b(collab|collaboration|together|looking for|partner)\b", re.IGNORECASE)
CONTRIBUTION_RE = re.compile(r"\b(contribution|contribute|build|project|feedback|share)\b", re.IGNORECASE)


def now() -> str:
    return datetime.now(UTC).isoformat()


def observer_dir() -> Path:
    core.STATE.mkdir(exist_ok=True)
    return core.STATE / "observer"


def atomic_json_write(path: Path, value: dict) -> None:
    """Atomically replace observer-only state, never touching Phase 1/2 files."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False)
    try:
        with handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    finally:
        if os.path.exists(handle.name):
            os.unlink(handle.name)


def default_state() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "created_at": now(),
        "updated_at": now(),
        "cursors": {},
        "agents": {},
        "rooms": {},
        "opportunities": [],
        "metrics": {"unique_dids_discovered": 0, "repeat_did": 0, "rooms_observed": 0, "questions_detected": 0, "collab_candidates": 0, "contribution_candidates": 0, "inbound_mailbox_messages": 0},
        "last_error": None,
    }


def read_json(path: Path, *, default: dict | None = None) -> dict:
    if not path.exists():
        if default is None:
            raise RuntimeError(f"observer file is missing: {path.name}")
        return default
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"observer state is corrupt; refusing to continue: {path.name}") from error
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError(f"observer state schema is invalid; refusing to continue: {path.name}")
    return value


def config_path() -> Path:
    return observer_dir() / CONFIG_NAME


def state_path() -> Path:
    return observer_dir() / STATE_NAME


def load_config() -> dict:
    path = config_path()
    if not path.exists():
        atomic_json_write(path, DEFAULT_CONFIG)
    config = read_json(path)
    rooms = config.get("watch_rooms")
    if not isinstance(rooms, list) or not all(isinstance(room, str) and core.validate_room(room) == room for room in rooms):
        raise RuntimeError("observer config watch_rooms is invalid")
    mailbox = config.get("mailbox")
    if mailbox is not None and (not isinstance(mailbox, str) or core.validate_room(mailbox) != mailbox):
        raise RuntimeError("observer config mailbox is invalid")
    for key, minimum, maximum in (("poll_interval_seconds", 1, 3600), ("long_poll_seconds", 0, 10), ("memory_retention", 1, 500), ("log_max_bytes", 1024, 10485760), ("log_rotations", 0, 10)):
        value = config.get(key)
        if not isinstance(value, int) or not minimum <= value <= maximum:
            raise RuntimeError(f"observer config {key} is invalid")
    return config


def load_state() -> dict:
    return read_json(state_path(), default=default_state())


def save_state(state: dict) -> None:
    state["updated_at"] = now()
    atomic_json_write(state_path(), state)


def verified_did() -> str | None:
    path = core.STATE / "verified-did.json"
    if not path.exists():
        return None
    try:
        did = json.loads(path.read_text("utf-8")).get("did")
    except (OSError, json.JSONDecodeError):
        return None
    return did if isinstance(did, str) and did.startswith("did:key:") else None


def discovered_mailbox(did: str | None) -> str | None:
    """Read public local plan metadata only; no signer and no network access."""
    if not did:
        return None
    plans = core.STATE / "proof-plans"
    if not plans.is_dir():
        return None
    for path in sorted(plans.glob("*.json"), reverse=True):
        try:
            plan = json.loads(path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        mailbox = plan.get("mailbox") if plan.get("did") == did else None
        if isinstance(mailbox, str) and re.fullmatch(r"mb-p-[a-f0-9]{32}", mailbox):
            return mailbox
    return None


def observed_rooms(config: dict) -> list[str]:
    mailbox = config["mailbox"] or discovered_mailbox(verified_did())
    return list(dict.fromkeys(["events", "lobby", *( [mailbox] if mailbox else []), *config["watch_rooms"]]))


class ObserverLock:
    def __init__(self) -> None:
        self.path = observer_dir() / LOCK_NAME
        self.acquired = False

    def __enter__(self) -> "ObserverLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self.path.open("x", encoding="utf-8") as handle:
                json.dump({"pid": os.getpid(), "started_at": now()}, handle)
        except FileExistsError as error:
            raise RuntimeError("observer is already running or has an unverified stale lock") from error
        self.acquired = True
        return self

    def __exit__(self, *_: object) -> None:
        if self.acquired:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass


def append_log(config: dict, event: dict) -> None:
    path = observer_dir() / LOG_NAME
    limit, rotations = config["log_max_bytes"], config["log_rotations"]
    if path.exists() and path.stat().st_size >= limit:
        for index in range(rotations, 0, -1):
            source = path.with_suffix(path.suffix + f".{index}")
            destination = path.with_suffix(path.suffix + f".{index + 1}")
            if source.exists():
                if index == rotations:
                    source.unlink()
                else:
                    os.replace(source, destination)
        if rotations:
            os.replace(path, path.with_suffix(path.suffix + ".1"))
        else:
            path.unlink()
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")


def message_did(message: dict) -> str | None:
    sender = message.get("from")
    return sender if isinstance(sender, str) and sender.startswith("did:key:") else None


def event(state: dict, config: dict, kind: str, room: str, message: dict, did: str | None = None) -> None:
    record = {"kind": kind, "room": room, "seq": message.get("seq"), "ts": message.get("ts"), "did": did, "observed_at": now(), "untrusted": True}
    state["opportunities"].append(record)
    del state["opportunities"][:-500]
    append_log(config, record)


def process_message(state: dict, config: dict, room: str, message: dict, own_did: str | None, mailbox: str | None) -> None:
    if not isinstance(message, dict) or not isinstance(message.get("seq"), int) or not isinstance(message.get("text"), str):
        return
    did = message_did(message)
    text = message["text"]  # Data only: this is never parsed as a command or fetched as a URL.
    if room not in state["rooms"]:
        state["rooms"][room] = {"first_seen": now(), "last_seen": now(), "message_count": 0, "signed_count": 0, "unsigned_count": 0}
        state["metrics"]["rooms_observed"] += 1
        event(state, config, "new_room", room, message)
    room_state = state["rooms"][room]
    room_state["last_seen"] = now()
    room_state["message_count"] += 1
    room_state["signed_count" if did else "unsigned_count"] += 1
    if did:
        fingerprint = core.did_note_location(did)[2]
        existing = state["agents"].get(fingerprint)
        if existing is None:
            existing = {"did": did, "fingerprint": fingerprint, "facts": {"first_seen": now(), "last_seen": now(), "seen_count": 0, "rooms": [], "message_refs": [], "recent_messages": [], "signed_count": 0, "unsigned_count": 0, "interaction_with_us": False}, "inferences": {"contribution_url_candidates": [], "role_candidates": [], "repeat_seen": False}}
            state["agents"][fingerprint] = existing
            state["metrics"]["unique_dids_discovered"] += 1
            event(state, config, "new_did", room, message, did)
        else:
            existing["inferences"]["repeat_seen"] = True
            state["metrics"]["repeat_did"] += 1
            event(state, config, "repeat_did", room, message, did)
        facts = existing["facts"]
        facts["last_seen"] = now()
        facts["seen_count"] += 1
        if room not in facts["rooms"]:
            facts["rooms"].append(room)
        reference = {"room": room, "seq": message["seq"], "ts": message.get("ts")}
        if reference not in facts["message_refs"]:
            facts["message_refs"].append(reference)
            facts["recent_messages"].append({**reference, "text": text, "signed": True, "untrusted": True})
        facts["signed_count"] += 1
        if room == mailbox and did != own_did:
            facts["interaction_with_us"] = True
            state["metrics"]["inbound_mailbox_messages"] += 1
            event(state, config, "inbound_mailbox_message", room, message, did)
        inference = existing["inferences"]
        urls = URL_RE.findall(text)
        for url in urls:
            if url not in inference["contribution_url_candidates"]:
                inference["contribution_url_candidates"].append(url)
        if urls or CONTRIBUTION_RE.search(text):
            state["metrics"]["contribution_candidates"] += 1
            event(state, config, "contribution_candidate", room, message, did)
        if COLLAB_RE.search(text):
            state["metrics"]["collab_candidates"] += 1
            event(state, config, "collaboration_candidate", room, message, did)
        if QUESTION_RE.search(text):
            state["metrics"]["questions_detected"] += 1
            event(state, config, "question_candidate", room, message, did)
        for role in ("developer", "researcher", "writer", "designer", "operator"):
            if re.search(rf"\b{role}\b", text, re.IGNORECASE) and role not in inference["role_candidates"]:
                inference["role_candidates"].append(role)
        for field in ("message_refs", "recent_messages"):
            del facts[field][:-config["memory_retention"]]
    else:
        # Keep unsigned messages out of per-DID identity memory, but retain their room signal.
        state["rooms"][room]["last_unsigned_seen"] = {"seq": message["seq"], "ts": message.get("ts"), "untrusted": True}


def observe_cycle(config: dict, state: dict) -> dict:
    own_did = verified_did()
    mailbox = config["mailbox"] or discovered_mailbox(own_did)
    for room in observed_rooms(config):
        since = state["cursors"].get(room, 0)
        try:
            payload = core.read_room(room, since=since, wait=config["long_poll_seconds"], limit=200)
        except httpx.HTTPError as error:
            state["last_error"] = {"room": room, "at": now(), "kind": type(error).__name__}
            continue
        messages = payload.get("messages", payload if isinstance(payload, list) else [])
        if not isinstance(messages, list):
            state["last_error"] = {"room": room, "at": now(), "kind": "invalid_response"}
            continue
        highest, seen = since, set()
        for message in sorted(messages, key=lambda item: item.get("seq", -1) if isinstance(item, dict) else -1):
            seq = message.get("seq") if isinstance(message, dict) else None
            if not isinstance(seq, int) or seq <= since or seq in seen:
                continue
            seen.add(seq)
            process_message(state, config, room, message, own_did, mailbox)
            highest = max(highest, seq)
        if highest > since:
            state["cursors"][room] = highest
    return state


def observe_once() -> dict:
    with ObserverLock():
        config, state = load_config(), load_state()
        observe_cycle(config, state)
        save_state(state)
        return observer_status(config, state)


def observe_forever(stop: Event | None = None) -> None:
    stop = stop or Event()
    previous_handlers: dict[int, Any] = {}
    def request_stop(*_: object) -> None:
        stop.set()
    for number in (signal.SIGINT, signal.SIGTERM):
        try:
            previous_handlers[number] = signal.signal(number, request_stop)
        except (ValueError, OSError):
            pass
    try:
        with ObserverLock():
            config, state = load_config(), load_state()
            while not stop.is_set():
                observe_cycle(config, state)
                save_state(state)
                stop.wait(config["poll_interval_seconds"])
    finally:
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)


def observer_status(config: dict | None = None, state: dict | None = None) -> dict:
    config = config or load_config()
    state = state or load_state()
    return {"read_only": True, "schema_version": SCHEMA_VERSION, "rooms": observed_rooms(config), "cursors": state["cursors"], "metrics": state["metrics"], "agent_count": len(state["agents"]), "last_error": state["last_error"]}


def list_agents() -> dict:
    state = load_state()
    return {"agents": [{"fingerprint": fingerprint, "did": agent["did"], "facts": {key: value for key, value in agent["facts"].items() if key != "recent_messages"}, "inferences": agent["inferences"]} for fingerprint, agent in state["agents"].items()]}


def get_agent(identifier: str) -> dict:
    state = load_state()
    for fingerprint, agent in state["agents"].items():
        if identifier in (fingerprint, agent["did"]):
            return {"untrusted_data": True, "agent": agent}
    raise RuntimeError("agent was not found")


def opportunities() -> dict:
    state = load_state()
    return {"untrusted_data": True, "opportunities": state["opportunities"], "metrics": state["metrics"]}
