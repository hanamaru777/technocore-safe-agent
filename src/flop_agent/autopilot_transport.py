"""Fixed-function seedless Oracle intent transport and Windows session publisher."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from . import autopilot, core, observer

CONFIG = "autopilot-ssh.json"
RECEIPTS = "autopilot-session-receipts.json"
INTENT_FIELDS = {"schema_version", "intent_id", "source_fingerprint", "room", "seq", "category", "topic", "public_knowledge_ids", "created_at", "expires_at", "safety_decision"}
CATEGORIES = {"help_request", "specific_question", "technical_collaboration", "artifact_contribution", "conversation", "controlled_e2e"}
TOPICS = {"repo_safety", "signer_did_nonce", "public_contribution", "did_signature", "nonce", "technocore_api", "prompt_injection_safety", "repo_tests_bugs", "contribution_artifact", "collaboration", "follow_up"}
SAFETY_DECISIONS = {"concrete_public_technical_request", "public_artifact_evidence", "proven_returning_high_quality_agent", "signed_public_direct_request", "controlled_pause_only_e2e"}


def config_path() -> Path: return core.STATE / CONFIG
def receipts_path() -> Path: return core.STATE / RECEIPTS


def load_config() -> dict:
    try: data = json.loads(config_path().read_text("utf-8"))
    except FileNotFoundError as error: raise RuntimeError("autopilot SSH config is missing") from error
    except json.JSONDecodeError as error: raise RuntimeError("autopilot SSH config is invalid") from error
    if set(data) != {"oracle_host", "ssh_user", "identity_file", "poll_interval_seconds"}: raise RuntimeError("autopilot SSH config has unsupported fields")
    if not all(isinstance(data[key], str) and data[key] for key in ("oracle_host", "ssh_user", "identity_file")): raise RuntimeError("autopilot SSH config is invalid")
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", data["oracle_host"]) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", data["ssh_user"]): raise RuntimeError("autopilot SSH host or user is invalid")
    if not re.fullmatch(r"[A-Za-z]:\\(?:[^<>:\"/\\|?*\x00-\x1f]+\\)*[^<>:\"/\\|?*\x00-\x1f]+", data["identity_file"]) or any(char in data["identity_file"] for char in "&;|`$(){}[]'\"!%"):
        raise RuntimeError("autopilot SSH identity path is invalid")
    if not isinstance(data["poll_interval_seconds"], int) or not 10 <= data["poll_interval_seconds"] <= 3600: raise RuntimeError("autopilot SSH poll interval is invalid")
    return data


def ssh_command(config: dict, operation: str) -> list[str]:
    remote = {"export": "sudo -n /usr/local/libexec/technocore-safe-agent-rpc export", "ack": "sudo -n /usr/local/libexec/technocore-safe-agent-rpc ack"}.get(operation)
    if remote is None: raise RuntimeError("unsupported fixed SSH operation")
    return ["ssh.exe", "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=10", "-i", config["identity_file"], f"{config['ssh_user']}@{config['oracle_host']}", remote]


def ssh_json(config: dict, operation: str, payload: dict | None = None) -> dict:
    try: result = subprocess.run(ssh_command(config, operation), input=json.dumps(payload) if payload else None, text=True, capture_output=True, check=False, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as error: raise RuntimeError("SSH transport failed closed") from error
    if result.returncode != 0: raise RuntimeError("SSH transport failed closed")
    try: return json.loads(result.stdout)
    except json.JSONDecodeError as error: raise RuntimeError("SSH returned invalid JSON") from error


def validate_intent(intent: dict) -> dict:
    if not isinstance(intent, dict) or set(intent) != INTENT_FIELDS or intent.get("schema_version") != 1: raise RuntimeError("autopilot transport intent schema rejected")
    if not isinstance(intent["intent_id"], str) or not re.fullmatch(r"[a-f0-9]{20}", intent["intent_id"]): raise RuntimeError("autopilot intent id rejected")
    if not isinstance(intent["source_fingerprint"], str) or not re.fullmatch(r"[a-f0-9]{16}", intent["source_fingerprint"]): raise RuntimeError("autopilot source rejected")
    if not isinstance(intent["room"], str) or not autopilot.PUBLIC_ROOMS.fullmatch(intent["room"]): raise RuntimeError("autopilot room rejected")
    if not isinstance(intent["seq"], int) or intent["seq"] < 0 or intent["category"] not in CATEGORIES or intent["topic"] not in TOPICS: raise RuntimeError("autopilot enum rejected")
    if intent["public_knowledge_ids"] != ["public-profile:1"]: raise RuntimeError("autopilot knowledge id rejected")
    if not all(isinstance(intent[key], str) and len(intent[key]) <= 128 for key in ("created_at", "expires_at")) or intent["safety_decision"] not in SAFETY_DECISIONS: raise RuntimeError("autopilot metadata rejected")
    if observer.parse_time(intent["created_at"]) is None or observer.parse_time(intent["expires_at"]) is None or observer.parse_time(intent["expires_at"]) <= datetime.now(UTC): raise RuntimeError("autopilot intent expired")
    return intent


def export_remote(config: dict | None = None) -> list[dict]:
    data = ssh_json(config or load_config(), "export")
    if set(data) != {"schema_version", "intents"} or data.get("schema_version") != 1 or not isinstance(data["intents"], list): raise RuntimeError("autopilot export schema rejected")
    return [validate_intent(item) for item in data["intents"]]


def load_receipts() -> dict:
    if not receipts_path().exists(): return {"schema_version": 1, "receipts": {}}
    data = json.loads(receipts_path().read_text("utf-8"))
    if set(data) != {"schema_version", "receipts"} or data.get("schema_version") != 1 or not isinstance(data["receipts"], dict): raise RuntimeError("local autopilot receipts are invalid")
    for intent_id, receipt in data["receipts"].items():
        if not re.fullmatch(r"[a-f0-9]{20}", intent_id) or not isinstance(receipt, dict) or set(receipt) != {"receipt_hash", "posted_at", "acked"} or not re.fullmatch(r"[a-f0-9]{64}", str(receipt["receipt_hash"])) or not isinstance(receipt["acked"], bool):
            raise RuntimeError("local autopilot receipt is invalid")
    return data


def save_receipts(data: dict) -> None: observer.atomic_json_write(receipts_path(), data)
def receipt_hash(intent: dict, text: str) -> str: return hashlib.sha256(f"{intent['intent_id']}|{text}".encode()).hexdigest()


def render(intent: dict) -> str:
    validate_intent(intent)
    internal = {"id": intent["intent_id"], "source_candidate_id": intent["intent_id"], "source_did": "did:key:public", "fingerprint": intent["source_fingerprint"], "room": intent["room"], "seq": intent["seq"], "category": intent["category"], "topic": intent["topic"], "public_evidence_ids": intent["public_knowledge_ids"], "created_at": intent["created_at"], "expires_at": intent["expires_at"], "safety_decision": intent["safety_decision"]}
    return autopilot.render(internal)


def ack(config: dict, intent: dict, receipt: str) -> None:
    payload = {"schema_version": 1, "intent_id": intent["intent_id"], "receipt_hash": receipt}
    response = ssh_json(config, "ack", payload)
    if response != {"schema_version": 1, "acknowledged": intent["intent_id"]}: raise RuntimeError("autopilot ACK rejected")


def session_once(dry_run: bool = False) -> dict:
    config = load_config(); receipts = load_receipts(); results = []
    for intent in export_remote(config):
        text = render(intent); receipt = receipt_hash(intent, text)
        previous = receipts["receipts"].get(intent["intent_id"])
        if previous:
            if not dry_run and not previous.get("acked"): ack(config, intent, previous["receipt_hash"]); previous["acked"] = True; save_receipts(receipts)
            results.append({"intent_id": intent["intent_id"], "action": "already_posted"}); continue
        if dry_run: results.append({"intent_id": intent["intent_id"], "action": "dry_run_valid"}); continue
        results.append({"intent_id": intent["intent_id"], "action": "ready_to_publish"})
    return {"poll_interval_seconds": config["poll_interval_seconds"], "results": results}


def verify_session_did() -> dict:
    """Run the one signer `did` operation required before each publish."""
    if os.name != "nt": raise RuntimeError("autopilot session publisher is Windows-only")
    did = core.current_did()
    core.require_verified_did(did)
    if not core.signer_matches_pinned():
        raise RuntimeError("official signer integrity check failed")
    return {"did": did}


def publish_one(intent_id: str, did: str) -> dict:
    if os.name != "nt": raise RuntimeError("autopilot session publisher is Windows-only")
    config = load_config(); receipts = load_receipts(); intents = {item["intent_id"]: item for item in export_remote(config)}; intent = intents.get(intent_id)
    if not intent: raise RuntimeError("requested intent is absent from remote export")
    text = render(intent); receipt = receipt_hash(intent, text)
    previous = receipts["receipts"].get(intent_id)
    if previous:
        if not previous.get("acked"): ack(config, intent, previous["receipt_hash"]); previous["acked"] = True; save_receipts(receipts)
        return {"intent_id": intent_id, "action": "receipt_reconciled"}
    local = autopilot.load()
    if not local["enabled"] or local["paused"]:
        raise RuntimeError("autopilot is disabled or paused")
    allowed, reason = autopilot.rate_ok(local, {"fingerprint": intent["source_fingerprint"], "room": intent["room"]})
    if not allowed: raise RuntimeError("autopilot rate limit blocked publish")
    if autopilot.DLP.search(text): raise RuntimeError("outbound DLP blocked rendered content")
    if not isinstance(did, str) or not did.startswith("did:key:z6Mk"):
        raise RuntimeError("autopilot session DID is invalid")
    core.require_verified_did(did)
    if not core.signer_matches_pinned(): raise RuntimeError("official signer integrity check failed")
    core.post_signed(intent["room"], text, True, did=did, action="safe_autopilot_session_publish", record_permalink=False)
    receipts["receipts"][intent_id] = {"receipt_hash": receipt, "posted_at": datetime.now(UTC).isoformat(), "acked": False}; save_receipts(receipts)
    local["rate_history"].append({"at": datetime.now(UTC).isoformat(), "fingerprint": intent["source_fingerprint"], "room": intent["room"], "text_hash": hashlib.sha256(text.encode()).hexdigest()}); autopilot.save(local)
    try: ack(config, intent, receipt)
    except RuntimeError: return {"intent_id": intent_id, "action": "posted_ack_pending"}
    receipts["receipts"][intent_id]["acked"] = True; save_receipts(receipts)
    return {"intent_id": intent_id, "action": "posted_and_acked"}
