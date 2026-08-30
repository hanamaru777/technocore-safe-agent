"""Fixed-function OCI Vault signer for the isolated Oracle service only.

This module has no CLI command and accepts no text, room, URL, or shell input.
It renders tracked public templates only, fetches the Vault secret immediately
around a signer child process, and never persists the seed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import sys
from datetime import UTC, datetime
from pathlib import Path
from threading import Event

from . import autopilot, autopilot_transport, core, observer

RECEIPT_NAME = "oracle-signer-receipts.json"
HEALTH_NAME = "signer-health.json"
HEX_SEED = re.compile(rb"[0-9a-f]{64}")
EXPECTED_DID = re.compile(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{20,128}")
ERROR_CODES = {"did_failure", "intent_invalid", "rate_limited", "submission_unknown", "vault_failure"}


def now() -> str: return datetime.now(UTC).isoformat()
def receipt_path() -> Path: return core.STATE / "signer" / RECEIPT_NAME
def health_path() -> Path: return core.STATE / "signer" / HEALTH_NAME
def receipt_hash(intent: dict, did: str, nonce: str, text: str) -> str: return hashlib.sha256(f"{intent['intent_id']}|{did}|{nonce}|{text}".encode()).hexdigest()


def default_health() -> dict:
    return {"schema_version": 1, "last_cycle_at": None, "last_success_at": None, "last_error_code": None, "consecutive_failures": 0, "status": "starting"}


def load_health() -> dict:
    path = health_path()
    if not path.exists(): return default_health()
    try: data = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error: raise RuntimeError("signer health state is corrupt") from error
    if not isinstance(data, dict) or set(data) != set(default_health()) or data.get("schema_version") != 1 or data.get("status") not in {"starting", "ok", "degraded"} or data.get("last_error_code") not in ERROR_CODES | {None} or not isinstance(data.get("consecutive_failures"), int) or data["consecutive_failures"] < 0:
        raise RuntimeError("signer health state is invalid")
    return data


def save_health(data: dict) -> None: observer.atomic_json_write(health_path(), data, mode=0o600)


def record_health(error_code: str | None = None) -> dict:
    health = load_health(); health["last_cycle_at"] = now()
    if error_code is None:
        health["last_success_at"] = health["last_cycle_at"]; health["last_error_code"] = None; health["consecutive_failures"] = 0; health["status"] = "ok"
    else:
        health["last_error_code"] = error_code if error_code in ERROR_CODES else "intent_invalid"; health["consecutive_failures"] += 1; health["status"] = "degraded"
    save_health(health); return health


def load_receipts() -> dict:
    path = receipt_path()
    if not path.exists(): return {"schema_version": 1, "receipts": {}}
    try: data = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error: raise RuntimeError("signer receipt state is corrupt") from error
    if not isinstance(data, dict) or set(data) != {"schema_version", "receipts"} or data["schema_version"] != 1 or not isinstance(data["receipts"], dict):
        raise RuntimeError("signer receipt state is invalid")
    for intent_id, item in data["receipts"].items():
        required = {"state", "did", "nonce", "text_hash", "receipt_hash", "prepared_at"}
        if not re.fullmatch(r"[a-f0-9]{20}", intent_id) or not isinstance(item, dict) or not required <= set(item) or item["state"] not in {"prepared", "posted", "acknowledged"} or not EXPECTED_DID.fullmatch(str(item["did"])) or not str(item["nonce"]).isdigit() or not re.fullmatch(r"[a-f0-9]{64}", str(item["text_hash"])) or not re.fullmatch(r"[a-f0-9]{64}", str(item["receipt_hash"])):
            raise RuntimeError("signer receipt state is invalid")
    return data


def save_receipts(data: dict) -> None: observer.atomic_json_write(receipt_path(), data, mode=0o600)


def expected_did() -> str:
    value = os.environ.get("TECHNOCORE_SIGNER_EXPECTED_DID", "")
    if not EXPECTED_DID.fullmatch(value): raise RuntimeError("signer expected DID is invalid")
    return value


def vault_seed() -> bytearray:
    """Fetch exactly one hex seed through the instance-principal Vault route."""
    secret_id = os.environ.get("OCI_VAULT_SECRET_OCID", "").strip()
    if not re.fullmatch(r"ocid1\.vaultsecret\.oc[1-9][0-9]?\.[0-9A-Za-z_-]*\.[0-9A-Za-z_-]+", secret_id): raise RuntimeError("signer Vault secret identifier is invalid")
    try:
        import oci
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        bundle = oci.secrets.SecretsClient(config={}, signer=signer).get_secret_bundle(secret_id=secret_id, stage="CURRENT").data
        encoded = bundle.secret_bundle_content.content
        raw = bytearray(base64.b64decode(encoded, validate=True))
    except Exception as error:
        raise RuntimeError("signer Vault retrieval failed closed") from error
    if not HEX_SEED.fullmatch(raw):
        raw[:] = b"\0" * len(raw)
        raise RuntimeError("signer Vault value is invalid")
    return raw


def with_vault_seed(operation):
    seed = vault_seed()
    plaintext = ""
    try:
        plaintext = seed.decode("ascii")
        os.environ["SIGN_SEED"] = plaintext
        return operation()
    finally:
        os.environ.pop("SIGN_SEED", None)
        seed[:] = b"\0" * len(seed)
        plaintext = ""


def verify_did() -> str:
    try: did = with_vault_seed(core.current_did)
    except RuntimeError as error: raise RuntimeError("vault_failure") from error
    try:
        if not hmac.compare_digest(did, expected_did()): raise RuntimeError("mismatch")
        core.require_verified_did(did)
        if not core.signer_matches_pinned(): raise RuntimeError("unpinned")
    except RuntimeError as error: raise RuntimeError("did_failure") from error
    return did


def message_exists(receipt: dict, intent: dict, text: str) -> bool:
    payload = core.read_room(intent["room"], limit=200, cache_buster=secrets.token_hex(16))
    messages = payload.get("messages", payload if isinstance(payload, list) else [])
    return isinstance(messages, list) and any(isinstance(item, dict) and item.get("from") == receipt["did"] and str(item.get("nonce")) == receipt["nonce"] and item.get("text") == text for item in messages)


def mark_acknowledged(state: dict, receipts: dict, intent: dict, receipt: dict) -> None:
    receipt["state"] = "acknowledged"; receipt["posted_at"] = receipt.get("posted_at", now()); receipt["acknowledged_at"] = now(); save_receipts(receipts)
    item = state["outbox"].get(intent["intent_id"])
    if item is None: raise RuntimeError("signer intent disappeared")
    item["status"] = "acknowledged"; item["receipt_hash"] = receipt["receipt_hash"]; item["posted_at"] = receipt["posted_at"]; item["acknowledged_at"] = now()
    state["receipts"][intent["intent_id"]] = {"at": now(), "receipt_hash": receipt["receipt_hash"]}
    state["rate_history"].append({"at": now(), "fingerprint": intent["source_fingerprint"], "room": intent["room"], "text_hash": receipt["text_hash"]})
    autopilot.save(state, allow_legacy=False)
    autopilot.audit({"at": now(), "source_candidate": item["source_candidate_id"], "eligible": True, "why": item["safety_decision"], "public_knowledge_ids": ["public-profile:1"], "dlp": "pass", "rate_limit": "pass", "action": "oracle_signer_acknowledged"}, allow_legacy=False)


def reconcile_or_skip(state: dict, receipts: dict, intent: dict, text: str) -> str | None:
    receipt = receipts["receipts"].get(intent["intent_id"])
    if receipt is None: return None
    if receipt["state"] in {"posted", "acknowledged"}:
        if state["outbox"].get(intent["intent_id"], {}).get("status") in {"queued", "posted"}: mark_acknowledged(state, receipts, intent, receipt)
        return "already_posted"
    if not hmac.compare_digest(receipt["text_hash"], hashlib.sha256(text.encode()).hexdigest()): raise RuntimeError("prepared receipt text mismatch")
    try: exists = message_exists(receipt, intent, text)
    except Exception as error: raise RuntimeError("submission_unknown") from error
    if exists:
        mark_acknowledged(state, receipts, intent, receipt); return "reconciled"
    return None


def submit_prepared(state: dict, receipts: dict, intent: dict, text: str, receipt: dict) -> str:
    try:
        did = verify_did()
        if not hmac.compare_digest(did, receipt["did"]): raise RuntimeError("did_failure")
        with_vault_seed(lambda: core.post_signed(intent["room"], text, True, did=did, nonce=receipt["nonce"], action="oracle_isolated_signer_publish", record_permalink=False))
    except RuntimeError as error:
        try:
            if message_exists(receipt, intent, text): mark_acknowledged(state, receipts, intent, receipt); return "reconciled"
        except Exception:
            pass
        receipt["attempts"] = int(receipt.get("attempts", 0)) + 1; receipt["last_attempt_at"] = now(); receipt["last_error_code"] = str(error) if str(error) in ERROR_CODES else "submission_unknown"; save_receipts(receipts)
        raise RuntimeError(receipt["last_error_code"]) from error
    mark_acknowledged(state, receipts, intent, receipt)
    return "posted"


def process_intent(state: dict, receipts: dict, intent: dict) -> str:
    try: autopilot_transport.validate_intent(intent)
    except RuntimeError as error: raise RuntimeError("intent_invalid") from error
    internal = state["outbox"].get(intent["intent_id"])
    if not isinstance(internal, dict) or autopilot.export_intent(internal) != intent: raise RuntimeError("signer internal intent mismatch")
    text = autopilot.render(internal)
    if autopilot.DLP.search(text): raise RuntimeError("outbound DLP blocked rendered content")
    existing = reconcile_or_skip(state, receipts, intent, text)
    if existing: return existing
    if intent["intent_id"] in state["receipts"]: return "already_posted"
    allowed, reason = autopilot.rate_ok(state, {"fingerprint": intent["source_fingerprint"], "room": intent["room"]})
    if not allowed: raise RuntimeError("rate_limited")
    receipt = receipts["receipts"].get(intent["intent_id"])
    if receipt is None:
        did = verify_did(); nonce = core.make_nonce(intent["room"], did)
        receipt = {"state": "prepared", "did": did, "nonce": nonce, "text_hash": hashlib.sha256(text.encode()).hexdigest(), "receipt_hash": receipt_hash(intent, did, nonce, text), "prepared_at": now(), "attempts": 0, "last_attempt_at": None, "last_error_code": None}
        receipts["receipts"][intent["intent_id"]] = receipt; save_receipts(receipts)
    return submit_prepared(state, receipts, intent, text, receipt)


def expire_queued_intent(state: dict, intent: dict) -> bool:
    item = state["outbox"].get(intent.get("intent_id"))
    if not isinstance(item, dict) or item.get("status", "queued") != "queued": return False
    expires_at = observer.parse_time(item.get("expires_at"))
    if expires_at is None or expires_at > datetime.now(UTC): return False
    item["status"] = "expired"; item["expired_at"] = now(); item["expiration_reason"] = "intent_ttl_elapsed"
    autopilot.save(state, allow_legacy=False)
    autopilot.audit({"at": now(), "source_candidate": item.get("source_candidate_id"), "eligible": False, "why": "intent_ttl_elapsed", "public_knowledge_ids": ["public-profile:1"], "dlp": "not_applicable", "rate_limit": "not_applicable", "action": "intent_expired"}, allow_legacy=False)
    return True


def run_once() -> dict:
    state = autopilot.load(allow_legacy=False)
    if not state["enabled"] or state["paused"]: return {"enabled": state["enabled"], "paused": state["paused"], "processed": []}
    receipts, processed = load_receipts(), []
    for intent in autopilot.export_pending(allow_legacy=False)["intents"]:
        if expire_queued_intent(state, intent):
            processed.append({"intent_id": intent["intent_id"], "action": "expired"}); continue
        processed.append({"intent_id": intent["intent_id"], "action": process_intent(state, receipts, intent)})
    return {"enabled": True, "paused": False, "processed": processed}


def quarantine_controlled_e2e() -> dict:
    """Terminally quarantine only the known ambiguous v1 controlled test intent."""
    state = autopilot.load(allow_legacy=False)
    if not state["enabled"] or not state["paused"]:
        raise RuntimeError("controlled E2E quarantine requires enabled autopilot paused=true")
    intent_id = autopilot.controlled_e2e_id("v1")
    item = state["outbox"].get(intent_id)
    if not isinstance(item, dict) or item.get("status", "queued") != "queued" or item.get("category") != "controlled_e2e" or item.get("topic") != "prompt_injection_safety":
        raise RuntimeError("controlled E2E v1 queued intent is required for quarantine")
    receipt = load_receipts()["receipts"].get(intent_id)
    if not isinstance(receipt, dict) or receipt.get("state") != "prepared" or receipt.get("last_error_code") != "submission_unknown":
        raise RuntimeError("controlled E2E quarantine requires an ambiguous prepared receipt")
    item["status"] = "quarantined"; item["quarantined_at"] = now(); item["quarantine_reason"] = "submission_unknown"
    autopilot.save(state, allow_legacy=False)
    autopilot.audit({"at": now(), "source_candidate": item["source_candidate_id"], "eligible": False, "why": "submission_unknown", "public_knowledge_ids": ["public-profile:1"], "dlp": "not_applicable", "rate_limit": "not_applicable", "action": "controlled_e2e_quarantined"}, allow_legacy=False)
    return {"intent_id": intent_id, "status": "quarantined"}


def run_cycle() -> dict:
    try:
        result = run_once(); record_health(); return result
    except RuntimeError as error:
        record_health(str(error)); return {"processed": [], "status": "degraded"}


def poll_seconds() -> int:
    value = os.environ.get("TECHNOCORE_SIGNER_POLL_SECONDS", "30")
    if not value.isdecimal() or not 10 <= int(value) <= 3600: raise RuntimeError("signer poll interval is invalid")
    return int(value)


def main() -> None:
    if len(sys.argv) != 1: raise SystemExit("oracle signer accepts no arguments")
    stop = Event()
    def request_stop(*_: object) -> None: stop.set()
    for number in (signal.SIGINT, signal.SIGTERM): signal.signal(number, request_stop)
    while not stop.is_set():
        run_cycle()
        stop.wait(poll_seconds())


if __name__ == "__main__": main()
