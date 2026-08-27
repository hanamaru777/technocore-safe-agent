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
import signal
import sys
from datetime import UTC, datetime
from pathlib import Path
from threading import Event

from . import autopilot, autopilot_transport, core, observer

RECEIPT_NAME = "oracle-signer-receipts.json"
HEX_SEED = re.compile(rb"[0-9a-f]{64}")
EXPECTED_DID = re.compile(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{20,128}")


def now() -> str: return datetime.now(UTC).isoformat()
def receipt_path() -> Path: return core.STATE / "signer" / RECEIPT_NAME
def receipt_hash(intent: dict, did: str, nonce: str, text: str) -> str: return hashlib.sha256(f"{intent['intent_id']}|{did}|{nonce}|{text}".encode()).hexdigest()


def load_receipts() -> dict:
    path = receipt_path()
    if not path.exists(): return {"schema_version": 1, "receipts": {}}
    try: data = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error: raise RuntimeError("signer receipt state is corrupt") from error
    if not isinstance(data, dict) or set(data) != {"schema_version", "receipts"} or data["schema_version"] != 1 or not isinstance(data["receipts"], dict):
        raise RuntimeError("signer receipt state is invalid")
    for intent_id, item in data["receipts"].items():
        required = {"state", "did", "nonce", "text_hash", "receipt_hash", "prepared_at"}
        if not re.fullmatch(r"[a-f0-9]{20}", intent_id) or not isinstance(item, dict) or not required <= set(item) or item["state"] not in {"prepared", "posted"} or not EXPECTED_DID.fullmatch(str(item["did"])) or not str(item["nonce"]).isdigit() or not re.fullmatch(r"[a-f0-9]{64}", str(item["text_hash"])) or not re.fullmatch(r"[a-f0-9]{64}", str(item["receipt_hash"])):
            raise RuntimeError("signer receipt state is invalid")
    return data


def save_receipts(data: dict) -> None: observer.atomic_json_write(receipt_path(), data, mode=0o600)


def expected_did() -> str:
    value = os.environ.get("TECHNOCORE_SIGNER_EXPECTED_DID", "")
    if not EXPECTED_DID.fullmatch(value): raise RuntimeError("signer expected DID is invalid")
    return value


def vault_seed() -> bytearray:
    """Fetch exactly one hex seed through the instance-principal Vault route."""
    secret_id = os.environ.get("OCI_VAULT_SECRET_OCID", "")
    if not re.fullmatch(r"ocid1\.vaultsecret\.[a-z0-9.-]+", secret_id): raise RuntimeError("signer Vault secret identifier is invalid")
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
    did = with_vault_seed(core.current_did)
    if not hmac.compare_digest(did, expected_did()): raise RuntimeError("signer DID does not match configured expected DID")
    core.require_verified_did(did)
    if not core.signer_matches_pinned(): raise RuntimeError("official signer integrity check failed")
    return did


def message_exists(receipt: dict, intent: dict, text: str) -> bool:
    payload = core.read_room(intent["room"])
    messages = payload.get("messages", payload if isinstance(payload, list) else [])
    return isinstance(messages, list) and any(isinstance(item, dict) and item.get("from") == receipt["did"] and str(item.get("nonce")) == receipt["nonce"] and item.get("text") == text for item in messages)


def mark_posted(state: dict, receipts: dict, intent: dict, receipt: dict) -> None:
    receipt["state"] = "posted"; receipt["posted_at"] = now(); save_receipts(receipts)
    item = state["outbox"].get(intent["intent_id"])
    if item is None: raise RuntimeError("signer intent disappeared")
    item["status"] = "posted"; item["receipt_hash"] = receipt["receipt_hash"]; item["posted_at"] = now()
    state["receipts"][intent["intent_id"]] = {"at": now(), "receipt_hash": receipt["receipt_hash"]}
    state["rate_history"].append({"at": now(), "fingerprint": intent["source_fingerprint"], "room": intent["room"], "text_hash": receipt["text_hash"]})
    autopilot.save(state)
    autopilot.audit({"at": now(), "source_candidate": item["source_candidate_id"], "eligible": True, "why": item["safety_decision"], "public_knowledge_ids": ["public-profile:1"], "dlp": "pass", "rate_limit": "pass", "action": "oracle_signer_posted"})


def reconcile_or_skip(state: dict, receipts: dict, intent: dict, text: str) -> str | None:
    receipt = receipts["receipts"].get(intent["intent_id"])
    if receipt is None: return None
    if receipt["state"] == "posted":
        if state["outbox"].get(intent["intent_id"], {}).get("status") == "queued": mark_posted(state, receipts, intent, receipt)
        return "already_posted"
    if not hmac.compare_digest(receipt["text_hash"], hashlib.sha256(text.encode()).hexdigest()): raise RuntimeError("prepared receipt text mismatch")
    if message_exists(receipt, intent, text):
        mark_posted(state, receipts, intent, receipt); return "reconciled"
    return "pending_reconciliation"


def process_intent(state: dict, receipts: dict, intent: dict) -> str:
    autopilot_transport.validate_intent(intent)
    internal = state["outbox"].get(intent["intent_id"])
    if not isinstance(internal, dict) or autopilot.export_intent(internal) != intent: raise RuntimeError("signer internal intent mismatch")
    text = autopilot.render(internal)
    if autopilot.DLP.search(text): raise RuntimeError("outbound DLP blocked rendered content")
    existing = reconcile_or_skip(state, receipts, intent, text)
    if existing: return existing
    if intent["intent_id"] in state["receipts"]: return "already_posted"
    allowed, reason = autopilot.rate_ok(state, {"fingerprint": intent["source_fingerprint"], "room": intent["room"]})
    if not allowed: raise RuntimeError(f"autopilot rate limit blocked publish: {reason}")
    did = verify_did(); nonce = core.make_nonce(intent["room"], did)
    receipt = {"state": "prepared", "did": did, "nonce": nonce, "text_hash": hashlib.sha256(text.encode()).hexdigest(), "receipt_hash": receipt_hash(intent, did, nonce, text), "prepared_at": now()}
    receipts["receipts"][intent["intent_id"]] = receipt; save_receipts(receipts)
    with_vault_seed(lambda: core.post_signed(intent["room"], text, True, did=did, nonce=nonce, action="oracle_isolated_signer_publish", record_permalink=False))
    mark_posted(state, receipts, intent, receipt)
    return "posted"


def run_once() -> dict:
    state = autopilot.load()
    if not state["enabled"] or state["paused"]: return {"enabled": state["enabled"], "paused": state["paused"], "processed": []}
    receipts, processed = load_receipts(), []
    for intent in autopilot.export_pending()["intents"]:
        processed.append({"intent_id": intent["intent_id"], "action": process_intent(state, receipts, intent)})
    return {"enabled": True, "paused": False, "processed": processed}


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
        try: run_once()
        except RuntimeError: pass  # Fail closed for this cycle; no untrusted error data is logged.
        stop.wait(poll_seconds())


if __name__ == "__main__": main()
