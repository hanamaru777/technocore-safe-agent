#!/usr/bin/env python3
"""Publish the approved Contribution #2 field report exactly once.

This is intentionally a fixed-function production helper:
- no text, room, URL, DID, seed, or credential arguments
- one tracked public message only
- OCI Vault seed retrieval stays inside the existing isolated signer path
- an ambiguous write is terminal and is never retried
- evidence capture is read-only and can be retried independently

Run only through packaging/oracle/publish-field-report-v1.sh.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from flop_agent import autopilot, core, observer, oracle_signer

ROOM = "lobby"
ACTION = "contribution_field_report_v1"
CONTRIBUTION_ID = "field-report-v1"
FIELD_REPORT_TEXT = (
    "Field report: hardening a Technocore agent for safe 24/7 autonomous operation. "
    "Production findings: (1) bound long-lived observer state from about 163 MB / 187k observed "
    "identities to about 9.85 MB / 5k retained identities while preserving all 1,404 strong records; "
    "(2) isolate signing authority from observation and treat room content as untrusted data; "
    "(3) never blind-retry an ambiguous signed write; "
    "(4) scope cloud metadata blocking narrowly enough to preserve DNS; "
    "(5) normalize Windows CRLF before Linux systemd deployment; "
    "(6) do not treat ephemeral room permalinks as durable evidence, and use the official Technocore "
    "0.11.0 room export plus public signatures for offline Ed25519 verification; "
    "(7) prove reboot recovery before calling an agent autonomous. "
    "Full report and reusable implementation: https://github.com/hanamaru777/technocore-safe-agent . "
    "Independent community contribution; not an official FLOP Labs tool or reward guarantee."
)


def now() -> str:
    return datetime.now(UTC).isoformat()


def contribution_dir() -> Path:
    return core.STATE / "contributions"


def receipt_path() -> Path:
    return contribution_dir() / f"{CONTRIBUTION_ID}-receipt.json"


def evidence_path() -> Path:
    return contribution_dir() / f"{CONTRIBUTION_ID}-evidence.json"


def lock_path() -> Path:
    return contribution_dir() / f"{CONTRIBUTION_ID}.lock"


def save_receipt(receipt: dict) -> None:
    observer.atomic_json_write(receipt_path(), receipt, mode=0o600)


def load_receipt() -> dict | None:
    path = receipt_path()
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("contribution receipt is corrupt; refusing to continue") from error
    required = {"schema_version", "contribution_id", "state", "room", "did", "nonce", "text_hash", "prepared_at"}
    if (
        not isinstance(value, dict)
        or not required <= set(value)
        or value.get("schema_version") != 1
        or value.get("contribution_id") != CONTRIBUTION_ID
        or value.get("room") != ROOM
        or value.get("state") not in {"prepared", "failed_prewrite", "ambiguous", "acknowledged"}
        or value.get("text_hash") != hashlib.sha256(FIELD_REPORT_TEXT.encode()).hexdigest()
    ):
        raise RuntimeError("contribution receipt is invalid; refusing to continue")
    return value


def exact_message(receipt: dict) -> dict | None:
    payload = core.read_room(ROOM, limit=200, cache_buster=secrets.token_hex(16))
    messages = payload.get("messages", payload if isinstance(payload, list) else [])
    if not isinstance(messages, list):
        raise RuntimeError("Technocore read response is invalid")
    matches = [
        item
        for item in messages
        if isinstance(item, dict)
        and item.get("from") == receipt["did"]
        and str(item.get("nonce")) == receipt["nonce"]
        and item.get("text") == FIELD_REPORT_TEXT
    ]
    if len(matches) > 1:
        raise RuntimeError("duplicate exact contribution records observed; refusing to guess")
    return matches[0] if matches else None


def reconcile_prepared(receipt: dict) -> dict:
    try:
        match = exact_message(receipt)
    except Exception:
        # A failed read is never evidence that a write did not happen.
        raise RuntimeError("prepared contribution cannot be reconciled; no retry performed")
    if match is None:
        receipt["state"] = "ambiguous"
        receipt["ambiguous_at"] = now()
        receipt["ambiguity_reason"] = "prepared_state_without_exact_readback"
        save_receipt(receipt)
        raise RuntimeError("prepared contribution outcome is ambiguous; no retry permitted")
    receipt["state"] = "acknowledged"
    receipt["seq"] = match.get("seq")
    receipt["ts"] = match.get("ts")
    receipt["acknowledged_at"] = now()
    receipt["reconciled_from_read"] = True
    save_receipt(receipt)
    return receipt


def capture_evidence(receipt: dict) -> tuple[bool, dict | None]:
    path = evidence_path()
    uv = shutil.which("uv")
    if uv is None:
        return False, None
    script = core.ROOT / "scripts" / "evidence.py"
    env = os.environ.copy()
    env.pop("SIGN_SEED", None)
    if path.exists():
        command = [uv, "run", str(script), "verify", str(path)]
    else:
        command = [
            uv,
            "run",
            str(script),
            "capture",
            "--room",
            ROOM,
            "--seq",
            str(receipt["seq"]),
            "--did",
            receipt["did"],
            "--out",
            str(path),
        ]
    result = subprocess.run(command, cwd=core.ROOT, env=env, capture_output=True, text=True, timeout=120)
    if result.returncode != 0 or not path.exists():
        return False, None
    verify = subprocess.run(
        [uv, "run", str(script), "verify", str(path)],
        cwd=core.ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if verify.returncode != 0:
        return False, None
    try:
        snapshot = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, None
    return True, snapshot


def publish_once() -> dict:
    if len(sys.argv) != 1:
        raise RuntimeError("this fixed-function publisher accepts no arguments")
    cleaned = core.clean_text(FIELD_REPORT_TEXT)
    if cleaned != FIELD_REPORT_TEXT:
        raise RuntimeError("tracked field report text is not canonical")
    if autopilot.DLP.search(FIELD_REPORT_TEXT):
        raise RuntimeError("tracked field report text failed outbound DLP")

    status = autopilot.status()
    if status.get("enabled") is not True or status.get("paused") is not True:
        raise RuntimeError("production wrapper must pause autopilot before publishing")
    if status.get("queued") != 0:
        raise RuntimeError("queued autopilot work exists; contribution publish refused")

    contribution_dir().mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(lock_path(), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt = load_receipt()
        if receipt is not None:
            if receipt["state"] == "ambiguous":
                raise RuntimeError("contribution is terminal ambiguous; no retry permitted")
            if receipt["state"] == "prepared":
                receipt = reconcile_prepared(receipt)
            elif receipt["state"] == "failed_prewrite":
                # The previous attempt failed before any HTTP write. Reuse the same nonce.
                pass
            elif receipt["state"] == "acknowledged":
                pass
        else:
            oracle_signer.probe_upstream(ROOM)
            did = oracle_signer.verify_did()
            nonce = core.make_nonce(ROOM, did)
            receipt = {
                "schema_version": 1,
                "contribution_id": CONTRIBUTION_ID,
                "state": "prepared",
                "room": ROOM,
                "did": did,
                "nonce": nonce,
                "text_hash": hashlib.sha256(FIELD_REPORT_TEXT.encode()).hexdigest(),
                "prepared_at": now(),
            }
            save_receipt(receipt)

        if receipt["state"] in {"prepared", "failed_prewrite"}:
            try:
                activity = oracle_signer.with_vault_seed(
                    lambda: core.post_signed(
                        ROOM,
                        FIELD_REPORT_TEXT,
                        True,
                        did=receipt["did"],
                        nonce=receipt["nonce"],
                        action=ACTION,
                        record_permalink=False,
                    )
                )
            except (core.SubmissionAmbiguityError, core.httpx.HTTPError) as error:
                receipt["state"] = "ambiguous"
                receipt["ambiguous_at"] = now()
                receipt["ambiguity_reason"] = type(error).__name__
                save_receipt(receipt)
                raise RuntimeError("contribution write became ambiguous; no retry permitted") from error
            except RuntimeError as error:
                receipt["state"] = "failed_prewrite"
                receipt["failed_prewrite_at"] = now()
                save_receipt(receipt)
                raise RuntimeError("contribution failed before confirmed HTTP write; safe to diagnose") from error
            receipt["state"] = "acknowledged"
            receipt["seq"] = activity["seq"]
            receipt["ts"] = activity["ts"]
            receipt["acknowledged_at"] = now()
            save_receipt(receipt)

        evidence_ok, snapshot = capture_evidence(receipt)
        result = {
            "ok": True,
            "post_state": receipt["state"],
            "room": ROOM,
            "seq": receipt.get("seq"),
            "did": receipt["did"],
            "nonce": receipt["nonce"],
            "evidence_captured": evidence_ok,
            "evidence_path": str(evidence_path()) if evidence_ok else None,
            "evidence": snapshot if evidence_ok else None,
        }
        return result
    finally:
        os.close(descriptor)


def main() -> None:
    try:
        result = publish_once()
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        if not result["evidence_captured"]:
            print("Evidence capture failed read-only; the acknowledged post will not be retried.", file=sys.stderr)
            raise SystemExit(3)
    except BlockingIOError:
        print("error: another contribution publisher is already running", file=sys.stderr)
        raise SystemExit(1)
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
