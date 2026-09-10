"""PREPARE-only isolated helper for the first genuine tclk/1 PaperRail pilot.

The helper accepts no arguments, never signs or posts, never retrieves the Vault DID seed,
and never returns the hash-lock preimage. It independently revalidates one typed stage and
its fixed-origin Note evidence, then delegates only canonical tclk frame construction and
restricted protocol-material persistence to the pinned local @flop-labs/tclk runtime.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

from . import core, observer, tclk_note_review, tclk_pilot

SCHEMA_VERSION = 1
MIN_PREPARE_SECONDS = 120
BRIDGE = Path(__file__).resolve().parents[2] / "tools" / "tclk_prepare_accept.mjs"

_DID = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{20,128}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CONTRACT = re.compile(r"^0x[0-9a-f]{64}$")
_DEAL_ROOM = re.compile(r"^mb-p-tclk-[0-9a-f]{16}$")
_ALLOWED_VERB = re.compile(r"\b(?:verify|review|inspect|check|audit|analy[sz]e|extract|summari[sz]e|compare|validate)\b", re.I)
_ALLOWED_OBJECT = re.compile(r"\b(?:public|repo(?:sitory)?|pull request|commit|spec(?:ification)?|schema|openapi|json|documentation|document|source|artifact|record|data)\b", re.I)
_FORBIDDEN = re.compile(
    r"\b(?:private\s+key|seed\s+phrase|signing\s+key|credential|password|nonce\s+replay|prediction\s+market|flopmarket|bet|buy|swap|powershell|cmd\.exe|shell\s+command|run\s+command|execute\s+command|curl|wget|x402|ptlc|adaptor|payment|transfer\s+funds|send\s+funds|wallet|sign\s+this|sign\s+message|signed\s+replay|same\s+signed)\b",
    re.I,
)


class PrepareError(RuntimeError):
    """Stable public-safe error from the PREPARE-only path."""


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def _expected_did() -> str:
    value = os.environ.get("TECHNOCORE_SIGNER_EXPECTED_DID", "").strip()
    if not _DID.fullmatch(value):
        raise PrepareError("expected_did_unavailable")
    return value


def _task_policy(resolved: dict) -> None:
    full = resolved.get("full_spec")
    material = resolved.get("material")
    values = []
    if isinstance(full, dict) and isinstance(full.get("value"), str):
        values.append(full["value"])
    if isinstance(material, dict) and isinstance(material.get("value"), str):
        values.append(material["value"])
    text = "\n".join(values)
    if not text or _FORBIDDEN.search(text):
        raise PrepareError("task_policy_blocked")
    if not _ALLOWED_VERB.search(text) or not _ALLOWED_OBJECT.search(text):
        raise PrepareError("task_policy_unknown")


def _stage_item(stage: dict) -> dict:
    return {
        "id": stage["offer_id"],
        "from": stage["counterpart_did"],
        "frame_type": "offer",
        "job_proto": stage["job_proto"],
        "job_id": stage["job_id"],
        "rail": stage["rail"],
        "expires_ms": stage["expires_ms"],
        "frame_text": stage["offer_line"],
        "frame_sha256": stage["frame_sha256"],
        "read_only": True,
        "accepted": False,
    }


def _resolve_and_bind(stage: dict, *, reader: Callable[[str, str], str], now_ms: int) -> dict:
    try:
        resolved = tclk_note_review.resolve_offer(_stage_item(stage), reader=reader, now_ms=now_ms)
    except tclk_note_review.ResolutionError as error:
        raise PrepareError("note_revalidation_failed") from error
    full = resolved.get("full_spec")
    material = resolved.get("material")
    full_hash = full.get("sha256") if isinstance(full, dict) else None
    material_hash = material.get("sha256") if isinstance(material, dict) else None
    if not isinstance(full_hash, str) or not _HEX64.fullmatch(full_hash):
        raise PrepareError("note_revalidation_failed")
    if not hmac.compare_digest(full_hash, stage["full_spec_sha256"]):
        raise PrepareError("note_hash_changed")
    expected_material = stage.get("material_sha256")
    if material_hash is None and expected_material is not None:
        raise PrepareError("note_hash_changed")
    if material_hash is not None:
        if not isinstance(expected_material, str) or not hmac.compare_digest(material_hash, expected_material):
            raise PrepareError("note_hash_changed")
    _task_policy(resolved)
    return resolved


def _bridge_environment() -> dict[str, str]:
    allowed = {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP"}
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    env["FLOP_STATE_DIR"] = str(core.STATE)
    return env


def _run_bridge(stage: dict) -> dict:
    env = _bridge_environment()
    if not shutil.which("node", path=env.get("PATH")):
        raise PrepareError("node_unavailable")
    if not BRIDGE.is_file():
        raise PrepareError("prepare_bridge_unavailable")
    package = BRIDGE.parent.parent / "node_modules" / "@flop-labs" / "tclk" / "package.json"
    if not package.is_file():
        raise PrepareError("pinned_runtime_unavailable")
    request = {
        "stage_id": stage["stage_id"],
        "stage_digest": stage["stage_digest"],
        "offer_id": stage["offer_id"],
        "offer_line": stage["offer_line"],
        "frame_sha256": stage["frame_sha256"],
        "job_id": stage["job_id"],
        "expires_ms": stage["expires_ms"],
        "from": stage["our_did"],
        "full_spec_sha256": stage["full_spec_sha256"],
        "material_sha256": stage["material_sha256"],
    }
    try:
        result = subprocess.run(
            ["node", str(BRIDGE)],
            input=json.dumps(request, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PrepareError("prepare_bridge_failed") from error
    if result.returncode != 0:
        raise PrepareError("prepare_bridge_failed")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise PrepareError("prepare_bridge_failed") from error
    required = {
        "stage_id", "stage_digest", "offer_id", "frame_sha256", "full_spec_sha256",
        "material_sha256", "expires_ms", "accept_line", "accept_sha256", "contract_id", "deal_room",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise PrepareError("prepare_bridge_output_invalid")
    if any(key in value for key in ("secret", "preimage", "seed", "private_key")):
        raise PrepareError("prepare_bridge_output_invalid")
    for field in ("stage_id", "stage_digest", "offer_id", "frame_sha256", "full_spec_sha256", "material_sha256", "expires_ms"):
        if value.get(field) != request.get(field):
            raise PrepareError("prepare_binding_mismatch")
    accept_line = value.get("accept_line")
    accept_hash = value.get("accept_sha256")
    if not isinstance(accept_line, str) or not accept_line.startswith("tclk1 ") or not isinstance(accept_hash, str) or not _HEX64.fullmatch(accept_hash):
        raise PrepareError("prepare_bridge_output_invalid")
    if hashlib.sha256(accept_line.encode("utf-8")).hexdigest() != accept_hash:
        raise PrepareError("accept_hash_mismatch")
    if not isinstance(value.get("contract_id"), str) or not _CONTRACT.fullmatch(value["contract_id"]):
        raise PrepareError("prepare_bridge_output_invalid")
    if not isinstance(value.get("deal_room"), str) or not _DEAL_ROOM.fullmatch(value["deal_room"]):
        raise PrepareError("prepare_bridge_output_invalid")
    return value


def _validate_preview(value: object) -> dict:
    required = {
        "schema_version", "status", "prepared_at", "accepted", "stage_id", "stage_digest",
        "offer_id", "frame_sha256", "full_spec_sha256", "material_sha256", "expires_ms",
        "accept_line", "accept_sha256", "contract_id", "deal_room",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema_version") != SCHEMA_VERSION or value.get("status") != "prepared" or value.get("accepted") is not False:
        raise PrepareError("preview_invalid")
    if not isinstance(value.get("prepared_at"), str):
        raise PrepareError("preview_invalid")
    if not isinstance(value.get("accept_line"), str) or hashlib.sha256(value["accept_line"].encode("utf-8")).hexdigest() != value.get("accept_sha256"):
        raise PrepareError("preview_invalid")
    if not isinstance(value.get("contract_id"), str) or not _CONTRACT.fullmatch(value["contract_id"]):
        raise PrepareError("preview_invalid")
    if not isinstance(value.get("deal_room"), str) or not _DEAL_ROOM.fullmatch(value["deal_room"]):
        raise PrepareError("preview_invalid")
    return value


def _load_preview(stage_id: str) -> dict | None:
    path = tclk_pilot.preview_path(stage_id)
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PrepareError("preview_invalid") from error
    return _validate_preview(value)


def _require_preview_binding(preview: dict, stage: dict) -> None:
    for field in (
        "stage_id", "stage_digest", "offer_id", "frame_sha256", "full_spec_sha256",
        "material_sha256", "expires_ms",
    ):
        if preview.get(field) != stage.get(field):
            raise PrepareError("preview_binding_mismatch")


def _require_protocol_file(stage_id: str) -> Path:
    protocol_path = tclk_pilot.secret_path(stage_id)
    if not protocol_path.is_file():
        raise PrepareError("protocol_material_missing")
    try:
        if (protocol_path.stat().st_mode & 0o777) != 0o600:
            raise PrepareError("protocol_material_permissions_invalid")
    except OSError as error:
        raise PrepareError("protocol_material_missing") from error
    return protocol_path


def prepare_stage(
    stage_id: str,
    *,
    reader: Callable[[str, str], str] = core.read_note,
    now_ms: int | None = None,
) -> dict:
    current = _now_ms() if now_ms is None else now_ms
    try:
        stage = tclk_pilot.load_stage(stage_id, now_ms=current, require_live=False)
    except tclk_pilot.PilotError as error:
        raise PrepareError(str(error)) from error
    if stage["expires_ms"] - current < MIN_PREPARE_SECONDS * 1000:
        raise PrepareError("prepare_window_elapsed")
    expected_did = _expected_did()
    if not hmac.compare_digest(expected_did, stage["our_did"]):
        raise PrepareError("stage_did_mismatch")

    existing = _load_preview(stage_id)
    protocol_path = tclk_pilot.secret_path(stage_id)
    if existing is not None:
        _require_preview_binding(existing, stage)
        _require_protocol_file(stage_id)
        return {"action": "already_prepared", "preview": existing}

    recovering = protocol_path.exists()
    if recovering:
        _require_protocol_file(stage_id)
    _resolve_and_bind(stage, reader=reader, now_ms=current)
    prepared = _run_bridge(stage)
    _require_protocol_file(stage_id)

    preview = {
        "schema_version": SCHEMA_VERSION,
        "status": "prepared",
        "prepared_at": datetime.fromtimestamp(current / 1000, UTC).isoformat(),
        "accepted": False,
        **prepared,
    }
    _validate_preview(preview)
    _require_preview_binding(preview, stage)
    try:
        tclk_pilot.preview_dir().mkdir(parents=True, exist_ok=True, mode=0o770)
        observer.atomic_json_write(tclk_pilot.preview_path(stage_id), preview, compact=True, mode=0o640)
    except OSError as error:
        raise PrepareError("preview_persistence_failed") from error
    return {"action": "recovered" if recovering else "prepared", "preview": preview}


def prepare_next(
    *,
    reader: Callable[[str, str], str] = core.read_note,
    now_ms: int | None = None,
) -> dict:
    current = _now_ms() if now_ms is None else now_ms
    try:
        paths = list(tclk_pilot.stage_dir().glob("*.json"))
    except OSError as error:
        raise PrepareError("stage_store_unavailable") from error
    candidates: list[dict] = []
    for path in paths:
        try:
            stage = tclk_pilot.load_stage(path.stem, now_ms=current, require_live=False)
        except tclk_pilot.PilotError:
            continue
        if stage["expires_ms"] - current < MIN_PREPARE_SECONDS * 1000:
            continue
        preview_exists = tclk_pilot.preview_path(stage["stage_id"]).exists()
        protocol_exists = tclk_pilot.secret_path(stage["stage_id"]).exists()
        if preview_exists and not protocol_exists:
            raise PrepareError("protocol_material_missing")
        if preview_exists:
            continue
        if protocol_exists:
            _require_protocol_file(stage["stage_id"])
        candidates.append(stage)
    if not candidates:
        return {"action": "idle", "preview": None}
    stage = min(candidates, key=lambda item: item["expires_ms"])
    return prepare_stage(stage["stage_id"], reader=reader, now_ms=current)


def public_result(result: dict) -> dict:
    action = result.get("action")
    preview = result.get("preview")
    if not isinstance(preview, dict):
        return {"ok": True, "action": action}
    return {
        "ok": True,
        "action": action,
        "stage_id": preview["stage_id"],
        "stage_digest": preview["stage_digest"],
        "offer_id": preview["offer_id"],
        "accept_sha256": preview["accept_sha256"],
        "contract_id": preview["contract_id"],
        "deal_room": preview["deal_room"],
        "expires_ms": preview["expires_ms"],
    }


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("tclk pilot preparer accepts no arguments")
    try:
        result = prepare_next()
    except PrepareError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        raise SystemExit(1)
    print(json.dumps(public_result(result), sort_keys=True))


if __name__ == "__main__":
    main()
