"""Typed, fail-closed tclk first-pilot staging and no-write PREPARE.

This module never posts to Technocore and never accesses the DID signing key or Vault.
Discord may create a public-only typed stage from already validated review evidence.
A separate hardened one-shot process running as ``technocore-signer`` independently
revalidates the stage and fixed-origin Note hashes, then mints one hash-lock preimage,
persists it only in signer-private state, and publishes only a public PREPARE preview.
"""
from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock

from . import core, observer, tclk_note_review, tclk_review_evidence, tclk_triage

SCHEMA_VERSION = 1
STAGES_NAME = "tclk-pilot-stages.json"
PREVIEWS_NAME = "tclk-pilot-previews.json"
PRIVATE_DIR_NAME = "tclk-pilot-private"
MAX_STAGES = 32
MIN_PREPARE_SECONDS = 180
MAX_PENDING_PER_RUN = 2

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OFFER_ID = re.compile(r"^0x[0-9a-f]{64}$")
_STAGE_ID = re.compile(r"^[a-f0-9]{24}$")
_DID = re.compile(r"^did:key:z6Mk[A-Za-z0-9]{44}$")
_JOB_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
_LOCK = Lock()


class PilotError(RuntimeError):
    """Stable fail-closed error safe to show to the operator."""


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def _shared_dir() -> Path:
    return core.STATE / "autopilot"


def stages_path() -> Path:
    return _shared_dir() / STAGES_NAME


def previews_path() -> Path:
    return _shared_dir() / PREVIEWS_NAME


def private_dir() -> Path:
    return core.STATE / "signer" / PRIVATE_DIR_NAME


def _private_path(stage_id: str) -> Path:
    return private_dir() / f"{stage_id}.json"


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _stage_digest(body: dict) -> str:
    return _sha(_canonical(body))


def _stage_id(body: dict) -> str:
    return _stage_digest(body)[:24]


def _default_store() -> dict:
    return {"schema_version": SCHEMA_VERSION, "records": []}


def _read_store(path: Path) -> dict:
    if not path.exists():
        return _default_store()
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PilotError("pilot_store_unreadable") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "records"}
        or value.get("schema_version") != SCHEMA_VERSION
        or not isinstance(value.get("records"), list)
        or len(value["records"]) > MAX_STAGES
    ):
        raise PilotError("pilot_store_invalid")
    return value


def _write_store(path: Path, value: dict, *, mode: int = 0o640) -> None:
    observer.atomic_json_write(path, value, compact=True, mode=mode)


def _task_family(spec: str, material: str | None) -> str:
    text = f"{spec}\n{material or ''}".lower()
    forbidden = (
        "nonce replay",
        "same signed url",
        "same signed message",
        "same signed request",
        "prediction market",
        "flopmarket",
        "private key",
        "seed phrase",
        "signing key",
        "credential",
        "password",
        "powershell",
        "cmd.exe",
        "shell command",
        "run command",
        "execute command",
        "curl ",
        "wget ",
    )
    if any(term in text for term in forbidden) or re.search(r"\b(?:bet|buy)\b", text):
        raise PilotError("task_policy_blocked")
    if re.search(r"https?://", text, re.IGNORECASE):
        raise PilotError("external_url_present")
    if re.search(r"\b(?:verify|verification|check|review|audit|inspect|compare|validate)\b", text):
        if re.search(r"\b(?:repo|repository|spec|artifact|document|did|signature|nonce|public data|public-data)\b", text):
            return "public_verification"
    raise PilotError("task_family_unsupported")


def _validated_stage(record: object) -> dict:
    required = {
        "stage_id",
        "stage_digest",
        "created_at",
        "offer_id",
        "frame_text",
        "frame_sha256",
        "counterpart_did",
        "job_id",
        "job_proto",
        "rail",
        "lock",
        "expires_ms",
        "task_family",
        "full_spec_sha256",
        "material_sha256",
        "review_resolved_at",
    }
    if not isinstance(record, dict) or set(record) != required:
        raise PilotError("stage_invalid")
    body = {key: record[key] for key in record if key not in {"stage_id", "stage_digest", "created_at"}}
    if (
        not _STAGE_ID.fullmatch(str(record["stage_id"]))
        or not _HEX64.fullmatch(str(record["stage_digest"]))
        or _stage_id(body) != record["stage_id"]
        or _stage_digest(body) != record["stage_digest"]
    ):
        raise PilotError("stage_digest_mismatch")
    if not isinstance(record["created_at"], str) or not isinstance(record["review_resolved_at"], str):
        raise PilotError("stage_time_invalid")
    if (
        not _OFFER_ID.fullmatch(str(record["offer_id"]))
        or not isinstance(record["frame_text"], str)
        or not record["frame_text"].startswith("tclk1 ")
        or len(record["frame_text"]) > 4096
        or _sha(record["frame_text"]) != record["frame_sha256"]
    ):
        raise PilotError("stage_frame_invalid")
    if (
        not _HEX64.fullmatch(str(record["frame_sha256"]))
        or not _DID.fullmatch(str(record["counterpart_did"]))
        or not _JOB_ID.fullmatch(str(record["job_id"]))
        or str(record["job_id"]).endswith("-")
    ):
        raise PilotError("stage_identity_invalid")
    if (
        record["job_proto"] != "a2a"
        or record["rail"] != "paper"
        or record["lock"] != "hash"
        or record["task_family"] != "public_verification"
    ):
        raise PilotError("stage_policy_invalid")
    if not isinstance(record["expires_ms"], int) or not _HEX64.fullmatch(str(record["full_spec_sha256"])):
        raise PilotError("stage_evidence_invalid")
    material = record["material_sha256"]
    if material is not None and not _HEX64.fullmatch(str(material)):
        raise PilotError("stage_evidence_invalid")
    return record


def _validated_preview(record: object, stage: dict | None = None) -> dict:
    required = {
        "stage_id",
        "stage_digest",
        "offer_id",
        "frame_sha256",
        "full_spec_sha256",
        "material_sha256",
        "accept_line",
        "accept_sha256",
        "contract",
        "deal_room",
        "expires_ms",
        "prepared_at",
        "posted",
    }
    if not isinstance(record, dict) or set(record) != required:
        raise PilotError("preview_invalid")
    if (
        not _STAGE_ID.fullmatch(str(record["stage_id"]))
        or not _HEX64.fullmatch(str(record["stage_digest"]))
        or not _OFFER_ID.fullmatch(str(record["offer_id"]))
        or not _HEX64.fullmatch(str(record["frame_sha256"]))
        or not _HEX64.fullmatch(str(record["full_spec_sha256"]))
        or not isinstance(record["accept_line"], str)
        or not record["accept_line"].startswith("tclk1 ")
        or len(record["accept_line"]) > 4096
        or not _HEX64.fullmatch(str(record["accept_sha256"]))
        or _sha(record["accept_line"]) != record["accept_sha256"]
        or not _OFFER_ID.fullmatch(str(record["contract"]))
        or not isinstance(record["deal_room"], str)
        or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,95}", record["deal_room"])
        or not isinstance(record["expires_ms"], int)
        or not isinstance(record["prepared_at"], str)
        or record["posted"] is not False
    ):
        raise PilotError("preview_invalid")
    material = record["material_sha256"]
    if material is not None and not _HEX64.fullmatch(str(material)):
        raise PilotError("preview_invalid")
    if stage is not None:
        bindings = (
            ("stage_id", "stage_id"),
            ("stage_digest", "stage_digest"),
            ("offer_id", "offer_id"),
            ("frame_sha256", "frame_sha256"),
            ("full_spec_sha256", "full_spec_sha256"),
            ("material_sha256", "material_sha256"),
            ("expires_ms", "expires_ms"),
        )
        if any(record[left] != stage[right] for left, right in bindings):
            raise PilotError("preview_stage_mismatch")
    return record


def load_stages() -> dict:
    store = _read_store(stages_path())
    for record in store["records"]:
        _validated_stage(record)
    return store


def load_previews() -> dict:
    store = _read_store(previews_path())
    for record in store["records"]:
        _validated_preview(record)
    return store


def get_stage(stage_id: str) -> dict | None:
    if not isinstance(stage_id, str) or not _STAGE_ID.fullmatch(stage_id):
        return None
    for record in reversed(load_stages()["records"]):
        if record["stage_id"] == stage_id:
            return record
    return None


def get_preview(stage_id: str) -> dict | None:
    if not isinstance(stage_id, str) or not _STAGE_ID.fullmatch(stage_id):
        return None
    for record in reversed(load_previews()["records"]):
        if record["stage_id"] == stage_id:
            stage = get_stage(stage_id)
            if stage is None:
                raise PilotError("preview_without_stage")
            return _validated_preview(record, stage)
    return None


def stage_offer(item: dict, *, evidence: dict | None = None, now_ms: int | None = None) -> dict:
    """Create one public-only stage from retained offer plus durable review evidence."""
    current = _now_ms() if now_ms is None else now_ms
    verdict = tclk_triage.classify(item, now_ms=current)
    if verdict.get("reviewable") is not True or verdict.get("reason") != "human_review_required":
        raise PilotError("offer_not_reviewable")
    if not isinstance(item.get("frame_text"), str) or _sha(item["frame_text"]) != item.get("frame_sha256"):
        raise PilotError("frame_hash_mismatch")
    if item.get("rail") != "paper" or item.get("job_proto") != "a2a" or item.get("read_only") is not True or item.get("accepted") is not False:
        raise PilotError("offer_policy_invalid")
    evidence = evidence if evidence is not None else tclk_review_evidence.get(str(item.get("id")))
    if not isinstance(evidence, dict):
        raise PilotError("review_evidence_missing")
    try:
        tclk_review_evidence._validate_record(evidence)
    except tclk_review_evidence.EvidenceError as error:
        raise PilotError("review_evidence_invalid") from error
    if (
        evidence.get("offer_id") != item.get("id")
        or evidence.get("frame_sha256") != item.get("frame_sha256")
        or evidence.get("job_id") != item.get("job_id")
        or evidence.get("expires_ms") != item.get("expires_ms")
        or evidence.get("accepted") is not False
    ):
        raise PilotError("review_evidence_mismatch")
    spec = evidence["full_spec"]
    material = evidence["material"]
    family = _task_family(spec["value"], None if material is None else material["value"])
    body = {
        "offer_id": item["id"],
        "frame_text": item["frame_text"],
        "frame_sha256": item["frame_sha256"],
        "counterpart_did": item["from"],
        "job_id": item["job_id"],
        "job_proto": "a2a",
        "rail": "paper",
        "lock": "hash",
        "expires_ms": item["expires_ms"],
        "task_family": family,
        "full_spec_sha256": spec["sha256"],
        "material_sha256": None if material is None else material["sha256"],
        "review_resolved_at": evidence["resolved_at"],
    }
    record = {
        "stage_id": _stage_id(body),
        "stage_digest": _stage_digest(body),
        "created_at": datetime.fromtimestamp(current / 1000, UTC).isoformat(),
        **body,
    }
    _validated_stage(record)
    with _LOCK:
        store = load_stages()
        for existing in store["records"]:
            if existing["stage_id"] == record["stage_id"]:
                return existing
            if existing["offer_id"] == record["offer_id"]:
                raise PilotError("offer_already_staged_differently")
        store["records"].append(record)
        store["records"] = store["records"][-MAX_STAGES:]
        _write_store(stages_path(), store)
    return record


def _signer_username() -> str:
    return pwd.getpwuid(os.geteuid()).pw_name


def _require_signer_user(username: str | None = None) -> None:
    if (username if username is not None else _signer_username()) != "technocore-signer":
        raise PilotError("prepare_requires_technocore_signer")


def _prepare_did() -> str:
    value = os.environ.get("TCLK_PREPARE_DID", "").strip()
    if not _DID.fullmatch(value):
        raise PilotError("prepare_did_invalid")
    return value


def _official_offer_check(frame_text: str, expected: dict) -> dict:
    from . import tclk_watch

    frame = tclk_watch.official_offer(frame_text)
    if not isinstance(frame, dict):
        raise PilotError("official_offer_decode_failed")
    job = frame.get("job") if isinstance(frame.get("job"), dict) else {}
    if (
        frame.get("id") != expected["offer_id"]
        or frame.get("from") != expected["counterpart_did"]
        or frame.get("lock") != "hash"
        or frame.get("rails") != ["paper"]
        or job.get("proto") != "a2a"
        or job.get("id") != expected["job_id"]
        or frame.get("expiresMs") != expected["expires_ms"]
    ):
        raise PilotError("official_offer_binding_mismatch")
    return frame


def _resolve_stage_notes(stage: dict, *, reader=core.read_note, now_ms: int) -> dict:
    item = {
        "id": stage["offer_id"],
        "frame_type": "offer",
        "read_only": True,
        "accepted": False,
        "rail": "paper",
        "job_proto": "a2a",
        "job_id": stage["job_id"],
        "expires_ms": stage["expires_ms"],
        "frame_sha256": stage["frame_sha256"],
    }
    try:
        resolved = tclk_note_review.resolve_offer(item, reader=reader, now_ms=now_ms)
    except tclk_note_review.ResolutionError as error:
        raise PilotError(str(error)) from error
    material = resolved["material"]
    if (
        resolved["full_spec"]["sha256"] != stage["full_spec_sha256"]
        or (None if material is None else material["sha256"]) != stage["material_sha256"]
    ):
        raise PilotError("review_evidence_changed")
    family = _task_family(resolved["full_spec"]["value"], None if material is None else material["value"])
    if family != stage["task_family"]:
        raise PilotError("task_family_changed")
    return resolved


def _prepare_bridge(stage: dict, *, our_did: str) -> dict:
    bridge_path = Path(__file__).resolve().parents[2] / "tools" / "tclk_prepare.mjs"
    from . import tclk_watch

    env = tclk_watch._node_environment()
    payload = {"offer": stage["frame_text"], "from": our_did}
    try:
        result = subprocess.run(
            ["node", str(bridge_path)],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
            env=env,
        )
        value = json.loads(result.stdout) if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        raise PilotError("prepare_bridge_failed") from error
    required = {"accept_line", "accept_sha256", "contract", "deal_room", "lock_material"}
    if not isinstance(value, dict) or set(value) != required:
        raise PilotError("prepare_bridge_failed")
    if (
        not re.fullmatch(r"0x[0-9a-f]{64}", str(value["lock_material"]))
        or not isinstance(value["accept_line"], str)
        or _sha(value["accept_line"]) != value["accept_sha256"]
        or not _HEX64.fullmatch(str(value["accept_sha256"]))
        or not _OFFER_ID.fullmatch(str(value["contract"]))
        or not isinstance(value["deal_room"], str)
    ):
        raise PilotError("prepare_bridge_invalid")
    return value


def _preview_record(stage: dict, prepared: dict, *, prepared_at: str) -> dict:
    return {
        "stage_id": stage["stage_id"],
        "stage_digest": stage["stage_digest"],
        "offer_id": stage["offer_id"],
        "frame_sha256": stage["frame_sha256"],
        "full_spec_sha256": stage["full_spec_sha256"],
        "material_sha256": stage["material_sha256"],
        "accept_line": prepared["accept_line"],
        "accept_sha256": prepared["accept_sha256"],
        "contract": prepared["contract"],
        "deal_room": prepared["deal_room"],
        "expires_ms": stage["expires_ms"],
        "prepared_at": prepared_at,
        "posted": False,
    }


def _private_record(stage: dict, prepared: dict, *, prepared_at: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "stage_id": stage["stage_id"],
        "stage_digest": stage["stage_digest"],
        "offer_id": stage["offer_id"],
        "accept_line": prepared["accept_line"],
        "accept_sha256": prepared["accept_sha256"],
        "contract": prepared["contract"],
        "deal_room": prepared["deal_room"],
        "preimage": prepared["lock_material"],
        "created_at": prepared_at,
    }


def _read_private(stage: dict) -> dict | None:
    path = _private_path(stage["stage_id"])
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PilotError("prepared_private_unreadable") from error
    required = {
        "schema_version",
        "stage_id",
        "stage_digest",
        "offer_id",
        "accept_line",
        "accept_sha256",
        "contract",
        "deal_room",
        "preimage",
        "created_at",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema_version") != SCHEMA_VERSION:
        raise PilotError("prepared_private_invalid")
    if (
        value["stage_id"] != stage["stage_id"]
        or value["stage_digest"] != stage["stage_digest"]
        or value["offer_id"] != stage["offer_id"]
        or not isinstance(value["accept_line"], str)
        or _sha(value["accept_line"]) != value["accept_sha256"]
        or not _HEX64.fullmatch(str(value["accept_sha256"]))
        or not _OFFER_ID.fullmatch(str(value["contract"]))
        or not isinstance(value["deal_room"], str)
        or not re.fullmatch(r"0x[0-9a-f]{64}", str(value["preimage"]))
        or not isinstance(value["created_at"], str)
    ):
        raise PilotError("prepared_private_invalid")
    return value


def _prepared_from_private(value: dict) -> dict:
    return {
        "accept_line": value["accept_line"],
        "accept_sha256": value["accept_sha256"],
        "contract": value["contract"],
        "deal_room": value["deal_room"],
    }


def prepare(
    stage_id: str,
    *,
    now_ms: int | None = None,
    reader=core.read_note,
    username: str | None = None,
    bridge=None,
    our_did: str | None = None,
) -> dict:
    """Signer-user-only, zero-POST PREPARE. Returns public preview only."""
    _require_signer_user(username)
    current = _now_ms() if now_ms is None else now_ms
    stage = get_stage(stage_id)
    if stage is None:
        raise PilotError("stage_not_found")
    _validated_stage(stage)
    if stage["expires_ms"] - current < MIN_PREPARE_SECONDS * 1000:
        raise PilotError("insufficient_prepare_time")
    _official_offer_check(stage["frame_text"], stage)
    _resolve_stage_notes(stage, reader=reader, now_ms=current)
    did = our_did if our_did is not None else _prepare_did()
    if not _DID.fullmatch(str(did)) or did == stage["counterpart_did"]:
        raise PilotError("prepare_did_invalid")

    private = _read_private(stage)
    preview = get_preview(stage_id)
    if preview is not None:
        if private is None:
            raise PilotError("prepared_private_missing")
        if preview["accept_sha256"] != private["accept_sha256"]:
            raise PilotError("prepared_binding_mismatch")
        return preview

    if private is not None:
        recovered = _preview_record(stage, _prepared_from_private(private), prepared_at=private["created_at"])
        _validated_preview(recovered, stage)
        previews = load_previews()
        previews["records"].append(recovered)
        previews["records"] = previews["records"][-MAX_STAGES:]
        _write_store(previews_path(), previews)
        return recovered

    prepared = (bridge or (lambda value: _prepare_bridge(value, our_did=did)))(stage)
    prepared_at = datetime.fromtimestamp(current / 1000, UTC).isoformat()
    private_dir().mkdir(parents=True, exist_ok=True, mode=0o700)
    private_record = _private_record(stage, prepared, prepared_at=prepared_at)
    observer.atomic_json_write(_private_path(stage_id), private_record, compact=True, mode=0o600)

    preview = _preview_record(stage, prepared, prepared_at=prepared_at)
    _validated_preview(preview, stage)
    previews = load_previews()
    previews["records"].append(preview)
    previews["records"] = previews["records"][-MAX_STAGES:]
    _write_store(previews_path(), previews)
    return preview


def prepare_pending(*, now_ms: int | None = None, username: str | None = None) -> list[dict]:
    """Prepare a tiny bounded set of live staged candidates; never signs or posts."""
    _require_signer_user(username)
    current = _now_ms() if now_ms is None else now_ms
    stages = sorted(load_stages()["records"], key=lambda item: item["expires_ms"])
    results: list[dict] = []
    for stage in stages:
        if len(results) >= MAX_PENDING_PER_RUN:
            break
        if stage["expires_ms"] - current < MIN_PREPARE_SECONDS * 1000:
            continue
        try:
            existing = get_preview(stage["stage_id"])
        except PilotError:
            raise
        if existing is not None:
            continue
        results.append(prepare(stage["stage_id"], now_ms=current, username=username))
    return results


def main() -> None:
    if len(os.sys.argv) == 2 and os.sys.argv[1] == "--prepare-pending":
        rows = prepare_pending()
        print(f"TCLK_PREPARE_PENDING={len(rows)}")
        for row in rows:
            print(f"TCLK_PREPARED={row['stage_id']}:{row['accept_sha256'][:16]}")
        return
    if len(os.sys.argv) != 2 or not _STAGE_ID.fullmatch(os.sys.argv[1]):
        raise SystemExit("usage: python -m flop_agent.tclk_pilot <stage-id> | --prepare-pending")
    preview = prepare(os.sys.argv[1])
    print(_canonical(preview))


if __name__ == "__main__":
    main()
