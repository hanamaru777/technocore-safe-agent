"""Public-only Discord decision notice for a PREPAREd first tclk pilot.

This overlay reads only the public stage, public PREPARE preview, and durable public
review evidence. It never reads signer-private protocol material or approval files,
never creates an approval, never signs or posts, and never follows or executes task
content. The actual first accept remains a separate root-operated one-shot action.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from . import discord_tclk_review as app
from . import core, observer, tclk_pilot, tclk_pilot_approval, tclk_review_evidence

NOTICE_SCHEMA_VERSION = 1
NOTICE_NAME = "tclk-approval-notices.json"
MAX_NOTIFIED = 128
PREPARED_NOTICE_LIMIT = 1


class NoticeError(RuntimeError):
    """Stable presentation-only fail-closed error."""


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def notice_path():
    return core.STATE / "resident" / NOTICE_NAME


def _default_notice_state() -> dict:
    return {"schema_version": NOTICE_SCHEMA_VERSION, "notified": []}


def _load_notice_state() -> dict:
    path = notice_path()
    if not path.exists():
        return _default_notice_state()
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise NoticeError("approval_notice_state_unreadable") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "notified"}
        or value.get("schema_version") != NOTICE_SCHEMA_VERSION
        or not isinstance(value.get("notified"), list)
        or len(value["notified"]) > MAX_NOTIFIED
    ):
        raise NoticeError("approval_notice_state_invalid")
    seen: set[str] = set()
    for item in value["notified"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"stage_id", "approval_digest", "notified_at"}
            or not isinstance(item.get("stage_id"), str)
            or not tclk_pilot_approval._HEX32.fullmatch(item["stage_id"])
            or not isinstance(item.get("approval_digest"), str)
            or not tclk_pilot_approval._HEX64.fullmatch(item["approval_digest"])
            or not isinstance(item.get("notified_at"), str)
            or item["stage_id"] in seen
        ):
            raise NoticeError("approval_notice_state_invalid")
        seen.add(item["stage_id"])
    return value


def _save_notice_state(value: dict) -> None:
    value["notified"] = value["notified"][-MAX_NOTIFIED:]
    try:
        observer.atomic_json_write(notice_path(), value, compact=True, mode=0o640)
    except OSError as error:
        raise NoticeError("approval_notice_state_write_failed") from error


def _evidence_for(stage: dict) -> dict:
    try:
        record = tclk_review_evidence.get(stage["offer_id"])
    except tclk_review_evidence.EvidenceError as error:
        raise NoticeError("approval_evidence_unavailable") from error
    if record is None:
        raise NoticeError("approval_evidence_missing")
    full = record.get("full_spec")
    material = record.get("material")
    material_hash = material.get("sha256") if isinstance(material, dict) else None
    if (
        record.get("offer_id") != stage.get("offer_id")
        or record.get("job_id") != stage.get("job_id")
        or record.get("frame_sha256") != stage.get("frame_sha256")
        or record.get("expires_ms") != stage.get("expires_ms")
        or record.get("accepted") is not False
        or not isinstance(full, dict)
        or full.get("sha256") != stage.get("full_spec_sha256")
        or material_hash != stage.get("material_sha256")
    ):
        raise NoticeError("approval_evidence_binding_mismatch")
    return record


def _decision_notice(prepared: dict, evidence: dict, *, now_ms: int) -> str:
    stage = prepared["stage"]
    preview = prepared["preview"]
    digest = prepared["approval_digest"]
    remaining = max(1, (stage["expires_ms"] - now_ms) // 60_000)
    spec = evidence["full_spec"]
    material = evidence["material"]
    lines = [
        "🟠 tclk/1 PREPARE完了 — あなたの承認待ち",
        f"job: a2a/{app._sanitize_note(stage['job_id'], 64)}",
        f"残り承認時間: 約{remaining}分 | rail: PaperRail / no-value rehearsal",
        f"task: {app._sanitize_note(spec['value'], 360)}",
        f"stage id: {stage['stage_id']}",
        f"offer id: {stage['offer_id']}",
        f"frame sha256: {stage['frame_sha256']}",
        f"full spec sha256: {stage['full_spec_sha256']}",
    ]
    if material is not None:
        lines.append(f"material sha256: {stage['material_sha256']}")
    lines.extend([
        f"accept sha256: {preview['accept_sha256']}",
        f"contract: {preview['contract_id']}",
        f"deal room: {preview['deal_room']}",
        f"approval digest: {digest}",
    ])
    if evidence.get("external_url_present"):
        lines.append("注意: task内にURL文字列があります。BOTは開いていません。")
    lines.extend([
        "",
        "内容を確認して本当に進める場合だけ、OracleへSSHして次の1行を実行:",
        f"sudo /usr/local/sbin/technocore-tclk-approve {stage['stage_id']} {digest} APPROVE",
        "",
        "このDiscord通知だけではacceptされません。Discord/ChatGPTは署名・投稿できません。",
    ])
    return "\n".join(lines)


def _new_prepared_approval_notices() -> list[str]:
    """Return bounded durable decision notices; public/local reads only."""
    current = _now_ms()
    try:
        state = _load_notice_state()
        paths = sorted(tclk_pilot.preview_dir().glob("*.json"), key=lambda path: path.stat().st_mtime)
    except (NoticeError, OSError):
        return []

    notified = {item["stage_id"]: item["approval_digest"] for item in state["notified"]}
    candidates: list[tuple[int, dict, dict]] = []
    for path in paths:
        stage_id = path.stem
        try:
            prepared = tclk_pilot_approval.public_prepared_approval(stage_id, now_ms=current)
            evidence = _evidence_for(prepared["stage"])
        except (tclk_pilot_approval.ApprovalError, NoticeError):
            continue
        old_digest = notified.get(stage_id)
        if old_digest is not None:
            # A digest change for the same immutable stage is never a reason to prompt
            # again. Treat it as fail-closed presentation corruption.
            continue
        candidates.append((prepared["stage"]["expires_ms"], prepared, evidence))

    rendered: list[str] = []
    for _, prepared, evidence in sorted(candidates, key=lambda item: item[0])[:PREPARED_NOTICE_LIMIT]:
        stage_id = prepared["stage"]["stage_id"]
        digest = prepared["approval_digest"]
        rendered.append(_decision_notice(prepared, evidence, now_ms=current))
        state["notified"].append({
            "stage_id": stage_id,
            "approval_digest": digest,
            "notified_at": datetime.now(UTC).isoformat(),
        })
        try:
            _save_notice_state(state)
        except NoticeError:
            # If durable dedupe cannot be written, suppress the notice rather than
            # risk restart spam with a high-stakes approval command.
            return []
    return rendered


_ORIGINAL_NOTICES = app._new_auto_review_notices


def _combined_notices() -> list[str]:
    return [*_ORIGINAL_NOTICES(), *_new_prepared_approval_notices()]


def main() -> None:
    # discord_tclk_review.main installs this module-global callback into the accepted
    # knowledge/control event loop. We replace only the notice callback before that.
    app._new_auto_review_notices = _combined_notices
    app.main()


if __name__ == "__main__":
    main()
