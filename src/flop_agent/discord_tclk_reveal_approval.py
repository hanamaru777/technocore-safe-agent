"""Public-only Discord notice for the second, irreversible tclk reveal approval.

The card is derived only from public reveal PREPARE state. It never reads the signer-private
reveal line/preimage and cannot approve, sign, post, or claim anything.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from . import discord_tclk_approval as app
from . import core, observer, tclk_pilot, tclk_pilot_reveal, tclk_pilot_reveal_approval

SCHEMA_VERSION = 1
MAX_NOTIFIED = 128


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def _state_path():
    return core.STATE / "resident" / "tclk-reveal-approval-notices.json"


def _load() -> dict:
    path = _state_path()
    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "notified": []}
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema_version": SCHEMA_VERSION, "notified": []}
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION or not isinstance(value.get("notified"), list):
        return {"schema_version": SCHEMA_VERSION, "notified": []}
    return value


def _save(value: dict) -> bool:
    value["notified"] = value["notified"][-MAX_NOTIFIED:]
    try:
        observer.atomic_json_write(_state_path(), value, compact=True, mode=0o640)
        return True
    except OSError:
        return False


def _new_reveal_notices() -> list[str]:
    current = _now_ms()
    state = _load()
    seen = {row.get("stage_id") for row in state["notified"] if isinstance(row, dict)}
    candidates = []
    try:
        paths = sorted(tclk_pilot_reveal.preview_dir().glob("*.json"), key=lambda p: p.stat().st_mtime)
    except OSError:
        return []
    for path in paths:
        stage_id = path.stem
        if stage_id in seen:
            continue
        try:
            prepared = tclk_pilot_reveal_approval.public_prepared_approval(stage_id, now_ms=current)
            stage = tclk_pilot.load_stage(stage_id, require_live=False)
        except Exception:
            continue
        preview = prepared["preview"]
        if stage.get("stage_digest") != preview.get("stage_digest") or stage.get("offer_id") != preview.get("offer_id"):
            continue
        candidates.append((preview["claim_by_ms"], stage, prepared))
    if not candidates:
        return []
    _, stage, prepared = sorted(candidates, key=lambda row: row[0])[0]
    preview = prepared["preview"]
    digest = prepared["approval_digest"]
    mins = max(1, (preview["claim_by_ms"] - current) // 60_000)
    notice = "\n".join([
        "🔴 tclk/1 REVEAL準備完了 — 2回目の明示承認が必要",
        f"job: a2a/{stage['job_id']}",
        f"残りclaim時間: 約{mins}分 | PaperRail / no-value rehearsal",
        f"stage id: {stage['stage_id']}",
        f"contract: {preview['contract_id']}",
        f"deal room: {preview['deal_room']}",
        f"accept sha256: {preview['accept_sha256']}",
        f"lock sha256: {preview['lock_line_sha256']}",
        f"work evidence sha256: {preview['work_evidence_sha256']}",
        f"reveal sha256: {preview['reveal_sha256']}",
        f"reveal approval digest: {digest}",
        "",
        "注意: REVEALするとhash-lockのpreimageが公開され、PaperRailの完了処理へ進みます。",
        "accept時の承認はREVEAL承認として使われません。内容を確認して進める場合だけOracleで実行:",
        f"sudo /usr/local/sbin/technocore-tclk-reveal-approve {stage['stage_id']} {digest} APPROVE_REVEAL",
        "",
        "このDiscord通知だけではREVEALされません。",
    ])
    state["notified"].append({"stage_id": stage["stage_id"], "approval_digest": digest, "notified_at": datetime.now(UTC).isoformat()})
    if not _save(state):
        return []
    return [notice]


_ORIGINAL_COMBINED = app._combined_notices


def _combined_notices() -> list[str]:
    return [*_ORIGINAL_COMBINED(), *_new_reveal_notices()]


def main() -> None:
    app._combined_notices = _combined_notices
    app.main()


if __name__ == "__main__":
    main()
