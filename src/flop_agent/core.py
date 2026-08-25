from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

import httpx

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "local-state"
BASE_URL = "https://technocore.chat"
UPSTREAM_COMMIT = "53079408c1581f46eff6acbf6e2eada289d4332c"
SIGNER_SHA256 = "d093e89c16671a5ada8d392133e34d4433155545bade7e23f4036a1da0da4f7f"
INVISIBLE_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}


def clean_text(text: str, limit: int = 4096) -> str:
    cleaned = "".join(" " if unicodedata.category(char) in INVISIBLE_CATEGORIES else char for char in text).strip()
    if not cleaned or len(cleaned) > limit:
        raise ValueError("本文は可視文字を含み、clean後4096文字以内である必要があります")
    return cleaned


def did_note_location(did: str) -> tuple[str, str, str]:
    fingerprint = hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]
    return fingerprint[:2], fingerprint[2:], fingerprint


def signer_sha256() -> str:
    return hashlib.sha256((ROOT / "scripts" / "sign.py").read_bytes()).hexdigest()


def find_uv() -> str | None:
    """Find uv even when its Windows installer directory is not on PATH."""
    return shutil.which("uv") or next(
        (str(path) for path in (Path.home() / ".local" / "bin" / "uv.exe",) if path.is_file()), None
    )


def invoke_signer(*args: str) -> list[str]:
    """Call the unmodified official signer. Seed arrives only through SIGN_SEED."""
    uv = find_uv()
    if uv is None:
        raise RuntimeError("uv が PATH または ~/.local/bin に見つかりません")
    environment = os.environ.copy()
    if os.name == "nt":
        environment["UV_LINK_MODE"] = "copy"
    result = subprocess.run([uv, "run", "scripts/sign.py", *args], cwd=ROOT, env=environment, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError("公式 signer の実行に失敗しました: " + result.stderr.strip())
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def current_did() -> str:
    lines = invoke_signer("did")
    if len(lines) != 1 or not lines[0].startswith("did:key:z6Mk"):
        raise RuntimeError("公式 signer から有効な DID を取得できませんでした")
    return lines[0]


def make_nonce(room: str, did: str) -> str:
    STATE.mkdir(exist_ok=True)
    path = STATE / "nonces.json"
    try:
        known = json.loads(path.read_text("utf-8"))
    except FileNotFoundError:
        known = {}
    key = f"{did}|{room}"
    value = max(time.time_ns() // 1_000_000, int(known.get(key, 0)) + 1)
    if value > 9999999999999999999:
        raise RuntimeError("nonce が許容範囲を超えました")
    known[key] = value
    path.write_text(json.dumps(known, indent=2, sort_keys=True), encoding="utf-8")
    return str(value)


def read_room(room: str, since: int | None = None, wait: int | None = None) -> dict:
    params: dict[str, int | str] = {"format": "json"}
    if since is not None:
        params["since"] = since
    if wait is not None and since is not None:
        params["wait"] = min(max(wait, 0), 10)
    response = httpx.get(f"{BASE_URL}/r/{quote(room, safe='')}", params=params, timeout=20)
    response.raise_for_status()
    return response.json()


def cursor_path(room: str) -> Path:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,47}", room):
        raise ValueError("無効な room 名です")
    STATE.mkdir(exist_ok=True)
    return STATE / f"cursor-{room}.json"


def read_new(room: str) -> dict:
    path = cursor_path(room)
    since = json.loads(path.read_text("utf-8")).get("seq", 0) if path.exists() else 0
    payload = read_room(room, since=since, wait=10)
    messages = payload.get("messages", payload if isinstance(payload, list) else [])
    if messages:
        path.write_text(json.dumps({"seq": max(item["seq"] for item in messages)}), encoding="utf-8")
    return {"since": since, "messages": messages}


def append_activity(record: dict) -> dict:
    STATE.mkdir(exist_ok=True)
    path = STATE / "activities.jsonl"
    previous = ""
    if path.exists() and path.stat().st_size:
        previous = json.loads(path.read_text("utf-8").splitlines()[-1])["hash"]
    record = {**record, "previous_hash": previous}
    canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    record["hash"] = hashlib.sha256(canonical.encode()).hexdigest()
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    return record


def git_commit_sha() -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError("活動証拠に記録する Git commit SHA を取得できませんでした")
    return result.stdout.strip()


def verify_activity_log() -> tuple[bool, int]:
    path = STATE / "activities.jsonl"
    previous, count = "", 0
    if not path.exists():
        return True, 0
    for line in path.read_text("utf-8").splitlines():
        record = json.loads(line)
        recorded_hash = record.pop("hash")
        if record.get("previous_hash") != previous:
            return False, count
        canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if hashlib.sha256(canonical.encode()).hexdigest() != recorded_hash:
            return False, count
        previous, count = recorded_hash, count + 1
    return True, count


def post_signed(room: str, text: str, confirm: bool) -> dict:
    if not confirm:
        raise RuntimeError("送信はユーザー確認なしでは実行しません")
    cleaned = clean_text(text)
    did = current_did()
    nonce = make_nonce(room, did)
    signed = invoke_signer("say", room, nonce, cleaned)
    if len(signed) != 2 or signed[0] != did:
        raise RuntimeError("公式 signer の出力を検証できませんでした")
    body = {"did": did, "sig": signed[1], "nonce": nonce, "text": cleaned}
    response = httpx.post(f"{BASE_URL}/r/{quote(room, safe='')}", json=body, timeout=20)
    response.raise_for_status()
    payload = read_room(room)
    messages = payload.get("messages", payload if isinstance(payload, list) else [])
    matches = [m for m in messages if m.get("from") == did and str(m.get("nonce")) == nonce and m.get("text") == cleaned]
    if not matches:
        raise RuntimeError("送信後の投稿を確認できないため、活動記録は追加しませんでした")
    matched = matches[-1]
    return append_activity({"did": did, "room": room, "seq": matched["seq"], "ts": matched["ts"], "nonce": nonce, "text": cleaned, "permalink": f"{BASE_URL}/humans#r/{room}/{matched['seq']}", "git_commit_sha": git_commit_sha(), "executed_at": datetime.now(UTC).isoformat(), "official_commit": UPSTREAM_COMMIT})


def sync_official() -> dict:
    url = "https://api.github.com/repos/flop-labs/technocore-chat/commits/HEAD"
    response = httpx.get(url, timeout=20, headers={"Accept": "application/vnd.github+json"})
    response.raise_for_status()
    latest_commit = response.json()["sha"]
    signer_response = httpx.get(f"https://raw.githubusercontent.com/flop-labs/technocore-chat/{latest_commit}/scripts/sign.py", timeout=20)
    signer_response.raise_for_status()
    latest_signer_hash = hashlib.sha256(signer_response.content).hexdigest()
    return {"pinned_commit": UPSTREAM_COMMIT, "latest_commit": latest_commit, "upstream_commit_changed": latest_commit != UPSTREAM_COMMIT, "pinned_signer_sha256": SIGNER_SHA256, "local_signer_sha256": signer_sha256(), "latest_upstream_signer_sha256": latest_signer_hash, "local_signer_matches_pinned": signer_sha256() == SIGNER_SHA256, "upstream_signer_changed": latest_signer_hash != SIGNER_SHA256}


def doctor() -> dict:
    uv = find_uv()
    uv_version = None
    if uv:
        result = subprocess.run([uv, "--version"], text=True, capture_output=True, check=False)
        uv_version = result.stdout.strip() if result.returncode == 0 else None
    activity_valid, activity_count = verify_activity_log()
    project_copy_mode = 'link-mode = "copy"' in (ROOT / "pyproject.toml").read_text("utf-8")
    checks = {
        "windows": os.name == "nt",
        "uv_found": uv is not None,
        "uv_copy_mode": os.name != "nt" or project_copy_mode or os.environ.get("UV_LINK_MODE") == "copy",
        "official_signer_present": (ROOT / "scripts" / "sign.py").is_file(),
        "official_signer_matches_pinned": signer_sha256() == SIGNER_SHA256,
        "activity_log_valid": activity_valid,
        "git_commit_available": bool(git_commit_sha()),
    }
    return {"ok": all(checks.values()), "checks": checks, "uv_path": uv, "uv_version": uv_version, "uv_link_mode": "copy" if os.name == "nt" else "platform-default", "python": sys.version.split()[0], "activity_count": activity_count}


def secret_scan() -> list[str]:
    tracked = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout.decode().split("\0")
    hits: list[str] = []
    pattern = re.compile(r"(?i)(?:\b[0-9a-f]{64}\b|SIGN_SEED\s*=\s*[^\s'\"]+|(?:api[_-]?key|secret|private[_-]?key)\s*[:=]\s*[^\s'\"]+)")
    for name in filter(None, tracked):
        path = ROOT / name
        if name == "uv.lock":
            continue  # dependency integrity hashes are not credential material
        if path.is_file() and path.suffix not in {".pyc", ".png", ".jpg"}:
            for number, line in enumerate(path.read_text("utf-8", errors="replace").splitlines(), 1):
                is_documented_hash = (name == "SOURCES.md" and "SHA-256" in line) or "SIGNER_SHA256 =" in line
                is_required_seed_handling = "SIGN_SEED" in line and (
                    "os.environ" in line or "env:SIGN_SEED" in line or "Remove-Item Env:SIGN_SEED" in line
                )
                if pattern.search(line) and not is_documented_hash and not is_required_seed_handling:
                    hits.append(f"{name}:{number}")
    return hits
