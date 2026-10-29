"""R1096: AWS K137 new FLOP-only storage/development-readiness inventory.

READ ONLY: fixed existing FLOP staging and landing directories. Never examines,
opens or modifies TradeBot paths. No cleaning, no process starts, no writes.
This is current-capacity evidence, not a rerun of historical R1067/R1071.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time

SHADOW = Path("/opt/flop-shadow")
PINNED_RELEASE = SHADOW / "releases" / "3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e"
LANDING = Path("/var/lib/flop-migration-r1066")
PROTECTED = (Path("/opt/tradebot-k137"), Path("/opt/tradebot-k137-private"))
MAX_ENTRIES = 100000
MAX_SECONDS = 30

class Stop(Exception):
    pass

def require(ok, reason):
    if not ok:
        raise Stop(reason)

def category(path: Path) -> str:
    name = path.name
    if name.endswith((".tmp", ".temp")):
        return "TEMP_UNVERIFIED"
    if name.endswith((".tar", ".gz", ".zip", ".zst", ".bak", ".backup")):
        return "ARCHIVE_UNVERIFIED"
    if name.endswith((".db", ".sqlite", ".sqlite3", "-wal", "-shm")):
        return "DATABASE_PROTECTED"
    if name.endswith((".log", ".jsonl")):
        return "LOG_OR_HISTORY_PROTECTED"
    if name.endswith((".pyc", ".pyo")):
        return "GENERATED_UNVERIFIED"
    return "OTHER_PROTECTED"

def scan(root: Path, start: float) -> dict:
    if not root.exists():
        require(not root.is_symlink(), "ROOT_LINK_STOP")
        return {"exists": False, "allocated_bytes": 0, "objects": 0,
                "regular_files": 0, "symlinks": 0, "classes": {},
                "largest": []}
    require(not root.is_symlink(), "ROOT_LINK_STOP")
    first = root.lstat()
    require(stat.S_ISDIR(first.st_mode), "ROOT_TYPE_STOP")
    device = first.st_dev
    count = files = links = used = 0
    classes: dict[str, dict[str, int]] = {}
    biggest: list[dict] = []
    stack = [(root, 0)]
    while stack:
        require(time.monotonic()-start < MAX_SECONDS, "TIME_BUDGET_STOP")
        node, depth = stack.pop()
        require(depth <= 48, "DEPTH_BOUND_STOP")
        s = node.lstat()
        require(s.st_dev == device, "CROSS_MOUNT_STOP")
        count += 1
        require(count <= MAX_ENTRIES, "ENTRY_BOUND_STOP")
        allocated = s.st_blocks * 512
        used += allocated
        if stat.S_ISLNK(s.st_mode):
            links += 1
            continue
        if stat.S_ISDIR(s.st_mode):
            with os.scandir(node) as listing:
                stack.extend((Path(e.path), depth + 1) for e in listing)
            continue
        require(stat.S_ISREG(s.st_mode), "SPECIAL_OBJECT_STOP")
        files += 1
        classification = category(node)
        group = classes.setdefault(classification, {"files": 0, "allocated_bytes": 0})
        group["files"] += 1
        group["allocated_bytes"] += allocated
        path_token = hashlib.sha256(str(node.relative_to(root)).encode(
            "utf-8", errors="surrogateescape")).hexdigest()[:12]
        biggest.append({"token": path_token, "type": classification,
                        "allocated_bytes": allocated})
        biggest.sort(key=lambda x: x["allocated_bytes"], reverse=True)
        if len(biggest) > 8:
            biggest.pop()
    return {"exists": True, "allocated_bytes": used, "objects": count,
            "regular_files": files, "symlinks": links,
            "classes": classes, "largest": biggest}

def main():
    try:
        require(sys.platform == "linux" and os.geteuid() != 0, "NONROOT_REQUIRED")
        require(os.getlogin() == "ubuntu" if os.isatty(0) else
                __import__("pwd").getpwuid(os.getuid()).pw_name == "ubuntu",
                "K137_USER_STOP")
        require(PINNED_RELEASE.is_dir() and not PINNED_RELEASE.is_symlink(),
                "KNOWN_FLOP_STAGE_MISSING_STOP")
        # Protected TradeBot paths are NEVER traversed or modified, even read-only.
        for fixed in (SHADOW, LANDING):
            require(not fixed.is_symlink(), "ROOT_SYMLINK_STOP")
        before = shutil.disk_usage("/")
        start = time.monotonic()
        results = {"shadow": scan(SHADOW, start), "landing": scan(LANDING, start)}
        after = shutil.disk_usage("/")
        require(after.total == before.total, "DISK_TOPOLOGY_DRIFT_STOP")
        output = {"phase": "R1096", "result": "AWS_FLOP_SCOPE_ONLY",
                  "action": "READ_ONLY", "host": "K137_STAGE_CONFIRMED",
                  "disk_total_bytes": after.total, "disk_free_bytes": after.free,
                  "tradebot_protected": "NOT_SCANNED_OR_MODIFIED",
                  "flop_shadow": results["shadow"],
                  "flop_landing": results["landing"],
                  "source_oci_bytes": "UNVERIFIED_AFTER_R1095",
                  "cutover": "NO_GO", "oci_retirement": "STRICT_NO_GO"}
        print(json.dumps(output, separators=(",", ":"), sort_keys=True))
        return 0
    except (Stop, OSError) as exc:
        code = str(exc) if isinstance(exc, Stop) else "HOST_STOP"
        print(json.dumps({"phase": "R1096", "result": "STOP", "code": code,
                          "action": "READ_ONLY"}))
        return 42

if __name__ == "__main__":
    raise SystemExit(main())
