#!/usr/bin/env python3
"""R934: classify Flop STATE metadata without opening contents or exposing names."""
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

ROOT = Path("/var/lib/technocore-safe-agent")
APP = Path("/opt/technocore-safe-agent")
EXPECTED_HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
GROUPS = frozenset(("observer", "autopilot", "signer", "close1",
                    "proof-plans", "public-proofs", "resident-exports"))
UNITS = (
    "technocore-safe-agent-resident.service",
    "technocore-safe-agent-signer.service",
    "technocore-safe-agent-lobby-capture.service",
    "technocore-safe-agent-precontest-supervisor.timer",
    "technocore-safe-agent-tclk-stager.timer",
    "technocore-safe-agent-tclk-work-watcher.timer",
    "technocore-safe-agent-tclk-lock-watcher.timer",
    "technocore-safe-agent-tclk-reveal-preparer.timer",
)
MAX_SECONDS = 14.0
MAX_FILES = 16000
MAX_DIRS = 512
MAX_DEPTH = 15
MAX_TOP = 16
D_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)

class Stop(Exception):
    pass

def require(condition, reason):
    if not condition:
        raise Stop(reason)

def classify(relative):
    pieces = relative.split("/")
    group = pieces[0] if len(pieces) > 1 and pieces[0] in GROUPS else "root"
    name = pieces[-1].lower()
    if group == "observer":
        if name in ("lobby-capture.sqlite3", "lobby-capture-service.sqlite3"):
            category = "capture_db"
        elif name.endswith(("-wal", "-shm", "-journal")):
            category = "sqlite_sidecar"
        elif name in ("observer-state.json", "resident-state.json"):
            category = "current_observer_state"
        elif name.startswith("observer-state.json.backup-"):
            category = "observer_compaction_backup"
        elif name.endswith(".tmp") or name.startswith(".compact-"):
            category = "temporary_state"
        elif name.endswith((".log", ".jsonl", ".gz", ".zst")):
            category = "observer_logs"
        elif "backup" in name or "snapshot" in name or "archive" in name:
            category = "observer_other_backup"
        else:
            category = "observer_other_unclassified"
    elif group == "autopilot":
        if name == "autopilot-outbox.json":
            category = "autopilot_current_outbox"
        elif name.startswith("autopilot-audit.jsonl"):
            category = "autopilot_audit"
        elif len(pieces) > 2 and pieces[1] == "tclk-pilot":
            category = "autopilot_tclk"
        elif "backup" in name or "snapshot" in name:
            category = "autopilot_backup"
        else:
            category = "autopilot_other_unclassified"
    elif group == "signer":
        if len(pieces) > 2 and pieces[1].startswith("tclk-pilot-"):
            category = "signer_tclk_private"
        elif name.startswith("close1-"):
            category = "signer_finance"
        else:
            category = "signer_other"
    else:
        category = group + "_unclassified"
    return group, category

def profile(root=ROOT, *, start=None):
    if start is None:
        start = time.monotonic()
    groups = defaultdict(lambda: {"files": 0, "bytes": 0})
    categories = defaultdict(lambda: {"files": 0, "bytes": 0})
    top = []
    stats = {"files": 0, "dirs": 0, "bytes": 0,
             "unknown_root_dirs": 0, "symlinks": 0, "hardlinks": 0,
             "special": 0, "incomplete": False, "reason": "none"}
    seen = set()

    def walk(fd, prefix="", depth=0):
        require(time.monotonic() - start < MAX_SECONDS, "TIME_LIMIT")
        require(depth <= MAX_DEPTH, "DEPTH_LIMIT")
        stats["dirs"] += 1
        require(stats["dirs"] <= MAX_DIRS, "DIR_COUNT_LIMIT")
        with os.scandir(fd) as entries:
            for e in entries:
                require(time.monotonic() - start < MAX_SECONDS, "TIME_LIMIT")
                name = e.name
                require(name not in (".", "..", ""), "ENTRY_INVALID")
                rel = prefix + "/" + name if prefix else name
                require(len(rel) < 512, "PATH_LIMIT")
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    stats["symlinks"] += 1
                    continue
                if stat.S_ISDIR(info.st_mode):
                    if depth == 0 and name not in GROUPS:
                        stats["unknown_root_dirs"] += 1
                        continue
                    child = os.open(name, D_FLAGS, dir_fd=fd)
                    try:
                        checked = os.fstat(child)
                        require((checked.st_dev, checked.st_ino) ==
                                (info.st_dev, info.st_ino), "DIR_REPLACED")
                        walk(child, rel, depth+1)
                    finally:
                        os.close(child)
                    continue
                if not stat.S_ISREG(info.st_mode):
                    stats["special"] += 1
                    continue
                if info.st_nlink != 1:
                    stats["hardlinks"] += 1
                    continue
                key = (info.st_dev, info.st_ino)
                require(key not in seen, "DUPLICATE_FILE_INODE")
                seen.add(key)
                stats["files"] += 1
                require(stats["files"] <= MAX_FILES, "FILE_COUNT_LIMIT")
                stats["bytes"] += info.st_size
                group, category = classify(rel)
                groups[group]["files"] += 1
                groups[group]["bytes"] += info.st_size
                categories[category]["files"] += 1
                categories[category]["bytes"] += info.st_size
                top.append({"group": group, "class": category,
                            "bytes": info.st_size,
                            "id_hash12": hashlib.sha256(
                                rel.encode("utf-8")).hexdigest()[:12]})
                if len(top) > MAX_TOP:
                    top.sort(key=lambda o: o["bytes"], reverse=True)
                    top.pop()
    try:
        fd = os.open(root, D_FLAGS)
        try:
            walk(fd)
        finally:
            os.close(fd)
    except (OSError, Stop) as exc:
        stats["incomplete"] = True
        stats["reason"] = str(exc) if isinstance(exc, Stop) else "FILE_METADATA_UNAVAILABLE"
    if any(stats[k] for k in ("unknown_root_dirs", "symlinks", "hardlinks", "special")):
        stats["incomplete"] = True
        if stats["reason"] == "none":
            stats["reason"] = "UNCLASSIFIED_PATHS"
    return {"stats": stats, "groups": dict(sorted(groups.items())),
            "classes": dict(sorted(categories.items())),
            "largest": sorted(top, key=lambda o: o["bytes"], reverse=True)}

def original_source_gate():
    require(sys.platform.startswith("linux") and os.geteuid() == 0,
            "SOURCE_ROOT_REQUIRED")
    require(ROOT.is_dir() and APP.is_dir() and
            (APP / "src/flop_agent/oracle_signer.py").is_file(),
            "NOT_ORIGINAL_FLOP_VM")
    try:
        proc = subprocess.run(
            ["git", "-C", str(APP), "-c", "safe.directory=" + str(APP),
             "rev-parse", "--verify", "HEAD"],
            check=False, capture_output=True, text=True, timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    except (OSError, subprocess.TimeoutExpired):
        raise Stop("SOURCE_GIT_UNAVAILABLE") from None
    require(proc.returncode == 0 and proc.stdout.strip() == EXPECTED_HEAD,
            "SOURCE_HEAD_DRIFT")

def fixed_unit_status():
    """One optional fixed-size unit query; no installed-unit listing scan."""
    try:
        proc = subprocess.run(
            ["systemctl", "show", "--no-pager", "--property=Id,ActiveState", *UNITS],
            capture_output=True, text=True, check=False, timeout=16,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "UNAVAILABLE", "reason": "SYSTEMCTL_START_OR_TIMEOUT"}
    if proc.returncode != 0 or len(proc.stdout) > 8192:
        return {"status": "UNAVAILABLE", "reason": "SYSTEMCTL_REJECTED_OR_OVERSIZE"}
    counts = {"active": 0, "inactive": 0, "failed": 0, "other": 0}
    for line in proc.stdout.splitlines():
        if line.startswith("ActiveState="):
            state = line.partition("=")[2]
            counts[state if state in counts else "other"] += 1
    return {"status": "READONLY_OBSERVED", "counts": counts,
            "complete": sum(counts.values()) == len(UNITS),
            "expected_count": len(UNITS)}

def main():
    original_source_gate()
    print("R934_SOURCE_PIN=PASS", flush=True)
    report = profile()
    print("R934_METADATA=" + json.dumps(
        report, sort_keys=True, separators=(",", ":")), flush=True)
    # Even incomplete metadata is useful; unit check is independent and bounded.
    print("R934_FIXED_UNIT_STATE=" + json.dumps(
        fixed_unit_status(), sort_keys=True), flush=True)
    print("R934_METADATA_ONLY_NO_SOURCE_MUTATION_NO_BACKUP_NO_DELETION", flush=True)

if __name__ == "__main__":
    try:
        main()
    except (Stop, OSError, ValueError, TypeError) as exc:
        print("R934_STOP=" + (
            str(exc) if isinstance(exc, Stop) else type(exc).__name__
        ), flush=True)
        print("R934_NO_SOURCE_MUTATION_NO_BACKUP_NO_DELETION", flush=True)
        sys.exit(42)
