#!/usr/bin/env python3
"""R1091: OCI-original FLOP one-pass disk attribution and safe-cache purge.

Single bounded metadata walk. Only canonical Python/test caches under the APP
root may be deleted on explicit --delete-proven-cache, never ANY STATE entry.
No shell, network, service, Git mutation, signer, database, or copy operation.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

APP = Path("/opt/technocore-safe-agent")
STATE = Path("/var/lib/technocore-safe-agent")
ORIGINAL_HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
CACHE_DIRS = frozenset({"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"})
PROTECTED_APP = frozenset({".git", ".venv", "node_modules", "runtime", "logs", "local-state"})
MAX_ENTRIES = 100000
MAX_DEPTH = 48


class Blocked(RuntimeError):
    pass


def require(ok, reason):
    if not ok:
        raise Blocked(reason)


def protected_context(app=APP, state=STATE):
    require(sys.platform == "linux" and os.geteuid() == 0, "ORIGINAL_ROOT_REQUIRED")
    require(app == APP and state == STATE, "ORIGINAL_PATH_REQUIRED")
    for root in (app, state):
        require(root.is_absolute(), "PATH_STOP")
        for part in (root, *root.parents):
            require(not part.is_symlink(), "SYMLINK_ANCESTOR_STOP")
        s = root.lstat()
        require(stat.S_ISDIR(s.st_mode), "ROOT_TYPE_STOP")
    result = subprocess.run(
        ["/usr/bin/git", "-c", "safe.directory=" + str(app), "-C", str(app),
         "rev-parse", "--verify", "HEAD"],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=10,
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
             "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
             "GIT_OPTIONAL_LOCKS": "0"})
    require(result.returncode == 0 and result.stdout == (ORIGINAL_HEAD + "\n").encode(),
            "ORIGINAL_HEAD_DRIFT_STOP")


def classify(root_name, rel):
    if root_name == "state":
        head = rel.parts[0] if rel.parts else "root"
        if head in {"observer", "signer", "autopilot", "close1"}:
            return "state_" + head
        return "state_other_PROTECTED"
    head = rel.parts[0] if rel.parts else "root"
    if head == ".venv":
        return "app_venv_ACTIVE"
    if head == ".git":
        return "app_git_PIN_REQUIRED"
    if head == "node_modules":
        return "app_node_modules_REVIEW"
    if head in {"runtime", "logs", "local-state"}:
        return "app_" + head + "_PROTECTED"
    if any(n in CACHE_DIRS for n in rel.parts):
        return "app_PROVEN_CACHE"
    return "app_other_REVIEW"


def scan_roots(app, state, *, limit=MAX_ENTRIES):
    """Read only lstat; no bytes read, checksum, SQLite access, or link following."""
    totals, candidates, count = {}, {}, 0
    def visit(path, root_name, rel, depth, device):
        nonlocal count
        count += 1
        require(count <= limit and depth <= MAX_DEPTH, "INVENTORY_BOUND_STOP")
        s = path.lstat()
        require(s.st_dev == device, "CROSS_MOUNT_STOP")
        if stat.S_ISLNK(s.st_mode):
            size = s.st_blocks * 512
            totals[classify(root_name, rel)] = totals.get(classify(root_name, rel), 0) + size
            return
        require(stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode), "SPECIAL_OBJECT_STOP")
        size = s.st_blocks * 512
        group = classify(root_name, rel)
        totals[group] = totals.get(group, 0) + size
        if stat.S_ISDIR(s.st_mode):
            if root_name == "app" and rel.name in CACHE_DIRS and not (
                set(rel.parts) & PROTECTED_APP) and not any(
                    c == ".." for c in rel.parts):
                candidates[str(path)] = (s.st_dev, s.st_ino, s.st_mtime_ns)
            with os.scandir(path) as entries:
                for child in entries:
                    visit(Path(child.path), root_name, rel / child.name, depth + 1, device)
    for name, root in (("app", app), ("state", state)):
        visit(root, name, Path(), 0, root.lstat().st_dev)
    return totals, candidates, count


def no_active_handles(paths):
    """Fail closed if an open file/directory FD points inside a deletion candidate."""
    targets = tuple(str(p) + "/" for p in paths)
    names = tuple(str(p) for p in paths)
    count = 0
    procs = [p for p in Path("/proc").iterdir() if p.name.isdigit()]
    require(len(procs) <= 4096, "FD_SCOPE_STOP")
    for proc in procs:
        try:
            handles = list((proc / "fd").iterdir())
        except FileNotFoundError:
            continue  # Process already gone; no remaining handles
        except OSError as exc:
            raise Blocked("FD_VISIBILITY_STOP") from exc
        for fd in handles:
            count += 1
            require(count <= 65536, "FD_BOUND_STOP")
            try:
                target = os.readlink(fd)
            except FileNotFoundError:
                continue  # FD already closed
            except OSError as exc:
                raise Blocked("FD_VISIBILITY_STOP") from exc
            require(not (target in names or target.startswith(targets)),
                    "CACHE_IN_USE_STOP")


def validate_cache_subtree(path, device):
    require(shutil.rmtree.avoids_symlink_attacks, "RMTREE_FD_SAFETY_STOP")
    for base, dirs, files in os.walk(path, topdown=True, followlinks=False):
        for leaf in dirs + files:
            p = Path(base) / leaf
            s = p.lstat()
            require(s.st_dev == device and s.st_nlink == 1 if stat.S_ISREG(s.st_mode)
                    else s.st_dev == device, "CACHE_LINK_STOP")
            require(stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode),
                    "CACHE_UNEXPECTED_OBJECT_STOP")


def delete_caches(app, candidates):
    """Explicitly approved deletion of ONLY regenerated Python/test cache dirs."""
    require(app == APP, "ORIGINAL_PATH_REQUIRED")
    # Prefer outermost candidates so no path is removed twice.
    chosen = []
    for p in sorted(map(Path, candidates), key=lambda x: (len(x.parts), str(x))):
        if not any(parent == ancestor or ancestor in parent.parents for ancestor in chosen for parent in (p,)):
            chosen.append(p)
    for p in chosen:
        expected = candidates[str(p)]
        require(p.is_relative_to(app) and p.name in CACHE_DIRS and
                not (set(p.relative_to(app).parts) & PROTECTED_APP) and
                not p.is_symlink(), "CACHE_SCOPE_STOP")
        s = p.lstat()
        require(stat.S_ISDIR(s.st_mode) and (s.st_dev, s.st_ino, s.st_mtime_ns) == expected,
                "CACHE_DRIFT_STOP")
        validate_cache_subtree(p, s.st_dev)
    if chosen:
        no_active_handles(chosen)
    freed_logical = 0
    for p in chosen:
        # No other directory is ever targeted. fd-safe rmtree prevents symlink swaps.
        s = p.lstat()
        require((s.st_dev, s.st_ino, s.st_mtime_ns) == candidates[str(p)], "CACHE_DRIFT_STOP")
        shutil.rmtree(p)
        # Never output potentially unbounded per-path lists in owner SSH receipts.
    return len(chosen)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--delete-proven-cache", action="store_true")
    args = parser.parse_args()
    try:
        protected_context()
        free_before = shutil.disk_usage(APP).free
        totals, candidates, count = scan_roots(APP, STATE)
        print("R1091_ORIGINAL_SCOPE=PINNED")
        print("OBJECTS_INSPECTED=" + str(count))
        for group, amount in sorted(totals.items()):
            print(group.upper() + "_ALLOCATED_BYTES=" + str(amount))
        print("PROVEN_CACHE_DIR_COUNT=" + str(len(candidates)))
        print("PROVEN_CACHE_ESTIMATED_BYTES=" + str(totals.get("app_PROVEN_CACHE", 0)))
        if args.delete_proven_cache:
            print("DELETED_CACHE_DIR_COUNT=" + str(delete_caches(APP, candidates)))
        else:
            print("DELETE=NOT_REQUESTED")
        print("DISK_FREE_BEFORE=" + str(free_before))
        print("DISK_FREE_AFTER=" + str(shutil.disk_usage(APP).free))
        print("STATE_GIT_VENV_LOG_SIGNER_DB_DELETE=NONE")
        print("RESULT=COMPLETE")
        return 0
    except (Blocked, OSError, subprocess.SubprocessError) as exc:
        code = str(exc) if isinstance(exc, Blocked) else "UNEXPECTED_HOST_STOP"
        print("RESULT=STOP;CODE=" + code, file=sys.stderr)
        return 42


if __name__ == "__main__":
    raise SystemExit(main())
