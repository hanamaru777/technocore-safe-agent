#!/usr/bin/env python3
"""R953: bounded no-content source metadata probe; NOT a backup or deletion tool.

New evidence only: R938 omitted original-source airdrop-radar entirely, and
aggregated installed unit status without identifying the inactive fixed unit.
NEVER open user-state file content, follow links, read /proc, or mutate state.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT = Path("/var/lib/technocore-safe-agent")
APP = Path("/opt/technocore-safe-agent")
EXPECTED_HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
# R938 skipped every other root directory, including potentially airdrop-radar.
PREVIOUS_GROUPS = frozenset((
    "observer", "autopilot", "signer", "close1", "proof-plans",
    "public-proofs", "resident-exports",
))
EXTRA_SOURCE_ROOT = "airdrop-radar"
KNOWN = PREVIOUS_GROUPS | {EXTRA_SOURCE_ROOT}
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
D_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
MAX_SECONDS = 14
MAX_FILES = 25000
MAX_DIRS = 800
MAX_DEPTH = 15
MAX_UNKNOWN_DIRECT_CHILDREN = 1024
MAX_REPORTED_LINKS = 128
CHALLENGE = re.compile(r"airdrop-radar/challenges/[a-z0-9][a-z0-9_-]{0,63}/")
ARTIFACT = re.compile(
    r"airdrop-radar/challenges/[a-z0-9][a-z0-9_-]{0,63}/artifacts/"
    r"[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*){0,2}\Z"
)
FIXED_RADAR = frozenset((
    "airdrop-radar/state.json", "airdrop-radar/current-snapshot.json",
    "airdrop-radar/last-success.json", "airdrop-radar/event-index.json",
    "airdrop-radar/events.jsonl", "airdrop-radar/precontest-supervisor.json",
    "airdrop-radar/precontest-candidates.json",
))


class Stop(Exception):
    pass


def need(ok, reason):
    if not ok:
        raise Stop(reason)


def token(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def link_scope(root, relative, target):
    # Lexical category ONLY. No realpath, stat(target), dereference or output
    # of the target, including attacker-controlled absolute path values.
    if os.path.isabs(target):
        candidate = os.path.normpath(target)
        home = os.path.normpath(str(root))
        return "absolute_inside_lexical_only" if candidate.startswith(home + "/") else "outside"
    candidate = os.path.normpath(os.path.join(os.path.dirname(relative), target))
    return "outside" if candidate == ".." or candidate.startswith("../") else "relative_inside_lexical_only"


def radar_kind(relative):
    if relative in FIXED_RADAR:
        return "radar_fixed_ledger"
    if CHALLENGE.match(relative):
        if ARTIFACT.fullmatch(relative):
            return "challenge_artifact_payload"
        if relative.endswith("/artifacts.json"):
            return "challenge_artifact_index"
        if relative.endswith("/requests.json"):
            return "challenge_request_journal"
        return "challenge_other_state_UNREVIEWED"
    if relative.startswith("airdrop-radar/challenge-candidate-reviews/"):
        return "candidate_review_UNREVIEWED"
    return "radar_UNREVIEWED"


def profile(root=ROOT, *, monotonic=time.monotonic):
    start = monotonic()
    result = {
        "status": "READONLY_METADATA_INCOMPLETE_UNTIL_PROVEN",
        "known_files": 0, "known_dirs": 0, "known_bytes": 0,
        "symlinks": 0, "special": 0, "hardlinks": 0,
        "unknown_roots": [], "symlink_classes": dict(),
        "radar": {}, "reason": "none",
        "metadata_walk_complete": False,
        "archive_complete": False, "writer_epoch_proven": False,
    }
    kinds = defaultdict(lambda: {"files": 0, "bytes": 0})
    link_types = Counter()
    seen_inodes = set()

    def guard():
        need(monotonic() - start <= MAX_SECONDS, "TIME_LIMIT")

    def record_link(fd, name, relative):
        result["symlinks"] += 1
        need(result["symlinks"] <= MAX_REPORTED_LINKS, "LINK_COUNT_LIMIT")
        target = os.readlink(name, dir_fd=fd)
        need(isinstance(target, str) and len(target) < 8192, "LINK_TARGET_OVERSIZE")
        link_types[link_scope(root, relative, target)] += 1

    def unknown_one_level(fd, root_name):
        # Unlike R938, inspect 1st-level shape of each unknown source root
        # without opening contents or descending into unapproved subtrees.
        sample = {
            "root_hash12": token(root_name), "children": 0,
            "regular_files": 0, "regular_bytes": 0,
            "dirs_not_traversed": 0, "symlinks_not_followed": 0,
            "special": 0, "classification_complete": False,
        }
        with os.scandir(fd) as entries:
            for item in entries:
                guard()
                sample["children"] += 1
                need(sample["children"] <= MAX_UNKNOWN_DIRECT_CHILDREN,
                     "UNKNOWN_CHILD_COUNT_LIMIT")
                mode = os.stat(item.name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(mode.st_mode):
                    sample["dirs_not_traversed"] += 1
                elif stat.S_ISLNK(mode.st_mode):
                    sample["symlinks_not_followed"] += 1
                    record_link(fd, item.name, root_name + "/" + item.name)
                elif stat.S_ISREG(mode.st_mode):
                    sample["regular_files"] += 1
                    sample["regular_bytes"] += mode.st_size
                else:
                    sample["special"] += 1
        return sample

    def walk(fd, prefix="", depth=0):
        guard()
        need(depth <= MAX_DEPTH, "DEPTH_LIMIT")
        result["known_dirs"] += 1
        need(result["known_dirs"] <= MAX_DIRS, "DIR_COUNT_LIMIT")
        with os.scandir(fd) as entries:
            for entry in entries:
                guard()
                name = entry.name
                need(name not in ("", ".", ".."), "UNSAFE_NAME")
                relative = (prefix + "/" + name) if prefix else name
                need(len(relative) < 512, "PATH_LIMIT")
                current = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISLNK(current.st_mode):
                    record_link(fd, name, relative)
                    continue
                if stat.S_ISDIR(current.st_mode):
                    child = os.open(name, D_FLAGS, dir_fd=fd)
                    try:
                        confirmed = os.fstat(child)
                        need((confirmed.st_dev, confirmed.st_ino) ==
                             (current.st_dev, current.st_ino), "DIRECTORY_RACE")
                        if not prefix and name not in KNOWN:
                            need(len(result["unknown_roots"]) < 32,
                                 "UNKNOWN_ROOT_LIMIT")
                            result["unknown_roots"].append(
                                unknown_one_level(child, name))
                        else:
                            walk(child, relative, depth + 1)
                    finally:
                        os.close(child)
                    continue
                if not stat.S_ISREG(current.st_mode):
                    result["special"] += 1
                    continue
                if current.st_nlink != 1:
                    result["hardlinks"] += 1
                    continue
                inode = (current.st_dev, current.st_ino)
                need(inode not in seen_inodes, "DUPLICATE_INODE")
                seen_inodes.add(inode)
                result["known_files"] += 1
                need(result["known_files"] <= MAX_FILES, "FILE_COUNT_LIMIT")
                result["known_bytes"] += current.st_size
                if relative.startswith(EXTRA_SOURCE_ROOT + "/"):
                    kind = radar_kind(relative)
                    kinds[kind]["files"] += 1
                    kinds[kind]["bytes"] += current.st_size

    try:
        fd = os.open(root, D_FLAGS)
        try:
            walk(fd)
        finally:
            os.close(fd)
    except (OSError, Stop) as exc:
        result["reason"] = str(exc) if isinstance(exc, Stop) else "METADATA_UNAVAILABLE_STOP"
    result["radar"] = dict(sorted(kinds.items()))
    result["symlink_classes"] = dict(sorted(link_types.items()))
    # Unknown roots by definition are not exhausted even after their
    # first-level metadata read. Links also remain uninterpreted.
    result["metadata_walk_complete"] = (
        result["reason"] == "none" and not result["unknown_roots"] and
        not result["symlinks"] and not result["hardlinks"] and
        not result["special"])
    return result


def source_pin():
    need(sys.platform.startswith("linux") and os.geteuid() == 0,
         "ORIGINAL_SOURCE_ROOT_REQUIRED")
    need(ROOT.is_dir() and APP.is_dir() and
         (APP / "src/flop_agent/airdrop_ledger.py").is_file(),
         "ORIGINAL_VM_SOURCE_NOT_PROVEN")
    try:
        run = subprocess.run(
            ["git", "-C", str(APP), "-c", "safe.directory=" + str(APP),
             "rev-parse", "--verify", "HEAD"],
            capture_output=True, text=True, check=False, timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Stop("SOURCE_GIT_UNAVAILABLE") from None
    need(run.returncode == 0 and run.stdout.strip() == EXPECTED_HEAD,
         "SOURCE_HEAD_DRIFT")


def fixed_units():
    # ONLY the eight historically pinned service/timer names; never dynamic
    # systemd listing, /proc inspection or creation of transient units.
    try:
        proc = subprocess.run(
            ["systemctl", "show", "--no-pager", "--property=Id,ActiveState",
             *UNITS], capture_output=True, text=True, check=False, timeout=16,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "UNAVAILABLE", "reason": "SYSTEMCTL_UNAVAILABLE"}
    if proc.returncode != 0 or len(proc.stdout) > 8192:
        return {"status": "UNAVAILABLE", "reason": "SYSTEMCTL_REJECTED"}
    states = {}
    for section in proc.stdout.strip().split("\n\n"):
        rows = dict(line.split("=", 1) for line in section.splitlines()
                    if "=" in line)
        name, state = rows.get("Id"), rows.get("ActiveState")
        if name not in UNITS or name in states or state not in (
                "active", "inactive", "failed", "activating", "deactivating"):
            return {"status": "INCOMPLETE_STOP"}
        states[name] = state
    if set(states) != set(UNITS):
        return {"status": "INCOMPLETE_STOP"}
    return {"status": "READONLY_FIXED_UNITS", "states": states}


def main():
    source_pin()
    print("R953_PIN=PASS", flush=True)
    # Classification is intentionally NOT an allowlist or retention decision.
    print("R953_METADATA=" + json.dumps(profile(), sort_keys=True), flush=True)
    print("R953_FIXED_UNITS=" + json.dumps(fixed_units(), sort_keys=True), flush=True)
    print("R953_NO_FILE_CONTENT_NO_SECRET_NO_PROC_NO_WRITE_NO_ARCHIVE_NO_DELETE", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (Stop, OSError, ValueError, TypeError) as error:
        print("R953_STOP=" + (
            str(error) if isinstance(error, Stop) else type(error).__name__),
            flush=True)
        print("R953_NO_SOURCE_MUTATION", flush=True)
        sys.exit(42)
