#!/usr/bin/env python3
"""R1036: one-shot original-OCI scheduled-writer route metadata. NEVER a fence."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

SOURCE = Path("/opt/technocore-safe-agent")
STATE = Path("/var/lib/technocore-safe-agent")
HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
PREFIX = "technocore-safe-agent-"
SUFFIXES = (
    "close1-discord-activation.service",
    "close1-discord-activation.timer",
    "close1-standalone-watch.timer",
    "postreboot-check.service",
)
UNIT_KEYS = ("Id", "LoadState", "ActiveState", "UnitFileState", "FragmentPath", "ExecStart")
CRON_DIRS = (Path("/etc/cron.d"), Path("/var/spool/cron/crontabs"), Path("/var/spool/cron"))
MAX_CRON_FILES = 120
MAX_CRON_FILE = 65536
MAX_CRON_TOTAL = 524288
MAX_PROC = 4096
MAX_RESULT = 16384
LIMIT_SEC = 20
FLAGS = {
    "original_source_pin": "PASS",
    "no_service_or_state_modification": "YES",
    "process_and_cron_discovery_complete": "NO",
    "all_writers_fenced": "NO",
    "signer_inflight_post_resolved": "NO",
    "capture_common_epoch_proven": "NO",
    "oci_retirement": "STRICT_NO_GO",
}

class Stop(Exception):
    pass

def need(ok, code):
    if not ok:
        raise Stop(code)

def execute(argv, stage):
    need(stage in ("HEAD", "SHOW"), "STAGE_STOP")
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=6, check=False,
                                env={"PATH": "/usr/bin:/bin", "LANG": "C",
                                     "HOME": "/nonexistent", "GIT_TERMINAL_PROMPT": "0",
                                     "GIT_OPTIONAL_LOCKS": "0"})
    except (OSError, subprocess.TimeoutExpired):
        raise Stop(stage + "_EXEC_STOP") from None
    need(result.returncode == 0 and len(result.stdout) <= 16384, stage + "_RESULT_STOP")
    try:
        return result.stdout.decode("utf-8", "strict")
    except UnicodeError:
        raise Stop(stage + "_ENCODING_STOP") from None

def preflight():
    need(sys.platform == "linux" and os.geteuid() == 0, "ROOT_STOP")
    for root in (SOURCE, STATE):
        try:
            mode = os.lstat(root).st_mode
        except OSError:
            raise Stop("SCOPE_STOP") from None
        need(stat.S_ISDIR(mode), "SCOPE_STOP")
    for forbidden in ("/opt/tradebot-k137", "/opt/tradebot-k137-private", "/opt/flop-shadow"):
        need(not Path(forbidden).exists() and not Path(forbidden).is_symlink(), "SCOPE_STOP")
    actual = execute(("git", "-c", "safe.directory=" + str(SOURCE), "-C", str(SOURCE),
                      "rev-parse", "--verify", "HEAD"), "HEAD")
    need(actual.strip() == HEAD, "HEAD_MISMATCH_STOP")

def unit_rows():
    rows = []
    for suffix in SUFFIXES:
        name = PREFIX + suffix
        text = execute(("systemctl", "show", "--no-pager",
                        "--property=" + ",".join(UNIT_KEYS), name), "SHOW")
        fields = {}
        for line in text.splitlines():
            need("=" in line, "UNIT_SCHEMA_STOP")
            key, value = line.split("=", 1)
            need(key in UNIT_KEYS and key not in fields, "UNIT_SCHEMA_STOP")
            fields[key] = value
        need(set(fields) == set(UNIT_KEYS) and fields["Id"] == name,
             "UNIT_ID_STOP")
        need(fields["LoadState"] in ("loaded", "not-found", "masked", "error", "bad-setting"),
             "UNIT_STATE_STOP")
        need(fields["ActiveState"] in ("active", "inactive", "activating", "deactivating", "failed", "reloading"),
             "UNIT_STATE_STOP")
        need(fields["UnitFileState"] in ("enabled", "disabled", "static", "masked", "linked", "transient", ""),
             "UNIT_STATE_STOP")
        command = fields["ExecStart"]
        need(len(command) <= 8192, "UNIT_COMMAND_BOUND_STOP")
        if not command:
            kind = "NO_EXEC"
        elif "flop_agent." in command and str(SOURCE) in command:
            kind = "FLOP_PYTHON"
        elif "/bin/sh" in command or "/bin/bash" in command:
            kind = "SHELL"
        else:
            kind = "OTHER_UNVERIFIED"
        fragment = fields["FragmentPath"]
        if fragment and fragment.startswith("/etc/systemd/system/") and len(fragment) <= 192:
            file_origin = "ETC_SYSTEMD"
        elif not fragment:
            file_origin = "NO_FRAGMENT"
        else:
            file_origin = "OTHER_UNVERIFIED"
        rows.append({"identity": name, "active": fields["ActiveState"],
                     "installed": fields["UnitFileState"], "load": fields["LoadState"],
                     "command_kind": kind, "fragment_origin": file_origin})
    return rows

def bounded_cron():
    candidates = []
    for root in (Path("/etc/crontab"),) + CRON_DIRS:
        try:
            info = os.lstat(root)
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode):
            candidates.append(root)
        elif stat.S_ISDIR(info.st_mode):
            try:
                entries = list(root.iterdir())
            except OSError:
                raise Stop("CRON_DIR_STOP") from None
            need(len(entries) <= MAX_CRON_FILES, "CRON_DIR_BOUND_STOP")
            candidates.extend(entries)
        else:
            raise Stop("CRON_TYPE_STOP")
    need(len(candidates) <= MAX_CRON_FILES and len(set(candidates)) == len(candidates),
         "CRON_COUNT_STOP")
    scanned = relevant = uncertain = bytes_read = 0
    for path in sorted(candidates):
        try:
            before = os.lstat(path)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                uncertain += 1
                continue
            if before.st_size > MAX_CRON_FILE:
                uncertain += 1
                continue
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOATIME", 0)
            fd = os.open(path, flags)
            try:
                opened = os.fstat(fd)
                need(stat.S_ISREG(opened.st_mode) and
                     opened.st_ino == before.st_ino and opened.st_dev == before.st_dev,
                     "CRON_FILE_DRIFT_STOP")
                data = os.read(fd, MAX_CRON_FILE + 1)
            finally:
                os.close(fd)
            need(len(data) <= MAX_CRON_FILE, "CRON_FILE_BOUND_STOP")
            bytes_read += len(data)
            need(bytes_read <= MAX_CRON_TOTAL, "CRON_TOTAL_BOUND_STOP")
            # Never print filenames, cron content, account names or commands.
            scanned += 1
            for raw in data.splitlines():
                line = raw.strip().lower()
                if not line or line.startswith(b"#"):
                    continue
                if (b"technocore-safe-agent" in line or b"flop_agent" in line
                        or b"/opt/technocore-safe-agent" in line):
                    relevant += 1
        except (PermissionError, FileNotFoundError, IsADirectoryError):
            uncertain += 1
    return {"cron_regular_files_read": scanned, "cron_flop_matching_lines": relevant,
            "cron_unverified_entries": uncertain, "cron_scan_complete": False}

def bounded_processes():
    try:
        entries = [p for p in Path("/proc").iterdir() if p.name.isdecimal()]
    except OSError:
        raise Stop("PROC_DIR_STOP") from None
    need(len(entries) <= MAX_PROC, "PROC_COUNT_STOP")
    checked = candidates = uncertain = 0
    for path in entries:
        try:
            with (path / "cmdline").open("rb") as f:
                line = f.read(4097)
            if len(line) > 4096:
                uncertain += 1
                continue
            if b"flop_agent" not in line and b"technocore-safe-agent" not in line:
                continue
            candidates += 1
            with (path / "cgroup").open("rb") as f:
                cgroup = f.read(8193)
            if len(cgroup) > 8192 or b"technocore-safe-agent-" not in cgroup:
                uncertain += 1
            checked += 1
        except (OSError, ProcessLookupError):
            uncertain += 1
    return {"matching_processes": candidates, "known_cgroup_candidates": checked,
            "unknown_or_raced_processes": uncertain, "process_scan_complete": False}

def run():
    started = time.monotonic()
    preflight()
    report = {"schema_version": 2, "original_head": HEAD,
              "units": unit_rows(), "cron": bounded_cron(),
              "processes": bounded_processes(), "flags": dict(FLAGS)}
    need(time.monotonic() - started <= LIMIT_SEC, "READ_TIME_STOP")
    raw = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    need(len(raw) <= MAX_RESULT and all(ord(x) < 128 for x in raw), "RESULT_BOUND_STOP")
    print(raw, end="")

if __name__ == "__main__":
    try:
        run()
    except (Stop, OSError, ValueError, TypeError, UnicodeError):
        print("FLOP_R1036_STOP=GUEST_GUARD_STOP")
        sys.exit(42)
