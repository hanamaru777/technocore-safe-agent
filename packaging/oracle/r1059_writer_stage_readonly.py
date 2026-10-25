#!/usr/bin/env python3
"""R1059 original OCI one-shot writer admission READ-ONLY census.

Future owner-controlled execution ONLY after separate exact carrier review.
Never run on shared K137 or other OCI machines. No start/stop, no wallet,
no external traffic and NO live writer-fence verdict. No raw commands or
private filenames are printed, even on STOP.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
APP = Path("/opt/technocore-safe-agent")
STATE = Path("/var/lib/technocore-safe-agent")
PREFIX = "technocore-safe-agent-"
UNIT_TYPES = (".service", ".timer")
CRON = (Path("/etc/crontab"), Path("/etc/cron.d"),
        Path("/var/spool/cron/crontabs"), Path("/var/spool/cron"))
MAX_PROC = 4096
MAX_FD = 1024
MAX_CRON_FILES = 240
MAX_CRON_CONTENT = 1024 * 1024
MAX_UNIT_BYTES = 1024 * 1024
MAX_SECONDS = 30.0
UNIT_NAME = re.compile(r"^[A-Za-z0-9_.@:-]+\.(?:service|timer)$")
FIXED_TIMERS = 8
FIXED_TEMPLATES = 27


class Stop(Exception):
    pass


def need(ok, reason):
    if not ok:
        raise Stop(reason)


def checked_read(argv, label):
    need(label in ("HEAD", "UNITS", "UNITFILES"), "COMMAND_STOP")
    p = subprocess.run(argv, capture_output=True, timeout=7, check=False,
                       env={"PATH": "/usr/bin:/bin", "LANG": "C",
                            "HOME": "/nonexistent", "GIT_TERMINAL_PROMPT": "0",
                            "GIT_OPTIONAL_LOCKS": "0"})
    need(p.returncode == 0 and len(p.stdout) <= MAX_UNIT_BYTES,
         label + "_OUTPUT_STOP")
    return p.stdout.decode("utf8", "strict")


def preflight():
    need(sys.platform == "linux" and os.geteuid() == 0,
         "ORIGINAL_GUEST_ROOT_ONLY_STOP")
    need(all(p.is_dir() and not p.is_symlink() for p in (APP, STATE)),
         "ORIGINAL_GUEST_PATH_STOP")
    for p in ("/opt/tradebot-k137", "/opt/tradebot-k137-private",
              "/opt/flop-shadow"):
        need(not os.path.lexists(p), "SHARED_K137_HOST_STOP")
    actual = checked_read(("git", "-c", "safe.directory=" + str(APP),
                           "-C", str(APP), "rev-parse", "--verify", "HEAD"),
                          "HEAD").strip()
    need(actual == HEAD, "EXACT_ORIGINAL_APP_HEAD_DRIFT_STOP")


def unit_tokens(text):
    """Parse systemd summary without returning any descriptions or commands."""
    need(type(text) is str and len(text.encode("utf8")) <= MAX_UNIT_BYTES,
         "UNIT_LIST_SIZE_STOP")
    names = set()
    for line in text.splitlines():
        words = line.strip().split()
        if not words or words[0].startswith(("LEGEND", "LOAD", "UNIT", "0")):
            continue
        for word in words[:2]:
            if UNIT_NAME.fullmatch(word):
                names.add(word)
                break
    need(len(names) <= 4096, "UNIT_LIST_COUNT_STOP")
    return names


def unit_census():
    loaded = unit_tokens(checked_read(
        ("systemctl", "list-units", "--all", "--plain", "--no-legend",
         "--no-pager", "--type=service", "--type=timer"), "UNITS"))
    files = unit_tokens(checked_read(
        ("systemctl", "list-unit-files", "--all", "--no-legend",
         "--no-pager", "--type=service", "--type=timer"), "UNITFILES"))
    allunits = loaded | files
    ours = {s for s in allunits if s.startswith(PREFIX)}
    dynamic = {s for s in ours if ("tclk-accept@" in s or
                                  "tclk-reveal@" in s)}
    # The following are totals only: an inactive unit is NOT a durable fence.
    return {"loaded_unit_names": len(loaded),
            "unitfile_names": len(files),
            "flop_prefixed_total": len(ours),
            "flop_dynamic_instance_or_template_names": len(dynamic),
            "dynamic_or_manual_instance_proven_absent": "NO",
            "unprefixed_unit_exec_targets_proven_exhaustive": "NO",
            "unit_restart_or_reboot_fence": "NOT_PROVEN"}


def cron_data(data: bytes) -> int:
    need(type(data) is bytes and len(data) <= 65536,
         "CRON_CONTENT_BOUND_STOP")
    return sum(1 for raw in data.splitlines()
               if raw.strip() and not raw.lstrip().startswith(b"#") and
               any(marker in raw.lower() for marker in (
                   b"technocore-safe-agent", b"flop_agent",
                   b"flop_state_dir")))


def cron_census():
    candidates = []
    unknown = 0
    for root in CRON:
        try:
            meta = root.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(meta.st_mode):
            candidates.append(root)
        elif stat.S_ISDIR(meta.st_mode):
            entries = list(root.iterdir())
            need(len(entries) <= MAX_CRON_FILES, "CRON_DIR_BOUND_STOP")
            candidates += entries
        else:
            unknown += 1
    need(len(candidates) <= MAX_CRON_FILES, "CRON_COUNT_STOP")
    regular = matches = bytes_read = 0
    for path in candidates:
        try:
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 65536:
                unknown += 1
                continue
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, "O_NOATIME", 0)
            f = os.open(path, flags)
            try:
                opened = os.fstat(f)
                need(opened.st_dev == before.st_dev and
                     opened.st_ino == before.st_ino and
                     opened.st_size == before.st_size, "CRON_RACE_STOP")
                data = os.read(f, 65537)
            finally:
                os.close(f)
            need(len(data) == before.st_size, "CRON_READ_STOP")
            bytes_read += len(data)
            need(bytes_read <= MAX_CRON_CONTENT, "CRON_TOTAL_BOUND_STOP")
            matches += cron_data(data)
            regular += 1
        except (PermissionError, FileNotFoundError, NotADirectoryError):
            unknown += 1
    return {"cron_regular_read": regular, "cron_unverified_entries": unknown,
            "cron_direct_flop_line_matches": matches,
            "cron_indirect_launch_exhaustively_proven": "NO"}


def write_fd_flags(data):
    """Linux /proc/PID/fdinfo NNN flags are octal; avoid path exposure."""
    if type(data) is not bytes or len(data) > 4096:
        return None
    for row in data.splitlines():
        if row.startswith(b"flags:"):
            try:
                flags = int(row.split(b":", 1)[1].strip(), 8)
                return (flags & os.O_ACCMODE) != os.O_RDONLY
            except (ValueError, IndexError):
                return None
    return None


def proc_census(root=Path("/proc")):
    entries = [p for p in root.iterdir() if p.name.isdecimal()]
    need(len(entries) <= MAX_PROC, "PROC_COUNT_STOP")
    matched = writable = unknown = 0
    for path in entries:
        try:
            raw = (path / "cmdline").read_bytes()[:4097]
            if len(raw) > 4096:
                unknown += 1
                continue
            if b"technocore-safe-agent" in raw or b"flop_agent" in raw:
                matched += 1
            fdpath = path / "fd"
            fds = list(fdpath.iterdir())
            if len(fds) > MAX_FD:
                unknown += 1
                continue
            for leaf in fds:
                try:
                    target = os.readlink(leaf)
                    if not (target == str(STATE) or
                            target.startswith(str(STATE) + "/")):
                        continue
                    info = (path / "fdinfo" / leaf.name).read_bytes()[:4097]
                    state = write_fd_flags(info)
                    if state is None:
                        unknown += 1
                    elif state:
                        writable += 1
                except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
                    unknown += 1
        except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
            unknown += 1
    return {"scanned_pids": len(entries), "flop_commandline_matches": matched,
            "open_flop_state_write_file_descriptors": writable,
            "unknown_or_raced_process_fd_objects": unknown,
            "fd_snapshot_is_durable_fence": "NO"}


# Only fixed stage identifiers can leave the original guest; no exception
# message, path, command line, unit name, DID, credential or other data.
# A STOP is not evidence of host health or a writer fence.
STAGE = "PREFLIGHT"


def run():
    global STAGE
    started = time.monotonic()
    STAGE = "PREFLIGHT"
    preflight()
    STAGE = "UNITS"
    units = unit_census()
    STAGE = "CRON"
    cron = cron_census()
    STAGE = "PROCESS"
    processes = proc_census()
    STAGE = "REPORT"
    report = {"schema_version": 1, "original_source_head": HEAD,
              "units": units, "cron": cron,
              "processes": processes,
              "writer_snapshot_complete_and_future_proof": "NO",
              "all_writers_fenced": "NO",
              "external_signer_post_resolved": "NO",
              "both_sqlite_common_epoch": "NOT_PROVEN",
              "no_service_file_or_network_mutation": "YES",
              "oci_retirement": "STRICT_NO_GO"}
    need(time.monotonic() - started <= MAX_SECONDS,
         "CENSUS_TIME_BUDGET_STOP")
    raw = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    need(len(raw) <= 4096, "OUTPUT_BOUND_STOP")
    print(raw)


def redacted_stop(stage: str, reason: str = "") -> str:
    """Reduce a failure to a single fixed stage. Never print the reason."""
    if stage == "PREFLIGHT":
        if reason in ("EXACT_ORIGINAL_APP_HEAD_DRIFT_STOP", "HEAD_OUTPUT_STOP"):
            return "PREFLIGHT_HEAD_STOP"
        return "PREFLIGHT_SCOPE_STOP"
    if stage in ("UNITS", "CRON", "PROCESS", "REPORT"):
        return stage + "_STOP"
    return "GUARD_STOP"


if __name__ == "__main__":
    try:
        run()
    except Stop as error:
        print("FLOP_R1059_STOP=" + redacted_stop(STAGE, str(error)))
        sys.exit(42)
    except (OSError, UnicodeError, subprocess.TimeoutExpired,
            ValueError, TypeError):
        print("FLOP_R1059_STOP=" + redacted_stop(STAGE))
        sys.exit(42)
