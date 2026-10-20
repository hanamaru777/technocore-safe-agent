#!/usr/bin/env python3
"""R1016 read-only original-OCI writer discovery preflight. NEVER a freeze.

Reads process and systemd *metadata only*. No systemctl mutation, no Vault or
data files, no nonce/SQLite read, no network, no service actions. Safe counts
only; deliberately NEVER authorizes a writer epoch, transfer or OCI deletion.
Must be separately inspected before any human guest execution.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ORIGINAL_HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
ROOT = Path("/opt/technocore-safe-agent")
STATE = Path("/var/lib/technocore-safe-agent")
PREFIX = "technocore-safe-agent-"
UNIT_SOURCES = (
    "airdrop-monitor.service", "airdrop-monitor.timer",
    "airdrop-notifier.service", "airdrop-notifier.timer",
    "discord.service", "lobby-capture.service", "resident.service",
    "close1-approved-trade.service", "close1-auto-resident.service",
    "close1-batch-trade.service", "close1-standalone-watch.service",
    "metadata-block.service", "precontest-supervisor.service",
    "precontest-supervisor.timer", "signer.service", "tclk-accept@.service",
    "tclk-lock-watcher.service", "tclk-lock-watcher.timer",
    "tclk-preparer.service", "tclk-preparer.timer",
    "tclk-reveal-preparer.service", "tclk-reveal-preparer.timer",
    "tclk-reveal@.service", "tclk-stager.service", "tclk-stager.timer",
    "tclk-work-watcher.service", "tclk-work-watcher.timer",
)
TEMPLATES = (PREFIX + "tclk-accept@.service",
             PREFIX + "tclk-reveal@.service")
EXPECTED = frozenset(PREFIX + item for item in UNIT_SOURCES)
MAX_LIST_LINES = 8000
MAX_PROCESS_IDS = 4096
MAX_CMDLINE = 4096
STOP_TAG = "FLOP_R1016_STOP="


class Stop(Exception):
    pass


def need(ok, why):
    if not ok:
        raise Stop(why)


def guest_preflight():
    need(sys.platform == "linux" and os.geteuid() == 0,
         "ORIGINAL_ROOT_OPERATOR_REQUIRED")
    need(ROOT.is_dir() and STATE.is_dir()
         and not Path("/opt/tradebot-k137-private").exists()
         and not Path("/opt/flop-shadow").exists(), "WRONG_GUEST_SCOPE")
    st = os.lstat(ROOT)
    need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode),
         "SOURCE_ROOT_TYPE_STOP")
    head = read_command(("git", "-c", f"safe.directory={ROOT}",
                         "-C", str(ROOT), "rev-parse", "--verify", "HEAD"))
    need(head.strip() == ORIGINAL_HEAD, "ORIGINAL_HEAD_MISMATCH_STOP")


def read_command(args):
    try:
        r = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        raise Stop("READONLY_COMMAND_FAILED_STOP") from None
    need(r.returncode == 0 and len(r.stdout) <= 512_000,
         "READONLY_COMMAND_FAILED_STOP")
    return r.stdout


def classify(name):
    """Map template INSTANCES back to one of 27 original source names."""
    if name in EXPECTED:
        return name
    for template in TEMPLATES:
        start = template.replace("@.service", "@")
        if name.startswith(start) and name.endswith(".service"):
            instance = name[len(start):-len(".service")]
            if instance and re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", instance):
                return template
    return None


def metadata_names(raw, *, active=False):
    lines = raw.splitlines()
    need(len(lines) <= MAX_LIST_LINES, "UNIT_LIST_BOUND_STOP")
    results = {}
    for row in lines:
        cols = row.strip().lstrip("●").split()
        if not cols or cols[0] in {"UNIT", "UNIT", "0", "To", "LOAD"}:
            continue
        name = cols[0]
        if not (name.endswith(".service") or name.endswith(".timer")):
            continue
        need(len(name) <= 256 and len(cols) >= (4 if active else 2),
             "UNIT_ROW_FORMAT_STOP")
        need(name not in results, "DUPLICATE_UNIT_ROW_STOP")
        results[name] = tuple(cols[1:4] if active else cols[1:2])
    return results


def analyze_units(installed, live):
    known_installed = {name for name in installed if classify(name)}
    known_live = {name for name in live if classify(name)}
    unknown = {name for name in set(installed) | set(live)
               if name.startswith(PREFIX) and not classify(name)}
    loaded_original = {classify(x) for x in known_installed}
    missing = EXPECTED - loaded_original
    active = sum(1 for name in known_live if len(live[name]) >= 3
                 and live[name][1] in {"active", "activating", "reloading"})
    active_signer = sum(1 for name in known_live
                        if any(tag in name for tag in ("-signer", "-tclk-accept@",
                                                       "-tclk-reveal@", "-close1-approved",
                                                       "-close1-batch"))
                        and live[name][1] in {"active", "activating"})
    enabled_timers = sum(1 for name in known_installed if name.endswith(".timer")
                         and installed[name][0] in {"enabled", "enabled-runtime"})
    return {"static_service_count": 19,
            "static_timer_count": 8,
            "installed_known_rows": len(known_installed),
            "active_known_rows": active,
            "active_signer_candidate_rows": active_signer,
            "enabled_timer_rows": enabled_timers,
            "missing_static_templates": len(missing),
            "unknown_flop_unit_rows": len(unknown)}


def process_witness(proc=Path("/proc")):
    try:
        names = [x for x in proc.iterdir() if x.name.isdecimal()]
    except OSError:
        raise Stop("PROC_ACCESS_STOP") from None
    need(len(names) <= MAX_PROCESS_IDS, "PROC_COUNT_BOUND_STOP")
    seen = unknown = 0
    for path in names:
        try:
            # Read no environment, no file descriptors and no user data.
            with (path / "cmdline").open("rb") as f:
                cmd = f.read(MAX_CMDLINE + 1)
            need(len(cmd) <= MAX_CMDLINE, "CMDLINE_BOUND_STOP")
            if not (b"flop_agent" in cmd or b"technocore-safe-agent" in cmd):
                continue
            seen += 1
            with (path / "cgroup").open("rb") as f:
                cg = f.read(8193)
            need(len(cg) <= 8192, "CGROUP_BOUND_STOP")
            if b"technocore-safe-agent-" not in cg:
                unknown += 1
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            # A disappearing PID is not evidence all writer processes were found.
            unknown += 1
    return {"candidate_flop_processes": seen,
            "unscoped_or_raced_processes": unknown,
            "process_scan_racy": True}


def cron_presence():
    paths = (Path("/etc/crontab"), Path("/etc/cron.d"),
             Path("/var/spool/cron/crontabs"), Path("/var/spool/cron"))
    exists = sum(p.exists() for p in paths)
    # Do not read or print any cron job content (credentials may be embedded).
    return {"cron_locations_present": exists,
            "cron_writer_discovery_complete": False}


def run():
    guest_preflight()
    installed = metadata_names(read_command((
        "systemctl", "list-unit-files", "--type=service", "--type=timer",
        "--no-legend", "--no-pager")))
    live = metadata_names(read_command((
        "systemctl", "list-units", "--all", "--type=service", "--type=timer",
        "--no-legend", "--no-pager")), active=True)
    report = {**analyze_units(installed, live),
              **process_witness(), **cron_presence()}
    for key in sorted(report):
        value = report[key]
        print(f"FLOP_R1016_{key.upper()}={str(value).upper() if isinstance(value, bool) else value}")
    print("FLOP_R1016_ORIGINAL_SOURCE_PIN=PASS")
    print("FLOP_R1016_NO_SOURCE_OR_UNIT_MODIFICATION=YES")
    print("FLOP_R1016_ALL_WRITERS_FENCED=NO")
    print("FLOP_R1016_SIGNER_INFLIGHT_POST_RESOLVED=NO")
    print("FLOP_R1016_CAPTURE_COMMON_EPOCH_PROVEN=NO")
    print("FLOP_R1016_OCI_RETIREMENT=STRICT_NO_GO")


if __name__ == "__main__":
    try:
        run()
    except (Stop, OSError, ValueError, UnicodeError) as error:
        why = str(error) if isinstance(error, Stop) else type(error).__name__
        print(STOP_TAG + why)
        sys.exit(42)
