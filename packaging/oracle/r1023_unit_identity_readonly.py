#!/usr/bin/env python3
"""R1023 original Oracle systemd metadata witness. Read-only; never a fence."""
from __future__ import annotations

import hashlib
import json
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
EXPECTED = frozenset(PREFIX + name for name in UNIT_SOURCES)
TEMPLATES = (PREFIX + "tclk-accept@.service", PREFIX + "tclk-reveal@.service")
SIGNERS = frozenset(PREFIX + name for name in (
    "signer.service", "tclk-accept@.service", "tclk-reveal@.service",
    "close1-approved-trade.service", "close1-batch-trade.service"))
FILE_STATES = frozenset(("enabled", "enabled-runtime", "linked", "linked-runtime",
    "alias", "masked", "masked-runtime", "static", "disabled", "indirect",
    "generated", "transient", "bad"))
LOAD_STATES = frozenset(("loaded", "not-found", "bad-setting", "error", "masked", "stub", "merged"))
ACTIVE_STATES = frozenset(("active", "reloading", "inactive", "failed", "activating",
                           "deactivating", "maintenance", "refreshing"))
ACTIVE = frozenset(("active", "activating", "reloading", "refreshing"))
MAX_INPUT = 512000
MAX_LINES = 8000
MAX_ROWS = 128
OUT_MAX = 65536
SAFE_UNKNOWN = re.compile(r"technocore-safe-agent-[a-z][a-z0-9-]{0,79}\.(?:service|timer)")
FLAGS = {
    "original_source_pin": "PASS", "no_source_or_unit_modification": "YES",
    "process_enumeration_complete": "NO", "all_writers_fenced": "NO",
    "signer_inflight_post_resolved": "NO", "capture_common_epoch_proven": "NO",
    "writer_epoch_proven": "NO", "oci_retirement": "STRICT_NO_GO",
}


class Stop(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Stop(code)


def read_command(args):
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        raise Stop("READONLY_COMMAND_STOP") from None
    need(result.returncode == 0 and len(result.stdout) <= MAX_INPUT, "READONLY_COMMAND_STOP")
    try:
        return result.stdout.decode("utf-8", "strict")
    except UnicodeError:
        raise Stop("METADATA_ENCODING_STOP") from None


def guest_preflight():
    need(sys.platform == "linux" and os.geteuid() == 0, "ORIGINAL_ROOT_OPERATOR_REQUIRED")
    need(ROOT.is_dir() and STATE.is_dir(), "WRONG_GUEST_SCOPE")
    for path in ("/opt/tradebot-k137", "/opt/tradebot-k137-private", "/opt/flop-shadow"):
        need(not Path(path).exists() and not Path(path).is_symlink(), "WRONG_GUEST_SCOPE")
    for path in (ROOT, STATE):
        mode = os.lstat(path).st_mode
        need(stat.S_ISDIR(mode) and not stat.S_ISLNK(mode), "ROOT_TYPE_STOP")
    head = read_command(("git", "-c", f"safe.directory={ROOT}", "-C", str(ROOT),
                         "rev-parse", "--verify", "HEAD"))
    need(head.strip() == ORIGINAL_HEAD, "ORIGINAL_HEAD_MISMATCH_STOP")


def classify(name):
    if name in EXPECTED:
        return name
    for template in TEMPLATES:
        start = template.replace("@.service", "@")
        if name.startswith(start) and name.endswith(".service"):
            instance = name[len(start):-len(".service")]
            if re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", instance):
                return template
    return None


def identity(name):
    known = classify(name)
    if known:
        return known
    if SAFE_UNKNOWN.fullmatch(name):
        return name
    return "redacted-sha256-" + hashlib.sha256(name.encode("utf-8")).hexdigest()


def metadata_names(raw, *, live=False):
    need(type(raw) is str and len(raw.encode("utf-8")) <= MAX_INPUT, "METADATA_BOUND_STOP")
    lines = raw.splitlines()
    need(len(lines) <= MAX_LINES, "METADATA_BOUND_STOP")
    result = {}
    for line in lines:
        if not line.strip():
            continue
        cols = line.strip().removeprefix("●").split()
        need(len(cols) >= (4 if live else 2), "METADATA_ROW_STOP")
        name = cols[0]
        need(len(name) <= 256 and name.endswith((".service", ".timer"))
             and not any(ord(char) < 33 or ord(char) == 127 for char in name),
             "METADATA_NAME_STOP")
        need(name not in result, "METADATA_DUPLICATE_STOP")
        if live:
            need(cols[1] in LOAD_STATES and cols[2] in ACTIVE_STATES
                 and re.fullmatch(r"[a-z][a-z0-9-]{0,39}", cols[3]), "METADATA_STATE_STOP")
            result[name] = (cols[1], cols[2])
        else:
            need(len(cols) <= 3 and cols[1] in FILE_STATES
                 and (len(cols) == 2 or cols[2] in FILE_STATES or cols[2] == "-"),
                 "METADATA_STATE_STOP")
            result[name] = cols[1]
    return result


def analyze_units(installed, live):
    names = sorted(name for name in installed.keys() | live.keys() if name.startswith(PREFIX))
    need(len(names) <= MAX_ROWS, "UNIT_COUNT_BOUND_STOP")
    rows = {}
    for name in names:
        label = identity(name)
        row = rows.setdefault(label, {"identity": label, "known": classify(name) is not None,
                                     "installed_states": set(), "active_states": set(),
                                     "signer_candidate": label in SIGNERS})
        if name in installed:
            row["installed_states"].add(installed[name])
        if name in live:
            row["active_states"].add(live[name][1])
    units = [{**row, "installed_states": sorted(row["installed_states"]),
              "active_states": sorted(row["active_states"])} for _, row in sorted(rows.items())]
    installed_known = {classify(name) for name in installed if classify(name)}
    return {"schema_version": 1, "original_head": ORIGINAL_HEAD,
            "static_service_count": 19, "static_timer_count": 8,
            "missing_known": sorted(EXPECTED - installed_known), "units": units,
            "active_known": [row["identity"] for row in units
                             if row["known"] and ACTIVE.intersection(row["active_states"])],
            "active_signer_candidates": [row["identity"] for row in units
                                        if row["signer_candidate"] and ACTIVE.intersection(row["active_states"])],
            "flags": dict(FLAGS)}


def render(report):
    raw = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    need(len(raw.encode("ascii")) <= OUT_MAX, "REPORT_BOUND_STOP")
    return raw


def run():
    guest_preflight()
    installed = metadata_names(read_command(("systemctl", "list-unit-files",
        "--type=service", "--type=timer", "--no-legend", "--no-pager")))
    live = metadata_names(read_command(("systemctl", "list-units", "--all",
        "--type=service", "--type=timer", "--no-legend", "--no-pager")), live=True)
    print(render(analyze_units(installed, live)), end="")


if __name__ == "__main__":
    try:
        run()
    except (Stop, OSError, ValueError, TypeError, UnicodeError) as error:
        code = str(error) if isinstance(error, Stop) else "LOCAL_GUARD_STOP"
        print("FLOP_R1023_STOP=" + code)
        sys.exit(42)
