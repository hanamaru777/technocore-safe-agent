#!/usr/bin/env python3
"""R867 once-only FLOP OCI runtime writer surface observation, READ ONLY.

No authority to freeze, restart, snapshot, sign, or delete any VM.
No secrets, process argv or environment values are printed.
Not a global no-writer or one-writer epoch proof.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

EXPECTED_SOURCE_HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
APP = Path("/opt/technocore-safe-agent")
STATE = Path("/var/lib/technocore-safe-agent")
SOURCE_UNITS = frozenset((
    "airdrop-monitor.service", "airdrop-monitor.timer",
    "airdrop-notifier.service", "airdrop-notifier.timer",
    "discord.service", "lobby-capture.service", "resident.service",
    "technocore-safe-agent-close1-approved-trade.service",
    "technocore-safe-agent-close1-auto-resident.service",
    "technocore-safe-agent-close1-batch-trade.service",
    "technocore-safe-agent-close1-standalone-watch.service",
    "technocore-safe-agent-metadata-block.service",
    "technocore-safe-agent-precontest-supervisor.service",
    "technocore-safe-agent-precontest-supervisor.timer",
    "technocore-safe-agent-signer.service",
    "technocore-safe-agent-tclk-accept@.service",
    "technocore-safe-agent-tclk-lock-watcher.service",
    "technocore-safe-agent-tclk-lock-watcher.timer",
    "technocore-safe-agent-tclk-preparer.service",
    "technocore-safe-agent-tclk-preparer.timer",
    "technocore-safe-agent-tclk-reveal-preparer.service",
    "technocore-safe-agent-tclk-reveal-preparer.timer",
    "technocore-safe-agent-tclk-reveal@.service",
    "technocore-safe-agent-tclk-stager.service",
    "technocore-safe-agent-tclk-stager.timer",
    "technocore-safe-agent-tclk-work-watcher.service",
    "technocore-safe-agent-tclk-work-watcher.timer",
))
PREFIX = "technocore-safe-agent-"
MAX_OUTPUT = 96 * 1024


class Stop(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Stop(reason)


def installed_name(source):
    require(source in SOURCE_UNITS, "UNKNOWN_SOURCE_UNIT")
    return source if source.startswith(PREFIX) else PREFIX + source


def unit_file_names(raw):
    require(isinstance(raw, str) and len(raw) < MAX_OUTPUT,
            "UNIT_FILE_LIST_INVALID")
    names = set()
    for line in raw.splitlines():
        fields = line.split()
        if fields and fields[0].startswith(PREFIX) and fields[0].endswith(
                (".service", ".timer")):
            names.add(fields[0])
    require(len(names) <= 128, "TOO_MANY_INSTALLED_UNITS")
    return names


def timer_file_states(raw):
    """One read-only systemctl response; retain exact known timer identities privately."""
    unit_file_names(raw)
    result = {}
    for line in raw.splitlines():
        fields = line.split()
        if fields and fields[0].startswith(PREFIX) and fields[0].endswith(".timer"):
            require(len(fields) >= 2, "TIMER_UNITFILE_STATE_MISSING")
            require(fields[0] not in result, "DUPLICATE_TIMER_UNITFILE")
            result[fields[0]] = fields[1]
    return result


def timer_state_counts(states):
    counts = {"enabled": 0, "disabled": 0, "masked": 0, "other": 0}
    for setting in states.values():
        if setting in ("enabled", "enabled-runtime"):
            counts["enabled"] += 1
        elif setting in ("disabled", "disabled-runtime"):
            counts["disabled"] += 1
        elif setting in ("masked", "masked-runtime"):
            counts["masked"] += 1
        else:
            counts["other"] += 1
    return counts


def timer_file_state_counts(raw):
    """Aggregate unit-file settings, not current scheduling or writer quiescence."""
    return timer_state_counts(timer_file_states(raw))


def loaded_states(raw):
    require(isinstance(raw, str) and len(raw) < MAX_OUTPUT,
            "LOADED_UNIT_LIST_INVALID")
    states = {}
    for line in raw.splitlines():
        fields = line.split()
        if fields and fields[0] == "●":
            fields = fields[1:]
        if len(fields) >= 4 and fields[0].startswith(PREFIX) and fields[0].endswith(
                (".service", ".timer")):
            require(len(states) < 128, "TOO_MANY_LOADED_UNITS")
            states[fields[0]] = fields[2]
    return states


def parent_template(name):
    require(re.fullmatch(r"technocore-safe-agent-[A-Za-z0-9_-]+@[^/@\s]+\.service",
                         name) is not None, "TEMPLATE_INSTANCE_INVALID")
    return name.split("@", 1)[0] + "@.service"


def compare(installed, states):
    expected = {installed_name(n) for n in SOURCE_UNITS}
    allnames = set(installed) | set(states)
    instances = [n for n in allnames if n not in expected and "@" in n
                 and parent_template(n) in expected]
    unknown = sorted(allnames - expected - set(instances))
    missing = sorted(expected - installed)
    return {
        "source_units_expected": len(expected),
        "installed_count": len(installed),
        "loaded_count": len(states),
        "loaded_active_count": sum(s == "active" for s in states.values()),
        "loaded_failed_count": sum(s == "failed" for s in states.values()),
        "loaded_active_timer_count": sum(
            name.endswith(".timer") and state == "active"
            for name, state in states.items()),
        "missing_count": len(missing),
        "unknown_count": len(unknown),
        "unknown_loaded_active_count": sum(states.get(n) == "active" for n in unknown),
        "template_instance_count": len(instances),
        "template_instance_active_count": sum(states.get(n) == "active" for n in instances),
        "unknown_digests": [hashlib.sha256(n.encode()).hexdigest()[:16]
                            for n in unknown],
        "missing_digests": [hashlib.sha256(n.encode()).hexdigest()[:16]
                            for n in missing],
    }


def known_unit_masks(installed, loaded, timer_states):
    """Fixed sorted source registry; bit i denotes its i-th item, never a unit name."""
    ordered = sorted(installed_name(name) for name in SOURCE_UNITS)
    require(len(ordered) == len(set(ordered)) == 27, "SOURCE_UNIT_ORDER_INVALID")
    require(set(timer_states) <= installed, "TIMER_NOT_INSTALLED")
    def bits(predicate):
        value = sum(1 << i for i, name in enumerate(ordered) if predicate(name))
        return format(value, "0" + str((len(ordered) + 3) // 4) + "x")
    return {
        "known_unit_order_sha256": hashlib.sha256(
            "\\n".join(ordered).encode("utf-8")).hexdigest(),
        "known_installed_mask_hex": bits(lambda name: name in installed),
        "known_loaded_active_mask_hex": bits(
            lambda name: loaded.get(name) == "active"),
        "known_loaded_failed_mask_hex": bits(
            lambda name: loaded.get(name) == "failed"),
        "known_timer_enabled_mask_hex": bits(
            lambda name: timer_states.get(name) in ("enabled", "enabled-runtime")),
        "known_timer_masked_mask_hex": bits(
            lambda name: timer_states.get(name) in ("masked", "masked-runtime")),
    }


def command(argv, timeout=6):
    try:
        p = subprocess.run(argv, check=False, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=timeout,
                           env={"PATH": "/usr/bin:/bin", "LANG": "C",
                                "GIT_CONFIG_GLOBAL": "/dev/null",
                                "GIT_CONFIG_NOSYSTEM": "1"}, text=True)
    except (OSError, subprocess.TimeoutExpired):
        raise Stop("READONLY_COMMAND_UNAVAILABLE") from None
    require(p.returncode == 0, "READONLY_COMMAND_FAILED")
    require(len(p.stdout) < MAX_OUTPUT, "READONLY_OUTPUT_TOO_LARGE")
    return p.stdout


def process_count():
    proc = Path("/proc")
    pids = sorted(int(p.name) for p in proc.iterdir() if p.name.isdigit())
    require(len(pids) <= 4096, "PROCESS_COUNT_EXCEEDED")
    count = 0
    for pid in pids:
        try:
            with (proc / str(pid) / "cmdline").open("rb") as stream:
                raw = stream.read(1025)
        except (OSError, PermissionError, ProcessLookupError):
            continue
        if any(mark in raw for mark in
               (b"flop_agent", b"technocore-safe-agent", b"technocore_safe_agent")):
            count += 1
    return count


def host_gate():
    require(os.name == "posix" and sys.platform == "linux" and
            os.geteuid() == 0 and len(sys.argv) == 1,
            "ROOT_LINUX_NO_ARGS_REQUIRED")
    require(APP.is_dir() and STATE.is_dir() and
            (APP / "src/flop_agent/oracle_signer.py").is_file(),
            "NOT_FLOP_SOURCE_HOST")
    require(not Path("/opt/tradebot-k137").exists(), "K137_NOT_ALLOWED")
    actual = command(["git", "-C", str(APP), "-c",
                      "safe.directory=" + str(APP),
                      "rev-parse", "--verify", "HEAD"]).strip()
    require(actual == EXPECTED_SOURCE_HEAD, "PRODUCTION_HEAD_CHANGED_STOP")


def main():
    host_gate()
    print("FLOP_R867_STAGE_IDENTITY_PASS", flush=True)
    unit_files_raw = command([
        "systemctl", "list-unit-files", "--no-pager", "--no-legend",
        "--plain", "--type=service", "--type=timer"])
    installed = unit_file_names(unit_files_raw)
    timer_states = timer_file_states(unit_files_raw)
    states = loaded_states(command([
        "systemctl", "list-units", "--all", "--no-pager", "--no-legend",
        "--plain", "--type=service", "--type=timer"]))
    print("FLOP_R867_STAGE_SYSTEMD_OBSERVED", flush=True)
    info = compare(installed, states)
    info["timer_unit_file_state_counts"] = timer_state_counts(timer_states)
    info.update(known_unit_masks(installed, states, timer_states))
    info["matched_flop_process_count"] = process_count()
    print("FLOP_R867_STAGE_PROC_OBSERVED", flush=True)
    info.update({
        "schema": 2, "source_commit": EXPECTED_SOURCE_HEAD,
        "installed_dropins_verified": False, "cron_verified": False,
        "manual_invocations_fenced": False, "writer_epoch_verified": False,
        "timer_schedules_fenced": False, "process_count_exhaustive": False,
        "safe_to_snapshot": False, "safe_to_delete_oracle": False,
    })
    print("FLOP_R867_READONLY_OBSERVATION=" +
          json.dumps(info, sort_keys=True, separators=(",", ":")), flush=True)
    print("FLOP_R867_NO_STOP_NO_SIGN_NO_BACKUP_NO_ORACLE_DELETE", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (Stop, OSError, ValueError, TypeError, UnicodeError) as error:
        print("FLOP_R867_STOP=" +
              (str(error) if isinstance(error, Stop) else type(error).__name__),
              flush=True)
        sys.exit(42)
