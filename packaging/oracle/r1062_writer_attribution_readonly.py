#!/usr/bin/env python3
"""R1062 original OCI one-shot writer admission READ-ONLY census.

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
MAX_SECONDS = 50.0
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


def systemd_list(argv, label):
    """Never fail whole census due to one systemd query.

    Every error is mapped to a fixed class. NEVER echo systemd output or
    stderr. Both queries are independently attempted once; failed data
    contributes NO count and is marked explicitly NOT_VERIFIED.
    """
    need(label in ("UNITS", "UNITFILES"), "SYSTEMD_STAGE_STOP")
    try:
        p = subprocess.run(argv, capture_output=True, timeout=10,
                           check=False, env={
                               "PATH": "/usr/bin:/bin", "LANG": "C",
                               "HOME": "/nonexistent",
                               "GIT_TERMINAL_PROMPT": "0",
                               "GIT_OPTIONAL_LOCKS": "0"})
        if p.returncode != 0:
            return set(), "NONZERO"
        if len(p.stdout) > MAX_UNIT_BYTES:
            return set(), "OVERSIZE"
        try:
            return unit_tokens(p.stdout.decode("utf8", "strict")), "OK"
        except (UnicodeError, Stop):
            return set(), "PARSE"
    except subprocess.TimeoutExpired:
        return set(), "TIMEOUT"
    except OSError:
        return set(), "EXEC"


# Exact 27 original source templates, independently checked by prior R1052.
# Four extra identities were seen by prior R1034, but these labels are not
# proof that the original extra units still own today's corresponding paths.
UNIT_TEMPLATES = (
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
EXPECTED_UNITS = frozenset(PREFIX + x for x in UNIT_TEMPLATES)
EXTRA_UNITS = frozenset(PREFIX + x for x in (
    "close1-discord-activation.service",
    "close1-discord-activation.timer",
    "close1-standalone-watch.timer",
    "postreboot-check.service",
))
SIGNER_TEMPLATES = frozenset(PREFIX + x for x in (
    "signer.service", "tclk-accept@.service", "tclk-reveal@.service",
    "close1-approved-trade.service", "close1-batch-trade.service",
))
DYNAMIC_PREFIXES = (PREFIX + "tclk-accept@", PREFIX + "tclk-reveal@")


def classify_unit_identity(name):
    """Public fixed class only; never return a dynamic identifier."""
    if name in EXPECTED_UNITS:
        return "ORIGINAL_TEMPLATE"
    if name in EXTRA_UNITS:
        return "HISTORICAL_EXTRA"
    if (name.endswith(".service") and
            any(name.startswith(p) for p in DYNAMIC_PREFIXES)):
        return "DYNAMIC_INSTANCE"
    return "UNKNOWN"


def unit_roles(names):
    need(type(names) is set and len(names) <= 4096,
         "UNIT_ROLES_BOUNDS_STOP")
    classified = {name: classify_unit_identity(name) for name in names}
    originals = sum(kind == "ORIGINAL_TEMPLATE" for kind in classified.values())
    dynamic = sum(kind == "DYNAMIC_INSTANCE" for kind in classified.values())
    extras = sum(kind == "HISTORICAL_EXTRA" for kind in classified.values())
    other = sum(kind == "UNKNOWN" for kind in classified.values())
    need(originals + dynamic + extras + other == len(names),
         "UNIT_ROLE_SUM_STOP")
    return {
        "expected_template_present": originals,
        "expected_template_missing": len(EXPECTED_UNITS) - originals,
        "historical_extra_present": extras,
        "new_or_unknown_unit_names": other,
        "dynamic_actual_instances": dynamic,
        "signer_route_template_present": len(names & SIGNER_TEMPLATES),
    }


def classify_state_fd_target(target):
    """Return a FIXED bucket. No basename/hash/cmdline ever printed."""
    if not isinstance(target, str):
        return "OTHER"
    prefix = str(STATE) + "/"
    if not target.startswith(prefix):
        return "OTHER"
    suffix = target[len(prefix):]
    if suffix.startswith(("signer/", "autopilot/", "nonces.json")):
        return "SIGNER"
    if suffix.startswith(("lobby-", "observer/", "capture/")):
        return "CAPTURE"
    if suffix.startswith(("tclk-", "tclk/")):
        return "TCLK"
    if suffix.startswith(("close1-", "close1/")):
        return "CLOSE1"
    return "OTHER"



def unit_census():
    loaded, loaded_status = systemd_list(
        ("systemctl", "list-units", "--all", "--plain", "--no-legend",
         "--no-pager", "--type=service", "--type=timer"), "UNITS")
    files, files_status = systemd_list(
        ("systemctl", "list-unit-files", "--all", "--no-legend",
         "--no-pager", "--type=service", "--type=timer"), "UNITFILES")
    both = loaded_status == "OK" and files_status == "OK"
    # NEVER present a zero as a proven absence when either query failed.
    ours = {s for s in (loaded | files) if s.startswith(PREFIX)} if both else set()
    dynamic = {s for s in ours if ("tclk-accept@" in s or
                                  "tclk-reveal@" in s)}
    roles = unit_roles(ours) if both else dict.fromkeys(unit_roles(set()), 0)
    return ({"loaded_unit_names": len(loaded) if both else 0,
             "unitfile_names": len(files) if both else 0,
             "flop_prefixed_total": len(ours),
             "flop_dynamic_instance_or_template_names": len(dynamic),
             "dynamic_or_manual_instance_proven_absent": "NO",
             "unprefixed_unit_exec_targets_proven_exhaustive": "NO",
             "unit_restart_or_reboot_fence": "NOT_PROVEN",
             **roles},
            loaded_status, files_status)



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
            if stat.S_ISLNK(meta.st_mode):
                unverified_links += 1
            else:
                unverified_special += 1
    need(len(candidates) <= MAX_CRON_FILES, "CRON_COUNT_STOP")
    regular = matches = bytes_read = 0
    unverified_links = unverified_special = unverified_regular = 0
    for path in candidates:
        try:
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 65536:
                unknown += 1
                if stat.S_ISLNK(before.st_mode):
                    unverified_links += 1
                elif not stat.S_ISREG(before.st_mode):
                    unverified_special += 1
                else:
                    unverified_regular += 1
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
            unverified_regular += 1
    return {"cron_regular_read": regular, "cron_unverified_entries": unknown,
            "cron_unverified_links": unverified_links,
            "cron_unverified_specials": unverified_special,
            "cron_unverified_regulars": unverified_regular,
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
    race = permission = other_unknown = 0
    writer_categories = {"SIGNER": 0, "CAPTURE": 0, "TCLK": 0,
                         "CLOSE1": 0, "OTHER": 0}
    for path in entries:
        try:
            raw = (path / "cmdline").read_bytes()[:4097]
            if len(raw) > 4096:
                unknown += 1
                other_unknown += 1
                continue
            if b"technocore-safe-agent" in raw or b"flop_agent" in raw:
                matched += 1
            fdpath = path / "fd"
            fds = list(fdpath.iterdir())
            if len(fds) > MAX_FD:
                unknown += 1
                other_unknown += 1
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
                        writer_categories[classify_state_fd_target(target)] += 1
                except PermissionError:
                    unknown += 1
                    permission += 1
                except (FileNotFoundError, ProcessLookupError):
                    unknown += 1
                    race += 1
                except OSError:
                    unknown += 1
                    other_unknown += 1
        except PermissionError:
            unknown += 1
            permission += 1
        except (FileNotFoundError, ProcessLookupError):
            unknown += 1
            race += 1
        except OSError:
            unknown += 1
            other_unknown += 1
    return {"scanned_pids": len(entries), "flop_commandline_matches": matched,
            "open_flop_state_write_file_descriptors": writable,
            "writable_fd_signer": writer_categories["SIGNER"],
            "writable_fd_capture": writer_categories["CAPTURE"],
            "writable_fd_tclk": writer_categories["TCLK"],
            "writable_fd_close1": writer_categories["CLOSE1"],
            "writable_fd_other": writer_categories["OTHER"],
            "unknown_or_raced_process_fd_objects": unknown,
            "proc_unknown_race": race,
            "proc_unknown_permission": permission,
            "proc_unknown_other": other_unknown,
            "fd_snapshot_is_durable_fence": "NO"}


# Only fixed stage identifiers can leave the original guest; no exception
# message, path, command line, unit name, DID, credential or other data.
# A STOP is not evidence of host health or a writer fence.
STAGE = "PREFLIGHT"


def best_effort(producer):
    """Read-only independent census; unknown never becomes an empty PASS."""
    try:
        return producer(), "OK"
    except (Stop, OSError, UnicodeError, subprocess.TimeoutExpired,
            ValueError, TypeError, RuntimeError):
        return None, "UNVERIFIED"


def run():
    global STAGE
    started = time.monotonic()
    STAGE = "PREFLIGHT"
    preflight()  # Security preflight is MANDATORY: not best-effort.
    STAGE = "UNITS"
    units, live_status, unitfiles_status = unit_census()
    STAGE = "CRON"
    cron, cron_status = best_effort(cron_census)
    STAGE = "PROCESS"
    processes, process_status = best_effort(proc_census)
    # Missing evidence stays distinguishable and NEVER implies zero findings.
    if cron is None:
        cron = {"cron_regular_read": 0, "cron_unverified_entries": 1,
                "cron_unverified_links": 0, "cron_unverified_specials": 0,
                "cron_unverified_regulars": 1,
                "cron_direct_flop_line_matches": 0,
                "cron_indirect_launch_exhaustively_proven": "NO"}
    if processes is None:
        processes = {"scanned_pids": 0, "flop_commandline_matches": 0,
                     "open_flop_state_write_file_descriptors": 0,
                     "writable_fd_signer": 0, "writable_fd_capture": 0,
                     "writable_fd_tclk": 0, "writable_fd_close1": 0,
                     "writable_fd_other": 0,
                     "unknown_or_raced_process_fd_objects": 1,
                     "proc_unknown_race": 0,
                     "proc_unknown_permission": 0,
                     "proc_unknown_other": 1,
                     "fd_snapshot_is_durable_fence": "NO"}
    STAGE = "REPORT"
    report = {"schema_version": 1, "original_source_head": HEAD,
              "units": units, "cron": cron, "processes": processes,
              "systemd_loaded_status": live_status,
              "systemd_unitfiles_status": unitfiles_status,
              "cron_collection_status": cron_status,
              "proc_collection_status": process_status,
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
        print("FLOP_R1062_STOP=" + redacted_stop(STAGE, str(error)))
        sys.exit(42)
    except (OSError, UnicodeError, subprocess.TimeoutExpired,
            ValueError, TypeError):
        print("FLOP_R1062_STOP=" + redacted_stop(STAGE))
        sys.exit(42)
