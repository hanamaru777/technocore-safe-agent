#!/usr/bin/env python3
"""R865 offline CODE-SOURCE census; never reports a live freeze or runs systemctl.

Fail closed when a new Oracle service/timer appears without explicit review.
Repo unit filenames != installed runtime unit identities. Manual invocations,
cron, root processes, and systemd transient/templated instances remain UNKNOWN.
"""
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

# Source-reviewed at main 3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e.
# These paths are NOT a list of presently running services.
REVIEWED_UNITS = frozenset((
    "airdrop-monitor.service",
    "airdrop-monitor.timer",
    "airdrop-notifier.service",
    "airdrop-notifier.timer",
    "discord.service",
    "lobby-capture.service",
    "resident.service",
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
REQUIRE_FENCING = frozenset((
    "resident.service",
    "technocore-safe-agent-signer.service",
    "technocore-safe-agent-close1-approved-trade.service",
    "technocore-safe-agent-close1-batch-trade.service",
    "technocore-safe-agent-tclk-accept@.service",
    "technocore-safe-agent-tclk-reveal@.service",
    "technocore-safe-agent-tclk-stager.service",
    "technocore-safe-agent-tclk-preparer.service",
))
STATE_ROOT = "/var/lib/technocore-safe-agent"
VALID_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")

class Stop(Exception):
    pass

def need(flag, reason):
    if not flag:
        raise Stop(reason)

def properties(content):
    need(type(content) is str and len(content) < 20000, "UNIT_TOO_LARGE")
    result = {}
    section = None
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            need(section in ("Unit", "Service", "Timer", "Install"),
                 "UNIT_SECTION_UNKNOWN")
            continue
        need(section is not None and "=" in line, "UNIT_SYNTAX_UNREVIEWED")
        key, value = line.split("=", 1)
        need(VALID_KEY.fullmatch(key) is not None, "UNIT_KEY_UNKNOWN")
        result.setdefault((section, key), []).append(value.strip())
    return result

def listed(folder):
    need(folder.is_dir() and not folder.is_symlink(), "UNIT_FOLDER_INVALID")
    return {p.name for p in folder.iterdir()
            if p.name.endswith((".service", ".timer"))}

def inventory(folder):
    actual = listed(folder)
    need(actual == REVIEWED_UNITS, "UNREVIEWED_SERVICE_OR_TIMER_STOP")
    report = []
    for name in sorted(actual):
        file = folder / name
        need(file.is_file() and not file.is_symlink(), "UNIT_FILE_INVALID")
        lines = properties(file.read_text(encoding="utf-8"))
        service = name.endswith(".service")
        if service:
            command = lines.get(("Service", "ExecStart"), [])
            need(len(command) == 1 and bool(command[0]),
                 "SERVICE_EXECSTART_UNREVIEWED")
        else:
            need(("Timer", "OnBootSec") in lines or
                 ("Timer", "OnUnitActiveSec") in lines or
                 ("Timer", "OnCalendar") in lines or
                 ("Timer", "OnUnitInactiveSec") in lines,
                 "TIMER_SCHEDULE_UNREVIEWED")
            # Do not infer installed target from filename: Unit= can differ,
            # and a timer can activate a service from another unit directory.
        rw = lines.get(("Service", "ReadWritePaths"), [])
        may_write = service and (
            any(STATE_ROOT in s for s in rw) or
            any(STATE_ROOT in s for s in lines.get(("Service", "Environment"), [])) or
            any(STATE_ROOT in s for s in lines.get(("Service", "ExecStart"), [])))
        if name in REQUIRE_FENCING:
            need(may_write, "PINNED_WRITER_CHANGED_STOP")
        report.append({
            "filename": name, "kind": "service" if service else "timer",
            "has_flop_state_reference": bool(may_write),
            "has_oneshot_or_template": (
                "@" in name or "oneshot" in lines.get(("Service", "Type"), [])),
        })
    digest = sha256(json.dumps(report, sort_keys=True,
                               separators=(",", ":")).encode()).hexdigest()
    return {"unit_sources": len(report),
            "potential_state_writer_sources":
                sum(row["has_flop_state_reference"] for row in report),
            "timer_sources":
                sum(row["kind"] == "timer" for row in report),
            "unit_registry_sha256": digest}

def main():
    need(len(sys.argv) == 1, "NO_ARGS_REQUIRED")
    root = Path(__file__).resolve().parents[2]
    need(not Path("/opt/technocore-safe-agent").exists()
         and not Path("/opt/tradebot-k137").exists(),
         "NOT_FOR_LIVE_PRODUCTION_USE")
    info = inventory(root / "packaging" / "oracle")
    print("FLOP_R865_STATIC_UNIT_SOURCE_CENSUS_PASS")
    for key in sorted(info):
        print("FLOP_R865_" + key.upper() + "=" + str(info[key]))
    print("FLOP_R865_LIVE_INSTALLED_UNITS_NOT_OBSERVED")
    print("FLOP_R865_RUNTIME_TIMERS_CGROUPS_MANUAL_CRON_NOT_OBSERVED")
    print("FLOP_R865_SOURCE_WRITER_EPOCH_NOT_PROVEN")
    print("FLOP_R865_NO_BACKUP_UPLOAD_SIGNING_OR_DELETION_AUTHORIZATION")

if __name__ == "__main__":
    try:
        main()
    except (Stop, OSError, UnicodeError, ValueError, IndexError) as e:
        print("FLOP_R865_SOURCE_CENSUS_STOP=" +
              (str(e) if isinstance(e, Stop) else type(e).__name__))
        sys.exit(42)
