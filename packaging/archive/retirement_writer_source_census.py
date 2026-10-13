#!/usr/bin/env python3
"""R865 offline CODE-SOURCE census; never reports live service state and never controls services.

Fail closed when a new Oracle service/timer appears without explicit review.
Repo unit filenames != installed runtime unit identities. Manual invocations,
cron, root processes, and systemd transient/templated instances remain UNKNOWN.
"""
from hashlib import sha1, sha256
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
# Verified directly from canonical GitHub main tree at the frozen source SHA.
# A changed unit is NOT reviewed until a new independent audit approves it.
PINNED_SOURCE_BLOBS = {
    "airdrop-monitor.service": "5c0575c39b73c73f9df05626f43a095dba0b01c0",
    "airdrop-monitor.timer": "3224743f49b34df34acf044d42322c072f2ed641",
    "airdrop-notifier.service": "5c842d0f5fd413609fe9a09c2e79d89138bf38a5",
    "airdrop-notifier.timer": "bdb91e3c14748646dbe4f21a62acfb22dd5af991",
    "discord.service": "085b1a105e18b1f48ebcd62f74202cb16341f821",
    "lobby-capture.service": "bdf71c805d179bda50dde0df4db7930f5308099d",
    "resident.service": "67c173c328f13fc0f8ed2ec24ecec4190df35a53",
    "technocore-safe-agent-close1-approved-trade.service": "03d6ac863051637aa9b644eb55d6204421d8f081",
    "technocore-safe-agent-close1-auto-resident.service": "cd17a98f32775cdc7088943a370417df3ab3b44b",
    "technocore-safe-agent-close1-batch-trade.service": "cb2b86dcfcf23379fe29f7d629aa18bda4c25261",
    "technocore-safe-agent-close1-standalone-watch.service": "859fe465180ac26e81d09b0f0e824e151232ed21",
    "technocore-safe-agent-metadata-block.service": "4053ee9b13d82327e06c7abfdb6f8d5f41d94653",
    "technocore-safe-agent-precontest-supervisor.service": "335d0b6aaa8a49e2d8ca3bd01bed9132eb92d335",
    "technocore-safe-agent-precontest-supervisor.timer": "faeac611812f5918e22d81cb8d0a7be8a996062e",
    "technocore-safe-agent-signer.service": "d78015ce4af0d53e8f8a386e7cc4b3a0755736f6",
    "technocore-safe-agent-tclk-accept@.service": "852cd1267374bfe0d632eb901f61f73f1a9c375c",
    "technocore-safe-agent-tclk-lock-watcher.service": "13b33e269ef269b77fa8aff2ac5e09b917870c16",
    "technocore-safe-agent-tclk-lock-watcher.timer": "4cc0d709ba62b715d92d86aab9c611ed547db8b9",
    "technocore-safe-agent-tclk-preparer.service": "4e294030846e6b2cd4c7d55ac665a2073eb05293",
    "technocore-safe-agent-tclk-preparer.timer": "b014c6bbcc3df5a96bae46887a8bb7095eb5354f",
    "technocore-safe-agent-tclk-reveal-preparer.service": "ca92e84099db0ecbc6d49082ea9a6155032c5637",
    "technocore-safe-agent-tclk-reveal-preparer.timer": "df6d29fc3f860f629475e44603cfe0e4a9b360fd",
    "technocore-safe-agent-tclk-reveal@.service": "c188b89177be04982c39290f0777fdddb84cd27b",
    "technocore-safe-agent-tclk-stager.service": "6a6c452a38d7aeeacd4adb90a949ae5a74cbb6cf",
    "technocore-safe-agent-tclk-stager.timer": "0b4508bd172b830e6191aa3dedae82cc030dfd6c",
    "technocore-safe-agent-tclk-work-watcher.service": "addc9e9205038008313ee170db28580bc18bb8d2",
    "technocore-safe-agent-tclk-work-watcher.timer": "10a8cf52ea288395bc5a3decab86f94aa56499af",
}
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

def git_blob_id(raw):
    return sha1(b"blob " + str(len(raw)).encode("ascii") + bytes((0,)) + raw).hexdigest()

def inventory(folder, *, enforce_pinned=True):
    actual = listed(folder)
    need(actual == REVIEWED_UNITS, "UNREVIEWED_SERVICE_OR_TIMER_STOP")
    need(set(PINNED_SOURCE_BLOBS) == REVIEWED_UNITS,
         "PINNED_UNIT_REGISTRY_INCOMPLETE")
    report = []
    for name in sorted(actual):
        file = folder / name
        need(file.is_file() and not file.is_symlink(), "UNIT_FILE_INVALID")
        raw = file.read_bytes()
        need(0 < len(raw) < 20000, "UNIT_BYTE_LIMIT")
        lines = properties(raw.decode("utf-8"))
        source_sha = sha256(raw).hexdigest()
        if enforce_pinned:
            need(git_blob_id(raw) == PINNED_SOURCE_BLOBS[name],
                 "PINNED_SOURCE_UNIT_DRIFT_STOP")
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
            # For source unit auditing only. This is NOT evidence of an
            # installed, enabled or inactive real systemd timer.
            explicit = lines.get(("Timer", "Unit"), [])
            need(len(explicit) <= 1, "TIMER_MULTIPLE_TARGETS_STOP")
            implicit = name[:-len(".timer")] + ".service"
            target = explicit[0] if explicit else implicit
            need(target in REVIEWED_UNITS and target.endswith(".service"),
                 "TIMER_TARGET_UNREVIEWED_STOP")
        rw = lines.get(("Service", "ReadWritePaths"), [])
        may_write = service and (
            any(STATE_ROOT in s for s in rw) or
            any(STATE_ROOT in s for s in lines.get(("Service", "Environment"), [])) or
            any(STATE_ROOT in s for s in lines.get(("Service", "ExecStart"), [])))
        if name in REQUIRE_FENCING:
            need(may_write, "PINNED_WRITER_CHANGED_STOP")
        report.append({
            "filename": name, "kind": "service" if service else "timer",
            "unit_file_sha256": source_sha,
            "timer_target": target if not service else None,
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
