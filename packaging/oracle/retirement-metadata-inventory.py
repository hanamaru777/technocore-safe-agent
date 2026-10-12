#!/usr/bin/env python3
"""Bounded metadata-only inventory for the FLOP-owned OCI production host.

READ ONLY: never opens FLOP state/SQLite/secrets/log files or walks directories.
Never runs a FLOP application, signs, sends network requests, or changes services.
Only predeclared file lstat(), one git rev-parse, four systemctl show calls.
No secret name/value, account config, DID, nonce or receipt content is emitted.
"""
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import time

EXPECTED_USER = "technocore"
EXPECTED_SIGNER = "technocore-signer"
SOURCE = Path("/opt/technocore-safe-agent")
ROOT = Path("/var/lib/technocore-safe-agent")

UNITS = (
    "technocore-safe-agent-resident.service",
    "technocore-safe-agent-signer.service",
    "technocore-safe-agent-lobby-capture.service",
    "technocore-safe-agent-discord.service",
)
# Curated explicit leaf names only; NO recursive traversal or file reads.
STATE_LEAVES = (
    "verified-did.json",
    "nonces.json",
    "activities.jsonl",
    "observer/observer-state.json",
    "observer/observer-config.json",
    "observer/observer-heartbeat.json",
    "observer/resident-state.json",
    "observer/resident-config.json",
    "observer/lobby-capture.sqlite3",
    "observer/lobby-capture.sqlite3-wal",
    "observer/lobby-capture.sqlite3-shm",
    "observer/lobby-capture-service.sqlite3",
    "observer/lobby-capture-service.sqlite3-wal",
    "observer/lobby-capture-service.sqlite3-shm",
    "signer/oracle-signer-receipts.json",
    "signer/signer-health.json",
    "signer/upstream-health.json",
)
STATE_DIRECTORIES = ("observer", "signer", "autopilot", "close1")
MAX_RUNTIME_SEC = 16

class Stop(Exception):
    pass

def require(ok, reason):
    if not ok:
        raise Stop(reason)

def safe_meta(base, relative):
    # No symlink can be followed, including all parent segments. Never open.
    require(not relative.startswith("/") and ".." not in relative.split("/"),
            "UNSAFE_PATH")
    path = base
    components = relative.split("/")
    for i, component in enumerate(components):
        path = path / component
        try:
            info = path.lstat()
        except FileNotFoundError:
            return "ABSENT"
        require(not stat.S_ISLNK(info.st_mode), "SYMLINK_PATH_STOP")
        require(i == len(components)-1 or stat.S_ISDIR(info.st_mode),
                "NONDIR_PARENT_PATH_STOP")
    if stat.S_ISREG(info.st_mode):
        return "FILE size=" + str(info.st_size) + " mtime_ns=" + str(info.st_mtime_ns)
    if stat.S_ISDIR(info.st_mode):
        return "DIRECTORY"
    raise Stop("UNEXPECTED_FILE_TYPE_STOP")

def systemd(unit):
    process = subprocess.run(
        ["systemctl", "show", unit, "--no-pager",
         "-p", "LoadState", "-p", "ActiveState", "-p", "SubState",
         "-p", "UnitFileState", "-p", "MainPID", "-p", "NRestarts"],
        capture_output=True, text=True, check=False, timeout=2.5,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"}
    )
    require(process.returncode == 0 and len(process.stdout) < 2000,
            "UNIT_QUERY_STOP")
    data = dict(row.split("=", 1) for row in process.stdout.splitlines()
                if "=" in row)
    fields = ("LoadState", "ActiveState", "SubState",
              "UnitFileState", "MainPID", "NRestarts")
    require(all(key in data for key in fields), "UNIT_FIELDS_STOP")
    require(all(len(data[key]) < 64 and
                all(c.isalnum() or c in "-_." for c in data[key])
                for key in fields), "UNIT_VALUE_STOP")
    return " ".join(key + "=" + data[key] for key in fields)

def main():
    start = time.monotonic()
    require(sys.argv[1:] == [], "UNEXPECTED_ARGS_STOP")
    require(sys.platform.startswith("linux"), "NOT_LINUX_STOP")
    require(os.geteuid() == 0, "ROOT_REQUIRED_STOP")
    require(pwd.getpwnam(EXPECTED_USER).pw_uid != 0 and
            pwd.getpwnam(EXPECTED_SIGNER).pw_uid != 0,
            "FLOP_USERS_NOT_FOUND_STOP")
    for base in (SOURCE, ROOT):
        info = base.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                "FLOP_OCI_ROOT_NOT_FOUND_STOP")
    require((SOURCE / ".git").is_dir(), "FLOP_OCI_GIT_NOT_PRESENT_STOP")
    # A wrong server must fail before any data metadata access. No K137 paths.
    require((SOURCE / "src/flop_agent/oracle_signer.py").is_file(),
            "FLOP_OCI_SIGNER_SOURCE_MISSING_STOP")
    head = subprocess.run(
        ["git", "-C", str(SOURCE), "-c", "safe.directory=" + str(SOURCE),
         "rev-parse", "--verify", "HEAD"],
        text=True, capture_output=True, timeout=3,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": "/nonexistent",
             "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
             "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}
    )
    require(head.returncode == 0 and len(head.stdout.strip()) == 40 and
            all(x in "0123456789abcdef" for x in head.stdout.strip()),
            "SOURCE_HEAD_UNAVAILABLE_STOP")
    print("FLOP_OCI_SOURCE_HEAD=" + head.stdout.strip(), flush=True)
    for unit in UNITS:
        print("FLOP_OCI_UNIT " + unit + " " + systemd(unit), flush=True)
    for name in STATE_DIRECTORIES:
        print("FLOP_OCI_DIR " + name + " " + safe_meta(ROOT, name), flush=True)
    for name in STATE_LEAVES:
        print("FLOP_OCI_META " + name + " " + safe_meta(ROOT, name), flush=True)
    statvfs = os.statvfs(str(ROOT))
    print("FLOP_OCI_ROOT_AVAILABLE_KIB=" + str(
        statvfs.f_bavail * statvfs.f_frsize // 1024), flush=True)
    print("FLOP_OCI_INVENTORY_ELAPSED_SEC=" + str(
        round(time.monotonic() - start, 3)), flush=True)
    require(time.monotonic() - start < MAX_RUNTIME_SEC, "TIME_BUDGET_STOP")
    print("FLOP_OCI_STATE_CONTENT_NOT_READ_NO_MUTATION_PASS", flush=True)
    print("FLOP_OCI_RETIREMENT_METADATA_INVENTORY_PASS", flush=True)

if __name__ == "__main__":
    try:
        main()
    except (Stop, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as e:
        print("FLOP_OCI_RETIREMENT_INVENTORY_STOP=" +
              (str(e) if isinstance(e, Stop) else type(e).__name__),
              flush=True)
        sys.exit(42)
