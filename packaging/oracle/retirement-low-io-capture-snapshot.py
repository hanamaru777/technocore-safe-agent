#!/usr/bin/env python3
"""Single-use LOW-IO SQLite consistent snapshots of FLOP's two INACTIVE Capture DBs.

Requires Flop OCI old source and stopped Capture unit; does not touch Signer,
Resident, application data, WAL, K137, OCI Vault, network or other BOTs.
Uses SQLite online-backup API in small batches, low IO/CPU priority and strict
resource gates. Creates Flop-only PRELIMINARY archive, NOT offsite protection.
Do not re-run after a STOP (partial staging may remain).
"""
import datetime
import json
import os
from pathlib import Path
import pwd
import resource
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
from urllib.parse import quote

ROOT = Path("/var/lib/technocore-safe-agent")
SRC = Path("/opt/technocore-safe-agent")
OLD_HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
DEST = ROOT / "retirement-capture-preliminary-v1"
TEMP = ROOT / ".retirement-capture-preliminary-v1.partial"
DATABASES = (
    "observer/lobby-capture.sqlite3",
    "observer/lobby-capture-service.sqlite3",
)
MAX_RUNTIME = 900
MAX_PAGE_COUNT = 400_000
BATCH_PAGES = 32
SLEEP_BETWEEN_BATCHES = 0.04
MIN_MEM_AVAILABLE_KIB = 300 * 1024
MIN_DISK_EXTRA = 2 * 1024**3

class Stop(Exception): pass

def check(ok, reason):
    if not ok:
        raise Stop(reason)

def command(argv, timeout=4, env=None):
    proc = subprocess.run(argv, capture_output=True, text=True,
                          check=False, timeout=timeout, env=env)
    check(proc.returncode == 0 and len(proc.stdout) < 512,
          "TOOL_FAILED_" + Path(argv[0]).name.upper())
    return proc.stdout.strip()

def unit_state(unit):
    val = command(["systemctl","show",unit,"--no-pager","-p","ActiveState","-p","SubState","-p","MainPID"])
    return dict(x.split("=", 1) for x in val.splitlines() if "=" in x)

def units():
    capture = unit_state("technocore-safe-agent-lobby-capture.service")
    check(capture == {"ActiveState":"inactive","SubState":"dead","MainPID":"0"},
          "CAPTURE_MUST_REMAIN_STOPPED")
    signer = unit_state("technocore-safe-agent-signer.service")
    resident = unit_state("technocore-safe-agent-resident.service")
    for u in (signer, resident):
        check(u.get("ActiveState") == "active" and u.get("SubState") == "running"
              and str(u.get("MainPID", "")).isdigit()
              and int(u["MainPID"]) > 1, "PROTECTED_UNIT_DRIFT_STOP")
    return (capture, signer, resident)

def memory_and_pressure():
    data = Path("/proc/meminfo").read_text()
    avail = int(next(x.split()[1] for x in data.splitlines()
                     if x.startswith("MemAvailable:")))
    check(avail >= MIN_MEM_AVAILABLE_KIB, "OCI_MEMORY_HEADROOM_STOP")
    for name, maximum in (("memory", 5.0), ("io", 10.0)):
        text = Path("/proc/pressure/" + name).read_text()
        full = next(x for x in text.splitlines() if x.startswith("full "))
        avg = float(next(x[6:] for x in full.split() if x.startswith("avg10=")))
        check(avg <= maximum, "OCI_" + name.upper() + "_PRESSURE_STOP")

def safe_input(name):
    check(name in DATABASES, "NOT_A_CAPTURE_DB_STOP")
    base = ROOT
    for component in name.split("/")[:-1]:
        base /= component
        st = base.lstat()
        check(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode),
              "CAPTURE_PARENT_STOP")
    file = ROOT / name
    info = file.lstat()
    check(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
          "CAPTURE_DB_FILE_STOP")
    check(0 < info.st_size < 1024**3, "CAPTURE_DB_SIZE_STOP")
    return file, info.st_size

def preflight():
    check(os.geteuid() == 0 and not sys.argv[1:], "ROOT_NO_ARGS_STOP")
    check(pwd.getpwnam("technocore").pw_uid != 0, "FLOP_OCI_USER_STOP")
    for p in (SRC, ROOT):
        st = p.lstat()
        check(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode),
              "FLOP_OCI_ROOT_STOP")
    check((SRC / "src/flop_agent/oracle_signer.py").is_file(),
          "FLOP_OCI_SOURCE_ID_STOP")
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": "/nonexistent",
           "GIT_TERMINAL_PROMPT":"0", "GIT_OPTIONAL_LOCKS":"0",
           "GIT_CONFIG_NOSYSTEM":"1", "GIT_CONFIG_GLOBAL":"/dev/null"}
    head = command(["git","-C",str(SRC),"-c","safe.directory="+str(SRC),
                    "rev-parse","--verify","HEAD"], env=env)
    check(head == OLD_HEAD, "FLOP_OCI_HEAD_DRIFT_STOP")
    check(not os.path.lexists(DEST) and not os.path.lexists(TEMP),
          "ARCHIVE_PREEXISTS_DO_NOT_RERUN")
    before = units()
    inputs = [safe_input(name) for name in DATABASES]
    free = shutil.disk_usage(ROOT).free
    check(free > MIN_DISK_EXTRA + sum(s for _,s in inputs),
          "INSUFFICIENT_ARCHIVE_DISK_STOP")
    memory_and_pressure()
    check(shutil.which("ionice") is not None, "IO_IDLE_PRIORITY_UNAVAILABLE_STOP")
    return before, inputs

def lower_priority():
    os.nice(19)
    command(["ionice","-c","3","-p",str(os.getpid())])
    # Hard cap virtual address space; not a replacement for per-process cgroup.
    max_vm = 384 * 1024**2
    resource.setrlimit(resource.RLIMIT_AS, (max_vm, max_vm))

def copy_db(src_path, dest_path, deadline):
    # Input mode=ro, no immutable=1 (which would ignore an important live WAL).
    uri = "file:" + quote(str(src_path), safe="/") + "?mode=ro"
    count = {"steps": 0}
    with sqlite3.connect(uri, uri=True, timeout=1,
                         cached_statements=0) as source:
        source.execute("PRAGMA query_only=ON")
        source.execute("PRAGMA cache_size=-256")
        pages = source.execute("PRAGMA page_count").fetchone()[0]
        check(0 < pages <= MAX_PAGE_COUNT, "SQLITE_PAGE_COUNT_STOP")
        with sqlite3.connect(str(dest_path), timeout=2,
                             cached_statements=0) as out:
            out.execute("PRAGMA cache_size=-256")
            def progress(status, remaining, total):
                count["steps"] += 1
                check(time.monotonic() < deadline, "SQLITE_BACKUP_TIMEOUT_STOP")
                check(total <= MAX_PAGE_COUNT, "SQLITE_BACKUP_GROWTH_STOP")
                if count["steps"] % 16 == 0:
                    memory_and_pressure()
                    units()
                time.sleep(SLEEP_BETWEEN_BATCHES)
            source.backup(out, pages=BATCH_PAGES, progress=progress, sleep=0.2)
            dest_pages = out.execute("PRAGMA page_count").fetchone()[0]
            check(dest_pages > 0 and dest_pages <= MAX_PAGE_COUNT,
                  "SQLITE_RESULT_PAGE_COUNT_STOP")
    return count["steps"], dest_path.stat().st_size

def main():
    start = time.monotonic()
    before, inputs = preflight()
    lower_priority()
    print("FLOP_OCI_CAPTURE_PRELIM_PREFLIGHT_PASS", flush=True)
    TEMP.mkdir(mode=0o700)
    entries = []
    for idx,(path,size) in enumerate(inputs):
        dst = TEMP / ("capture-" + str(idx) + ".sqlite3")
        steps, snap_size = copy_db(path, dst, start + MAX_RUNTIME)
        dst.chmod(0o600)
        check(snap_size > 0, "SQLITE_EMPTY_SNAPSHOT_STOP")
        entries.append({
            "source_relative": DATABASES[idx],
            "source_size_at_preflight": size,
            "archive_file": dst.name,
            "archive_size": snap_size,
            "backup_steps": steps,
        })
        print("FLOP_OCI_CAPTURE_PRELIM_DB_PASS index=" + str(idx)
              + " size=" + str(snap_size), flush=True)
    check(units() == before, "PROTECTED_UNIT_CHANGED_DURING_BACKUP_STOP")
    memory_and_pressure()
    manifest = {
        "kind":"preliminary_capture_only",
        "source_commit": OLD_HEAD,
        "capture_unit_remained_inactive": True,
        "signer_autopilot_and_nonce_not_archived": True,
        "off_host_restored": False,
        "sqlite_integrity_off_host_pending": True,
        "files": entries,
    }
    manifest_file = TEMP / "MANIFEST.json"
    with manifest_file.open("x", encoding="utf-8") as f:
        json.dump(manifest,f,sort_keys=True,separators=(",",":"))
        f.write("\n")
    manifest_file.chmod(0o600)
    TEMP.rename(DEST)
    print("FLOP_OCI_CAPTURE_ARCHIVE_IS_LOCAL_ONLY_NOT_RETIREMENT_PROOF", flush=True)
    print("FLOP_OCI_CAPTURE_PRELIMINARY_SNAPSHOT_PASS", flush=True)

if __name__ == "__main__":
    try:
        main()
    except (Stop, OSError, KeyError, ValueError, PermissionError,
            subprocess.TimeoutExpired, sqlite3.Error, RuntimeError) as error:
        print("FLOP_OCI_CAPTURE_SNAPSHOT_STOP=" +
              (str(error) if isinstance(error, Stop) else type(error).__name__),
              flush=True)
        sys.exit(42)
