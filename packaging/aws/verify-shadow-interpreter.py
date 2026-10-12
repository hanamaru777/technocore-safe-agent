#!/usr/bin/env python3
"""One-shot FLOP-only Python 3.12 interpreter smoke on existing AWS source stage.

NO packages, no network, no Flop daemon, no signer, no state import or other-BOT writes.
Completed AWS source stage already exists; this does NOT retry the source-stage script.
"""
import datetime
import grp
import hashlib
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import time

SOURCE_SHA = "3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e"
RELEASE = Path("/opt/flop-shadow/releases") / SOURCE_SHA
STATE = Path("/var/lib/flop-shadow")
CACHE = Path("/var/cache/flop-shadow")
VENV = STATE / "venv"
SERVICE = "k137q-public-k58.service"
TIMER = "k137q-public-k58.timer"

class Stop(Exception): pass

def require(ok, why):
    if not ok:
        raise Stop(why)

def exec_checked(args, timeout=20, env=None):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, timeout=timeout, check=False, env=env)
    require(p.returncode == 0, "CHILD_STOP_" + Path(args[0]).name.upper())
    return p.stdout.strip()

def stat_secure(path, owner, mode):
    s = path.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == owner and
            stat.S_IMODE(s.st_mode) == mode,
            "SHADOW_PATH_GUARD_STOP_" + path.name)

def k137_status(name):
    text = exec_checked(["systemctl", "show", name, "--no-pager",
                         "-p", "ActiveState", "-p", "UnitFileState"])
    d = dict(x.split("=",1) for x in text.splitlines() if "=" in x)
    return d.get("ActiveState"), d.get("UnitFileState")

def snapshot():
    svc, timer = k137_status(SERVICE), k137_status(TIMER)
    require(svc[0] == "inactive" and svc[1] in ("static", "disabled") and
            timer in (("active", "enabled"), ("inactive", "disabled")),
            "K137_RUNNING_OR_UNEXPECTED_STATE_STOP")
    return svc, timer

def gate():
    mem = Path("/proc/meminfo").read_text()
    available = int(next(x.split()[1] for x in mem.splitlines()
                         if x.startswith("MemAvailable:")))
    require(available >= 1024 * 1024, "K137_MEMORY_HEADROOM_STOP")
    for which, maximum in (("memory",5.0), ("io",10.0)):
        pressure = Path("/proc/pressure/" + which).read_text().splitlines()
        full = next(x for x in pressure if x.startswith("full "))
        avg = float(next(x[6:] for x in full.split() if x.startswith("avg10=")))
        require(avg <= maximum, "K137_" + which.upper() + "_PRESSURE_STOP")
    require(shutil.disk_usage("/").free >= 20 * 1024**3,
            "K137_DISK_HEADROOM_STOP")

def safe_slot(now):
    # K137's separately owned natural Q timer fires at hh:02 and may run
    # for up to 180 seconds. 06..57 is a conservative source-only window:
    # 06 leaves a recovery margin, 57 leaves five minutes to next hh:02.
    return 6 <= now.minute <= 57


def await_k137_idle(timeout_seconds=510, interval_seconds=15):
    # No timer or K137 service is changed. This is bounded in the foreground;
    # nothing is scheduled or backgrounded. No sleeps if a safe slot exists.
    deadline = time.monotonic() + timeout_seconds
    original = None
    waiting_printed = False
    while True:
        st = snapshot()
        if original is None:
            original = st
        # A timer state change is possible naturally; never "restore" it.
        require(st[1] == original[1], "K137_TIMER_CHANGED_DURING_WAIT_STOP")
        now = datetime.datetime.now(datetime.timezone.utc)
        if safe_slot(now) and st[0] == "inactive":
            return st
        if not waiting_printed:
            print("FLOP_SHADOW_WAIT_K137_NATURAL_TIMER_WINDOW", flush=True)
            waiting_printed = True
        remaining = deadline - time.monotonic()
        require(remaining > 0, "K137_WINDOW_WAIT_TIMEOUT_STOP")
        time.sleep(min(interval_seconds, remaining))


def preflight():
    require(os.geteuid() == 0, "ROOT_REQUIRED_STOP")
    require(os.uname().machine == "x86_64" and sys.version_info >= (3, 12),
            "PYTHON_ARCH_VERSION_STOP")
    user = pwd.getpwnam("flop-shadow")
    group = grp.getgrnam("flop-shadow")
    require(user.pw_gid == group.gr_gid and
            user.pw_shell == "/usr/sbin/nologin" and
            set(os.getgrouplist(user.pw_name, user.pw_gid)) == {user.pw_gid},
            "SHADOW_USER_ISOLATION_STOP")
    stat_secure(Path("/opt/flop-shadow"), 0, 0o755)
    stat_secure(RELEASE, 0, 0o755)
    stat_secure(STATE, user.pw_uid, 0o700)
    stat_secure(CACHE, user.pw_uid, 0o700)
    require(not os.path.lexists(VENV), "SHADOW_VENV_PREEXISTING_STOP")
    require((RELEASE / "pyproject.toml").is_file() and
            (RELEASE / "uv.lock").is_file(), "SHADOW_SOURCE_MISSING_STOP")
    require(exec_checked(["git", "-C", str(RELEASE), "rev-parse", "HEAD"]) == SOURCE_SHA,
            "SHADOW_SOURCE_HEAD_DRIFT_STOP")
    require(exec_checked(["git", "-C", str(RELEASE), "status", "--porcelain"]) == "",
            "SHADOW_SOURCE_DIRTY_STOP")
    require(exec_checked(["git", "-C", str(RELEASE), "rev-parse",
                          "HEAD:uv.lock"]) == "03117a907b31fbda0bea32012bdba3cf6e1e05cb",
            "SHADOW_LOCK_DRIFT_STOP")
    require(exec_checked(["git", "-C", str(RELEASE), "rev-parse",
                          "HEAD:pyproject.toml"]) == "1032be41c75f279e58374a86eddb30325125a7ab",
            "SHADOW_PROJECT_DRIFT_STOP")
    original = await_k137_idle()
    gate()
    return user, original

SMOKE = r"""
import pathlib, sys, tomllib
assert sys.version_info >= (3,12)
base = pathlib.Path(sys.argv[1])
src = base / 'src' / 'flop_agent'
assert (src / 'testnet.py').is_file()
compiled = 0
for p in sorted(src.glob('*.py')):
    assert p.is_file() and not p.is_symlink()
    compile(p.read_bytes(), str(p), 'exec')  # NO IMPORT, EXEC, OR .PYC WRITES
    compiled += 1
project = tomllib.loads((base / 'pyproject.toml').read_text())
lock = tomllib.loads((base / 'uv.lock').read_text())
assert project['project']['name'] == 'technocore-safe-agent'
assert len(lock['package']) == 36
print('FLOP_SHADOW_SOURCE_SYNTAX_PASS count=' + str(compiled), flush=True)
print('FLOP_SHADOW_DEPENDENCY_MANIFEST_STATIC_PASS count=36', flush=True)
"""

def main():
    user, original = preflight()
    print("FLOP_SHADOW_VENV_PREFLIGHT_PASS", flush=True)
    # runuser does not use account login shell; environment is explicitly cleared
    # so no operator credentials or K137 HOME leaks into this process.
    clean_env = ["env", "-i", "HOME=/var/lib/flop-shadow",
                 "PATH=/usr/bin:/bin", "LANG=C"]
    user_command = ["runuser", "-u", "flop-shadow", "--", *clean_env]
    exec_checked([*user_command, "/usr/bin/python3", "-I", "-m", "venv",
                  "--without-pip", str(VENV)], timeout=35)
    require(VENV.is_dir() and not VENV.is_symlink(), "SHADOW_VENV_MISSING_STOP")
    exec_checked([*user_command, str(VENV / "bin" / "python3"), "-I", "-c",
                  SMOKE, str(RELEASE)], timeout=45)
    gate()
    require(snapshot() == original, "K137_SERVICE_TIMER_DRIFT_STOP")
    require(not Path("/etc/systemd/system/flop-shadow.service").exists(),
            "SHADOW_SERVICE_PRESENT_STOP")
    print("FLOP_SHADOW_PYTHON_VENV_ONLY_PASS", flush=True)
    print("K137_SERVICE_TIMER_UNCHANGED_PASS", flush=True)
    print("FLOP_SHADOW_NO_DEPS_NO_NETWORK_NO_RUNTIME_PASS", flush=True)
    print("FLOP_SHADOW_OFFLINE_INTERPRETER_STAGE_PASS", flush=True)

if __name__ == "__main__":
    try:
        require(not sys.argv[1:], "ARGS_STOP")
        main()
    except (Stop, OSError, KeyError, ValueError, StopIteration,
            subprocess.TimeoutExpired) as e:
        print("FLOP_SHADOW_OFFLINE_STOP=" + (
            str(e) if isinstance(e, Stop) else type(e).__name__), flush=True)
        sys.exit(42)
