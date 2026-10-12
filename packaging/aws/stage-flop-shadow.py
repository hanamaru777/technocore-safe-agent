#!/usr/bin/env python3
"""FLOP AWS shadow: ONE-TIME public-source-only, OFFLINE/DISARMED stage.
No FLOP process, keys, state, systemd changes, package installs or other BOT mutation.
GitHub HTTPS read-only fetch is the sole network operation.
"""
import datetime
import os
import pathlib
import pwd
import grp
import shutil
import stat
import subprocess
import sys
import tomllib

EXPECTED = "3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e"
LOCK_BLOB = "03117a907b31fbda0bea32012bdba3cf6e1e05cb"
PROJECT_BLOB = "1032be41c75f279e58374a86eddb30325125a7ab"
URL = "https://github.com/hanamaru777/technocore-safe-agent.git"
BASES = ("/opt/flop-shadow", "/var/lib/flop-shadow", "/etc/flop-shadow",
         "/var/log/flop-shadow", "/var/cache/flop-shadow")
RELEASE = "/opt/flop-shadow/releases/" + EXPECTED
STAGING = "/var/cache/flop-shadow/.source-staging"

class Stop(Exception):
    pass

def require(ok, code):
    if not ok:
        raise Stop(code)

def command(args, timeout=12, env=None):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, timeout=timeout, env=env, check=False)
    require(p.returncode == 0, "COMMAND_STOP_" + pathlib.Path(args[0]).name.upper())
    return p.stdout.strip()

def check_parent(p):
    st = pathlib.Path(p).lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
            "UNSAFE_PARENT_STOP")

def status(unit):
    lines = command(["systemctl", "show", unit, "--no-pager",
                     "--property=ActiveState", "--property=UnitFileState"])
    d = dict(line.split("=", 1) for line in lines.splitlines() if "=" in line)
    return (d.get("ActiveState", ""), d.get("UnitFileState", ""))

def k137():
    require(pathlib.Path("/opt/tradebot-k137").exists() and
            pathlib.Path("/var/lib/tradebot-k137-public").exists(),
            "K137_EXPECTED_PATH_MISSING_STOP")
    require(pwd.getpwnam("tradebot-k137").pw_name == "tradebot-k137",
            "K137_USER_MISSING_STOP")
    srv = status("k137q-public-k58.service")
    tim = status("k137q-public-k58.timer")
    require(srv[0] == "inactive" and srv[1] in ("static", "disabled"),
            "K137_SERVICE_NOT_DISARMED_STOP")
    require(tim == ("inactive", "disabled"), "K137_TIMER_NOT_DISABLED_STOP")
    return srv, tim

def no_flop_units():
    require(not list(pathlib.Path("/etc/systemd/system").glob("flop-shadow*")),
            "FLOP_SYSTEMD_CONFLICT_STOP")
    for name in ("flop-shadow.service", "flop-shadow.timer",
                 "flop-shadow-check.service", "flop-shadow-check.timer"):
        require(status(name)[1] in ("not-found", ""),
                "FLOP_UNIT_PRESENT_STOP")

def pressure():
    memory = pathlib.Path("/proc/meminfo").read_text()
    avail = int(next(x.split()[1] for x in memory.splitlines()
                     if x.startswith("MemAvailable:")))
    def full(t):
        data = pathlib.Path("/proc/pressure/" + t).read_text().splitlines()
        line = next(x for x in data if x.startswith("full "))
        return float(next(x[6:] for x in line.split() if x.startswith("avg10=")))
    return avail, full("memory"), full("io")

def gate():
    available, mem_full, io_full = pressure()
    require(available >= 700 * 1024 and mem_full <= 5 and io_full <= 10,
            "HOST_PRESSURE_STOP")
    require(shutil.disk_usage("/").free >= 20 * (1024 ** 3),
            "DISK_HEADROOM_STOP")
    minute = datetime.datetime.now(datetime.timezone.utc).minute
    require(9 <= minute <= 50, "K137_HOURLY_WINDOW_STOP")

def git_env():
    return {"PATH":"/usr/bin:/bin", "HOME":"/nonexistent",
            "GIT_CONFIG_NOSYSTEM":"1", "GIT_CONFIG_GLOBAL":"/dev/null",
            "GIT_TERMINAL_PROMPT":"0", "GIT_ASKPASS":"/bin/false",
            "GIT_SSH_COMMAND":"/bin/false", "GIT_LFS_SKIP_SMUDGE":"1",
            "GIT_OPTIONAL_LOCKS":"0", "LANG":"C"}

def git(*args, timeout=15):
    return command(["git", "-c", "core.hooksPath=/dev/null",
                    "-c", "maintenance.auto=false", "-c", "credential.helper=",
                    "-c", "protocol.file.allow=never", "-C", STAGING, *args],
                   timeout=timeout, env=git_env())

def validate():
    require(git("rev-parse", "HEAD") == EXPECTED, "SOURCE_SHA_STOP")
    require(git("status", "--porcelain") == "", "SOURCE_NOT_CLEAN_STOP")
    require(git("rev-parse", "HEAD:uv.lock") == LOCK_BLOB, "LOCK_SHA_STOP")
    require(git("rev-parse", "HEAD:pyproject.toml") == PROJECT_BLOB,
            "PROJECT_SHA_STOP")
    modes = git("ls-files", "--stage").splitlines()
    require(all(x.startswith(("100644 ", "100755 ")) for x in modes),
            "SOURCE_SYMLINK_OR_SUBMODULE_STOP")
    src = pathlib.Path(STAGING)
    project = tomllib.loads((src / "pyproject.toml").read_text())
    lock = tomllib.loads((src / "uv.lock").read_text())
    require(project["project"]["name"] == "technocore-safe-agent",
            "PROJECT_NAME_STOP")
    require(project["project"]["requires-python"] == ">=3.12" and
            lock["requires-python"] == ">=3.12", "PYTHON_SPEC_STOP")
    names = {x["name"] for x in lock["package"]}
    require(len(names) >= 30 and
            {"cryptography", "httpx", "discord.py", "oci", "pytest"} <= names,
            "LOCK_PACKAGE_STOP")
    require(all(x.get("source", {}).get("registry", "") in
                ("https://pypi.org/simple", "") for x in lock["package"]),
            "LOCK_REGISTRY_STOP")
    require(sys.version_info >= (3, 12), "PYTHON_VERSION_STOP")
    print("FLOP_SHADOW_DEPENDENCY_LOCK_STATIC_PASS packages=" + str(len(names)),
          flush=True)

def install():
    require(os.geteuid() == 0, "ROOT_REQUIRED_STOP")
    require(os.uname().sysname == "Linux" and os.uname().machine == "x86_64",
            "HOST_ARCH_STOP")
    require("Ubuntu" in pathlib.Path("/etc/os-release").read_text(),
            "HOST_OS_STOP")
    for p in ("/opt", "/etc", "/var/lib", "/var/log", "/var/cache"):
        check_parent(p)
    for p in BASES:
        require(not os.path.lexists(p), "PREEXISTING_FLOP_SHADOW_STOP")
    try:
        pwd.getpwnam("flop-shadow")
    except KeyError:
        pass
    else:
        raise Stop("FLOP_USER_EXISTS_STOP")
    try:
        grp.getgrnam("flop-shadow")
    except KeyError:
        pass
    else:
        raise Stop("FLOP_GROUP_EXISTS_STOP")
    no_flop_units()
    original_k137 = k137()
    gate()
    print("FLOP_SHADOW_PREFLIGHT_PASS", flush=True)

    for p in BASES:
        pathlib.Path(p).mkdir(mode=0o700)
    pathlib.Path("/opt/flop-shadow/releases").mkdir(mode=0o755)
    pathlib.Path(STAGING).mkdir(mode=0o700)
    command(["git", "init", "-q", STAGING], env=git_env())
    git("fetch", "--quiet", "--depth=1", "--no-tags", URL,
        "refs/heads/main", timeout=90)
    require(git("rev-parse", "FETCH_HEAD") == EXPECTED,
            "REMOTE_HEAD_CHANGED_NO_CHECKOUT_STOP")
    git("checkout", "--quiet", "--detach", EXPECTED, timeout=30)
    validate()
    gate()
    require(k137() == original_k137, "K137_STATE_DRIFT_STOP")
    pathlib.Path(STAGING).rename(RELEASE)
    os.chmod("/opt/flop-shadow", 0o755)
    os.chmod(RELEASE, 0o755)

    command(["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home",
             "--home-dir", "/var/lib/flop-shadow",
             "--shell", "/usr/sbin/nologin", "flop-shadow"])
    user = pwd.getpwnam("flop-shadow")
    groups = set(os.getgrouplist("flop-shadow", user.pw_gid))
    forbidden = {grp.getgrnam("tradebot-k137").gr_gid,
                 grp.getgrnam("sudo").gr_gid}
    require(user.pw_uid != 0 and user.pw_shell == "/usr/sbin/nologin" and
            not groups.intersection(forbidden), "SHADOW_USER_ISOLATION_STOP")
    for p in BASES[1:]:
        os.chown(p, user.pw_uid, user.pw_gid)
        os.chmod(p, 0o700)
    require(k137() == original_k137, "K137_POSTCHECK_STOP")
    no_flop_units()
    require(pathlib.Path(RELEASE).is_dir(), "RELEASE_MISSING_STOP")
    print("FLOP_SHADOW_SOURCE_SHA=" + EXPECTED, flush=True)
    print("FLOP_SHADOW_USER_ISOLATED_PASS", flush=True)
    print("K137_SERVICE_TIMER_UNCHANGED_PASS", flush=True)
    print("FLOP_SHADOW_NO_RUNTIME_NO_SECRETS_NO_INSTALL_PASS", flush=True)
    print("FLOP_SHADOW_DISARMED_STAGE_PASS", flush=True)

if __name__ == "__main__":
    try:
        require(sys.argv[1:] == [], "ARGUMENTS_STOP")
        install()
    except (Stop, OSError, ValueError, KeyError, StopIteration,
            subprocess.TimeoutExpired) as error:
        reason = str(error) if isinstance(error, Stop) else type(error).__name__
        print("FLOP_SHADOW_STOP=" + reason, flush=True)
        sys.exit(42)
