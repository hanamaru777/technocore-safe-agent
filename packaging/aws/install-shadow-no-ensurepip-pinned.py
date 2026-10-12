#!/usr/bin/env python3
"""One-shot FLOP-only verified PIP wheel bootstrap and locked runtime wheel stage.

This is NOT a production deploy. No FLOP program/Signer, no system services,
no Oracle/Technocore writes, no K137 data reads/mutation.
Only HTTPS GET of wheels listed in frozen uv.lock, private FLOP-only files.
"""
import datetime
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import time
import tomllib
from urllib.parse import urlsplit

RELEASE_SHA = "3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e"
RELEASE = Path("/opt/flop-shadow/releases") / RELEASE_SHA
VENV = Path("/var/lib/flop-shadow/venv")
CACHE = Path("/var/cache/flop-shadow")
WHEELS = CACHE / "runtime-wheel-cache-v2"
PIP_WHEEL = "pip-26.2.1-py3-none-any.whl"
PIP_SHA256 = ("71138adf1f4ca900cdb7d289c21b7494"
              "329f2332b6d85f0e1c42108c0384ed3e")
PIP_URL = ("https://files.pythonhosted.org/packages/"
           "f3/6e/1736e5b4ae2b778ef2f81c47d797de9f891d4d8acb047a24ca37a60294dd/"
           + PIP_WHEEL)
EXPECTED_LOCK = "03117a907b31fbda0bea32012bdba3cf6e1e05cb"
CORE = ("cryptography", "httpx", "cffi", "pycparser", "anyio", "idna",
        "typing-extensions", "certifi", "httpcore", "h11")
K137_SVC = "k137q-public-k58.service"
K137_TIMER = "k137q-public-k58.timer"

class Stop(Exception): pass

def require(ok, reason):
    if not ok:
        raise Stop(reason)

def cmd(argv, timeout=20, env=None, label=None):
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, timeout=timeout, check=False, env=env)
    require(p.returncode == 0,
            "CHILD_FAILED_" + (label if label else Path(argv[0]).name.upper()))
    return p.stdout.strip()

def k137(name):
    out = cmd(["systemctl", "show", name, "--no-pager",
               "-p", "ActiveState", "-p", "UnitFileState"])
    d = dict(x.split("=", 1) for x in out.splitlines() if "=" in x)
    return d.get("ActiveState"), d.get("UnitFileState")

def k137_snapshot(allow_active=False):
    svc, timer = k137(K137_SVC), k137(K137_TIMER)
    require(svc[1] in ("static", "disabled") and
            svc[0] in (("inactive", "active") if allow_active else ("inactive",)) and
            timer in (("active", "enabled"), ("inactive", "disabled")),
            "K137_UNIT_STATE_STOP")
    return svc, timer

def slot_now(now):
    return 6 <= now.minute <= 44

def await_quiet():
    deadline = time.monotonic() + 840
    baseline_timer = None
    printed = False
    while True:
        svc, timer = k137_snapshot(allow_active=True)
        if baseline_timer is None:
            baseline_timer = timer
        require(timer == baseline_timer, "K137_TIMER_DRIFT_STOP")
        if svc[0] == "inactive" and slot_now(datetime.datetime.now(datetime.timezone.utc)):
            return k137_snapshot()
        if not printed:
            print("FLOP_SHADOW_DEP_WAIT_K137_QUIET_WINDOW", flush=True)
            printed = True
        remain = deadline - time.monotonic()
        require(remain > 0, "K137_QUIET_WINDOW_TIMEOUT_STOP")
        time.sleep(min(15, remain))

def headroom():
    mem = Path("/proc/meminfo").read_text()
    avail = int(next(x.split()[1] for x in mem.splitlines()
                     if x.startswith("MemAvailable:")))
    require(avail >= 1100 * 1024, "K137_MEM_HEADROOM_STOP")
    for name, maximum in (("memory", 5.0), ("io", 10.0)):
        value = Path("/proc/pressure/" + name).read_text().splitlines()
        full = next(x for x in value if x.startswith("full "))
        avg10 = float(next(x[6:] for x in full.split() if x.startswith("avg10=")))
        require(avg10 <= maximum, "K137_PSI_" + name.upper() + "_STOP")
    require(shutil.disk_usage("/").free >= 20 * 1024**3,
            "K137_DISK_HEADROOM_STOP")

def directory(path, uid, mode):
    s = path.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == uid and
            stat.S_IMODE(s.st_mode) == mode,
            "FLOP_DIR_GUARD_STOP_" + path.name)

def wheel_name(name, pkg):
    files = pkg["wheels"]
    def selected(w):
        fname = urlsplit(w["url"]).path.rsplit("/", 1)[-1]
        if name == "cffi":
            return "-cp312-cp312-manylinux2014_x86_64." in fname
        if name == "cryptography":
            return "-cp311-abi3-manylinux2014_x86_64." in fname
        return fname.endswith("-py3-none-any.whl")
    matches = [w for w in files if selected(w)]
    require(len(matches) == 1, "WHEEL_PLATFORM_AMBIGUOUS_STOP_" + name)
    return matches[0]

def wheel_plan(lock):
    byname = {p["name"]: p for p in lock["package"]}
    require(set(CORE).issubset(byname), "LOCK_CORE_PACKAGE_MISSING_STOP")
    chosen = []
    for name in CORE:
        pkg = byname[name]
        require(pkg.get("source") == {"registry": "https://pypi.org/simple"},
                "LOCK_UNTRUSTED_REGISTRY_STOP")
        for dep in pkg.get("dependencies", []):
            require(dep["name"] in CORE, "LOCK_DEP_OUTSIDE_CORE_STOP")
        w = wheel_name(name, pkg)
        url = w["url"]
        parsed = urlsplit(url)
        filename = parsed.path.rsplit("/", 1)[-1]
        require(parsed.scheme == "https" and parsed.hostname == "files.pythonhosted.org"
                and not parsed.username and not parsed.password and not parsed.query
                and filename.endswith(".whl") and filename.count("/") == 0,
                "WHEEL_URL_NOT_ALLOWLISTED_STOP")
        digest = w["hash"]
        require(digest.startswith("sha256:") and len(digest) == 71
                and all(x in "0123456789abcdef" for x in digest[7:]),
                "WHEEL_SHA_MISSING_STOP")
        size = w["size"]
        require(isinstance(size, int) and 0 < size <= 15 * 1024**2,
                "WHEEL_SIZE_UNSAFE_STOP")
        chosen.append((name, pkg["version"], filename, url, digest[7:], size))
    require(len(chosen) == 10 and sum(x[5] for x in chosen) < 50 * 1024**2,
            "WHEEL_COUNT_SIZE_STOP")
    return chosen

def preflight():
    require(os.geteuid() == 0 and sys.version_info >= (3, 12) and
            os.uname().machine == "x86_64", "ROOT_PYTHON_ARCH_STOP")
    user = pwd.getpwnam("flop-shadow")
    require(user.pw_shell == "/usr/sbin/nologin" and user.pw_uid != 0 and
            grp.getgrnam("flop-shadow").gr_gid == user.pw_gid and
            set(os.getgrouplist(user.pw_name, user.pw_gid)) == {user.pw_gid},
            "FLOP_USER_ISOLATION_STOP")
    directory(RELEASE, 0, 0o755)
    directory(VENV, user.pw_uid, 0o755)
    directory(CACHE, user.pw_uid, 0o700)
    require(not os.path.lexists(WHEELS), "WHEEL_STAGE_EXISTS_DO_NOT_RERUN")
    require(cmd(["git", "-C", str(RELEASE), "rev-parse", "HEAD"]) == RELEASE_SHA,
            "RELEASE_HEAD_DRIFT_STOP")
    require(cmd(["git", "-C", str(RELEASE), "status", "--porcelain"]) == "",
            "RELEASE_DIRTY_STOP")
    require(cmd(["git", "-C", str(RELEASE), "rev-parse", "HEAD:uv.lock"]) == EXPECTED_LOCK,
            "LOCK_BLOB_DRIFT_STOP")
    require((VENV / "bin" / "python3").is_file(),
            "VENV_PYTHON_MISSING_STOP")
    # NEVER execute a user-owned venv binary as root, even in read-only checks.
    # A compromised flop-shadow user could replace its bin/python3 symlink.
    preflight_user = ["runuser", "-u", "flop-shadow", "--", "env", "-i",
                      "HOME=/var/lib/flop-shadow", "PATH=/usr/bin:/bin",
                      "LANG=C", "PYTHONDONTWRITEBYTECODE=1"]
    current = cmd([*preflight_user, str(VENV / "bin" / "python3"), "-I", "-c",
                   "import sys;print(sys.version_info.major,sys.version_info.minor)"], label="VENV_VERSION")
    require(current == "3 12", "VENV_PYTHON_VERSION_STOP")
    # Ubuntu on this host lacks ensurepip (proven via real operator).
    # Never install OS-wide Python packages. Bootstrap a pinned official pip
    # wheel into this FLOP-only venv after hash-checking its complete bytes.
    lock = tomllib.loads((RELEASE / "uv.lock").read_text())
    plan = wheel_plan(lock)
    require(not (VENV / "lib" / "python3.12" / "site-packages" / "pip").exists(),
            "PIP_ALREADY_PRESENT_REVIEW_STOP")
    require(not (VENV / "lib" / "python3.12" / "site-packages" /
                 "pip-26.2.1.dist-info").exists(), "PIP_DIST_ALREADY_PRESENT_STOP")
    return user, plan

# Runs as isolated flop-shadow non-login account. Exact HTTPS public wheel GETs only.
FETCH = r"""
import hashlib, json, pathlib, os, sys, urllib.request
release, cache = map(pathlib.Path, sys.argv[1:3])
plan = json.loads(sys.argv[3])
assert len(plan) == 11 and all(len(row) == 6 for row in plan)
assert cache.parent.is_dir() and cache.parent.name == 'flop-shadow'
cache.mkdir(mode=0o700)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('NO_REDIRECT')
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
for name, version, filename, url, digest, size in plan:
    out = cache / filename
    assert not out.exists() and not out.is_symlink()
    h = hashlib.sha256()
    with opener.open(urllib.request.Request(url, headers={'User-Agent':'FlopShadowPinnedWheels/1'}), timeout=20) as res, open(out, 'xb') as f:
        assert res.status == 200
        received = 0
        limit = size if size else 3 * 1024 * 1024
        while True:
            chunk = res.read(min(65536, limit + 1 - received))
            if not chunk: break
            received += len(chunk)
            assert received <= limit
            h.update(chunk)
            f.write(chunk)
    assert (size == 0 or received == size) and h.hexdigest() == digest
    os.chmod(out, 0o600)
print('FLOP_SHADOW_PINNED_WHEELS_SHA256_PASS count=' + str(len(plan)), flush=True)
"""

PIP_BOOTSTRAP = r"""
# The entire input wheel was SHA256-verified against official PyPI.
# No code from pip is executed until AFTER safe Flop-only extraction.
import os, pathlib, shutil, stat, sys, zipfile
root = pathlib.Path(sys.argv[1])
wheel = pathlib.Path(sys.argv[2])
assert root.is_dir() and not root.is_symlink()
assert wheel.is_file() and not wheel.is_symlink()
assert root.name == 'site-packages'
assert wheel.name == 'pip-26.2.1-py3-none-any.whl'
assert not (root/'pip').exists() and not (root/'pip-26.2.1.dist-info').exists()
stage = root/'.flop-pip-bootstrap-v1'
assert not stage.exists() and not stage.is_symlink()
with zipfile.ZipFile(wheel, 'r') as z:
    infos = z.infolist()
    assert 20 < len(infos) < 2500
    seen = set()
    count = 0
    for info in infos:
        name = info.filename
        posix = pathlib.PurePosixPath(name)
        assert not posix.is_absolute() and '\\' not in name and '\x00' not in name
        assert all(x not in ('.','..','') for x in posix.parts)
        assert posix.parts[0] in ('pip', 'pip-26.2.1.dist-info')
        assert name not in seen
        seen.add(name)
        fmt = stat.S_IFMT(info.external_attr >> 16)
        assert fmt in (0, stat.S_IFDIR, stat.S_IFREG)
        assert info.file_size <= 15 * 1024 * 1024
        count += info.file_size
        assert count < 40 * 1024 * 1024
    names = {str(pathlib.PurePosixPath(n)) for n in seen}
    assert 'pip/__main__.py' in names
    assert 'pip/__init__.py' in names
    assert 'pip-26.2.1.dist-info/METADATA' in names
    stage.mkdir(mode=0o700)
    for info in infos:
        target = stage.joinpath(*pathlib.PurePosixPath(info.filename).parts)
        if info.is_dir():
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
        else:
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with z.open(info) as reader, target.open('xb') as dst:
                shutil.copyfileobj(reader, dst, length=65536)
            target.chmod(0o600)
(stage/'pip').rename(root/'pip')
(stage/'pip-26.2.1.dist-info').rename(root/'pip-26.2.1.dist-info')
stage.rmdir()
print('FLOP_SHADOW_PINNED_PIP_WHEEL_BOOTSTRAP_PASS', flush=True)
"""

SMOKE = r"""
import importlib.metadata as metadata, socket
def no_connect(*a, **k): raise RuntimeError('NETWORK_FORBIDDEN')
socket.socket.connect = no_connect
socket.create_connection = no_connect
import cryptography, httpx
assert metadata.version('cryptography') == '50.0.1'
assert metadata.version('httpx') == '0.28.1'
print('FLOP_SHADOW_RUNTIME_IMPORT_OFFLINE_PASS', flush=True)
"""

def main():
    user, plan = preflight()
    original = await_quiet()
    headroom()
    print("FLOP_SHADOW_RUNTIME_DEPS_PREFLIGHT_PASS", flush=True)
    isolated = ["runuser", "-u", "flop-shadow", "--", "env", "-i",
                "HOME=/var/lib/flop-shadow", "PATH=/usr/bin:/bin",
                "LANG=C", "PYTHONDONTWRITEBYTECODE=1"]
    # Extend the 10 immutable uv.lock wheels with one independently pinned
    # official pip PyPI wheel. No dependency resolution or unpinned downloads.
    pip_plan = ("pip", "26.2.1", PIP_WHEEL, PIP_URL, PIP_SHA256, 0)
    wheel_output = cmd([*isolated, "/usr/bin/python3", "-I", "-c", FETCH,
                        str(RELEASE), str(WHEELS), json.dumps([*plan, pip_plan])],
                       timeout=220, label="LOCKED_WHEEL_DOWNLOAD")
    require("FLOP_SHADOW_PINNED_WHEELS_SHA256_PASS count=11" in wheel_output,
            "WHEEL_SHA256_CONFIRMATION_STOP")
    print("FLOP_SHADOW_PINNED_WHEELS_SHA256_PASS count=11", flush=True)
    require(len(list(WHEELS.glob("*.whl"))) == 11,
            "WHEELS_COUNT_DRIFT_STOP")
    headroom()
    require(k137_snapshot() == original, "K137_DRIFT_BEFORE_BOOTSTRAP_STOP")
    pip_site = str(VENV / "lib" / "python3.12" / "site-packages")
    pip_result = cmd([*isolated, str(VENV / "bin" / "python3"), "-I", "-c",
                      PIP_BOOTSTRAP, pip_site, str(WHEELS / PIP_WHEEL)], timeout=90,
                     label="PINNED_PIP_BOOTSTRAP")
    require("FLOP_SHADOW_PINNED_PIP_WHEEL_BOOTSTRAP_PASS" in pip_result,
            "PIP_BOOTSTRAP_CONFIRMATION_STOP")
    pip_version = cmd([*isolated, str(VENV / "bin" / "python3"), "-I",
                       "-m", "pip", "--version"], label="PINNED_PIP_VERSION")
    require(pip_version.startswith("pip 26.2.1 "), "PIP_VERSION_STOP")
    print("FLOP_SHADOW_PINNED_PIP_WHEEL_BOOTSTRAP_PASS", flush=True)
    archives = [str(WHEELS / x[2]) for x in plan]
    cmd([*isolated, str(VENV / "bin" / "python3"), "-I", "-m", "pip",
         "--isolated", "install", "--quiet", "--no-index", "--no-deps",
         "--no-cache-dir", "--no-compile", "--no-input", "--only-binary=:all:",
         *archives],
        timeout=120, label="OFFLINE_LOCKED_WHEEL_INSTALL")
    cmd([*isolated, str(VENV / "bin" / "python3"), "-I", "-B",
         "-c", SMOKE], timeout=30, label="OFFLINE_IMPORT_SMOKE")
    headroom()
    require(k137_snapshot() == original, "K137_SERVICE_TIMER_CHANGED_STOP")
    print("K137_SERVICE_TIMER_UNCHANGED_PASS", flush=True)
    print("FLOP_SHADOW_NO_SIGNER_NO_RUNTIME_NO_SYSTEM_SERVICES_PASS", flush=True)
    print("FLOP_SHADOW_PINNED_RUNTIME_DEPS_STAGE_PASS", flush=True)

if __name__ == "__main__":
    try:
        require(not sys.argv[1:], "ARGS_UNEXPECTED_STOP")
        main()
    except (Stop, OSError, KeyError, ValueError, AssertionError,
            subprocess.TimeoutExpired) as ex:
        print("FLOP_SHADOW_RUNTIME_DEPS_STOP=" + (
            str(ex) if isinstance(ex, Stop) else type(ex).__name__), flush=True)
        sys.exit(42)
