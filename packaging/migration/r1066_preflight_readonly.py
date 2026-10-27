"""Owner-invoked R1066 preflight, NOT archive admission or migration approval.

Sent on stdin by the locally pinned Windows coordinator. No remote files are
installed. Only host identity, directory metadata, git HEAD, statvfs and the
invoking process's cgroup resource limits are read. Never inspect data trees,
receipts, environment files, SQLite, Vault or previous witnesses.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
APP = "/opt/technocore-safe-agent"
STATE = "/var/lib/technocore-safe-agent"
LANDING = "/var/lib/flop-migration-r1066"
PROTECTED = ("/opt/flop-shadow", "/opt/tradebot-k137", "/opt/tradebot-k137-private")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
FIELDS = {"role", "machine_sha256", "uid", "head", "cgroup_sha256", "minimum_free_bytes", "challenge"}


class Stop(Exception):
    pass


def need(ok):
    if not ok:
        raise Stop("PREFLIGHT_UNVERIFIED")


def read_small(path, limit=4096):
    # All paths are fixed or derived from the kernel's own cgroup membership.
    with open(path, "rb") as stream:
        raw = stream.read(limit + 1)
    need(len(raw) <= limit)
    return raw


def directory(path):
    p = Path(path)
    for entry in (p, *p.parents):
        info = entry.lstat()
        need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode))
    return p.stat()


def git_head(path):
    # Fixed executable and arguments; no hooks, network or shell commands.
    result = subprocess.run(
        ["/usr/bin/git", "-c", "safe.directory=" + path, "-C", path,
         "rev-parse", "--verify", "HEAD"],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=False,
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C",
             "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
             "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"},
    )
    need(result.returncode == 0 and len(result.stdout) == 41 and not result.stderr)
    value = result.stdout.decode("ascii").strip()
    need(re.fullmatch(r"[0-9a-f]{40}", value))
    return value


def resources(expected):
    # A private landing directory is NOT a resource-isolation boundary.
    # Require an independently enrolled, existing bounded cgroup v2 scope.
    raw = read_small("/proc/self/cgroup").decode("ascii").strip()
    need(raw.startswith("0::/") and "\n" not in raw)
    relative = raw[4:]
    need(relative and len(relative) <= 512 and
         re.fullmatch(r"[A-Za-z0-9_.@:/-]+", relative) and
         all(x not in ("", ".", "..") for x in relative.split("/")))
    need(hashlib.sha256(raw.encode("ascii")).hexdigest() == expected)
    root = "/sys/fs/cgroup/" + relative
    directory(root)
    memory = read_small(root + "/memory.max", 32).strip()
    pids = read_small(root + "/pids.max", 32).strip()
    cpu = read_small(root + "/cpu.max", 64).split()
    need(memory.isdigit() and pids.isdigit() and len(cpu) == 2 and
         all(x.isdigit() for x in cpu))
    memory, pids, quota, period = int(memory), int(pids), int(cpu[0]), int(cpu[1])
    need(0 < memory <= 256 * 1024**2 and 0 < pids <= 64 and
         0 < quota <= period <= 1000000)
    return memory, pids


def probe(request):
    need(type(request) is dict and set(request) == FIELDS)
    need(request["role"] in ("oci", "k137") and
         type(request["uid"]) is int and 0 <= request["uid"] <= 2147483647 and
         type(request["minimum_free_bytes"]) is int and
         1024**3 <= request["minimum_free_bytes"] <= 2**50)
    need(all(type(request[x]) is str and HEX64.fullmatch(request[x])
             for x in ("machine_sha256", "cgroup_sha256", "challenge")))
    need(type(request["head"]) is str and re.fullmatch(r"[0-9a-f]{40}", request["head"]))
    need(sys.platform == "linux" and os.geteuid() == request["uid"])
    machine = read_small("/etc/machine-id", 64).strip()
    need(re.fullmatch(rb"[0-9a-f]{32}", machine))
    need(hashlib.sha256(machine).hexdigest() == request["machine_sha256"])
    if request["role"] == "oci":
        need(request["uid"] == 0 and request["head"] == HEAD)
        need(not any(os.path.lexists(p) for p in PROTECTED))
        directory(APP)
        directory(STATE)
        need(git_head(APP) == HEAD)
        disk_root = STATE
        resource_status, memory, pids = "NOT_ASSESSED", 0, 0
        protected_status = "NOT_PRESENT"
    else:
        need(request["uid"] > 0)
        for path in PROTECTED:
            info = directory(path)
            need(info.st_uid != request["uid"] and not os.access(path, os.W_OK))
        need(git_head(PROTECTED[0]) == request["head"])
        info = directory(LANDING)
        need(info.st_uid == request["uid"] and stat.S_IMODE(info.st_mode) == 0o700)
        need(os.access(LANDING, os.R_OK | os.X_OK | os.W_OK))
        memory, pids = resources(request["cgroup_sha256"])
        disk_root = LANDING
        resource_status = "BOUNDED_SCOPE_OBSERVED"
        protected_status = "DIRECTORY_WRITE_DENIED_ONLY"
    disk = os.statvfs(disk_root)
    free = disk.f_bavail * disk.f_frsize
    need(request["minimum_free_bytes"] <= free <= 2**60)
    return {"schema_version": 1, "role": request["role"], "challenge": request["challenge"],
            "host_identity": "MATCH", "head": "MATCH", "scope": "MATCH",
            "disk_free_bytes": free, "disk_required_bytes": request["minimum_free_bytes"],
            "resources": resource_status, "memory_max_bytes": memory, "pids_max": pids,
            "protected_tradebot": protected_status, "read_only": True,
            "writer_admission": "NOT_PROVEN", "five_post_finality": "NOT_PROVEN",
            "common_sqlite_epoch": "NOT_PROVEN", "signer_portability": "NOT_PROVEN",
            "restore_authority": "NOT_PROVEN", "cutover": "NO_GO",
            "oci_retirement": "STRICT_NO_GO"}


def run(request):
    try:
        result = probe(request)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    except Exception:
        # No raw paths, git stderr, identity or exception text.
        print('{"code":"PREFLIGHT_UNVERIFIED"}')
        raise SystemExit(42)


# No automatic invocation: the pinned coordinator appends one validated request.
