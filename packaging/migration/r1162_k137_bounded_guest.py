"""Fixed stdin guest for R1162, entered ONLY inside the bounded transient service.

R and tradebot_evidence are injected from verified frozen source by the launcher.
There is no standalone entry, command input, networking, or filesystem writer.
"""
import hashlib
import json
import os
import re
import stat
import sys
import time

UNIT = "flop-r1162-admission.service"
TRADEBOT = "k137q-public-k58.service"
MACHINE_SHA256 = ("e2692bd8b11c4021e3ddaebe9e5d49e28" "3ac00584737bc5b7145e657f438d514")


def need(ok, code="K137_GUEST_UNVERIFIED"):
    if not ok:
        raise ValueError(code)


def shape(value, fields):
    need(type(value) is dict and set(value) == set(fields.split()))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cgroup():
    raw = R.read_small("/proc/self/cgroup", 1024)
    # A new SERVICE, not an old session scope or a caller-provided digest.
    need(raw.strip() == ("0::/system.slice/" + UNIT).encode(), "K137_SERVICE_CGROUP_STOP")
    path = "/sys/fs/cgroup/system.slice/" + UNIT
    R.directory(path)
    members = R.read_small(path + "/cgroup.procs", 4096).splitlines()
    need(members and all(x.isdigit() for x in members) and
         str(os.getpid()).encode() in members and len(set(members)) == len(members),
         "K137_SERVICE_CGROUP_STOP")
    memory = R.read_small(path + "/memory.max", 32).strip()
    pids = R.read_small(path + "/pids.max", 32).strip()
    cpu = R.read_small(path + "/cpu.max", 64).split()
    swap = R.read_small(path + "/memory.swap.max", 32).strip()
    need(memory.isdigit() and pids.isdigit() and len(cpu) == 2 and
         all(x.isdigit() for x in cpu) and swap == b"0", "K137_PAYLOAD_CAP_STOP")
    memory, pids, quota, period = int(memory), int(pids), int(cpu[0]), int(cpu[1])
    need(0 < memory <= 256 * 1024**2 and 0 < pids <= 64 and len(members) <= pids and
         0 < quota and 2 * quota <= period <= 1000000, "K137_PAYLOAD_CAP_STOP")
    return dict(scope_sha256=sha(raw), memory_max=memory, pids_max=pids,
                cpu_quota=quota, cpu_period=period, swap_max=0)


def sandbox():
    # Runtime corroboration of the fixed command, not a sudo permission probe.
    props = "User,Group,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,ControlGroup,KillMode,Restart"
    r = R.subprocess.run(
        ["/usr/bin/systemctl", "show", "--no-pager", "--property=" + props, "--", UNIT],
        stdin=R.subprocess.DEVNULL, capture_output=True, timeout=5, check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    need(r.returncode == 0 and len(r.stdout) <= 2048 and not r.stderr, "K137_SANDBOX_STOP")
    rows = {}
    for line in r.stdout.decode("ascii").splitlines():
        key, value = line.split("=", 1)
        need(key not in rows, "K137_SANDBOX_STOP")
        rows[key] = value
    need(rows == dict(User="ubuntu", Group="ubuntu", NoNewPrivileges="yes",
                      ProtectSystem="strict", ProtectHome="yes", PrivateTmp="yes",
                      ControlGroup="/system.slice/" + UNIT, KillMode="control-group", Restart="no"),
         "K137_SANDBOX_STOP")
    return sha(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode())


def probe(request):
    shape(request, "challenge expires_at source_blobs provider_sha256")
    need(type(request["challenge"]) is str and re.fullmatch("[a-f0-9]{64}", request["challenge"]))
    need(type(request["provider_sha256"]) is str and re.fullmatch("[a-f0-9]{64}", request["provider_sha256"]))
    need(type(request["expires_at"]) is int and int(time.time()) < request["expires_at"] <= int(time.time()) + 180)
    need(sys.platform == "linux" and os.geteuid() == 1000 and os.getegid() == 1000, "K137_UID_STOP")
    # These checks are in the already constrained child, never bare SSH Python.
    limits = cgroup()
    isolation = sandbox()
    machine = R.read_small("/etc/machine-id", 64).strip()
    need(re.fullmatch(rb"[a-f0-9]{32}", machine) and sha(machine) == MACHINE_SHA256, "K137_MACHINE_STOP")
    boot = R.read_small("/proc/sys/kernel/random/boot_id", 64).strip()
    need(re.fullmatch(rb"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", boot), "K137_BOOT_STOP")
    for path in R.PROTECTED:
        info = R.directory(path)
        need(info.st_uid != 1000 and not os.access(path, os.W_OK), "K137_PROTECTED_STOP")
    R.directory(R.K137_STAGE)
    need(R.git_head(R.K137_STAGE) == R.K137_STAGE_SHA, "K137_HEAD_STOP")
    landing = R.directory(R.LANDING)
    need(landing.st_uid == 1000 and stat.S_IMODE(landing.st_mode) == 0o700 and
         os.access(R.LANDING, os.R_OK | os.X_OK) and not os.access(R.LANDING, os.W_OK),
         "K137_READONLY_LANDING_STOP")
    target = tradebot_evidence(R)
    need(target["cgroup_sha256"] != sha(("/system.slice/" + UNIT).encode()), "K137_PROTECTED_STOP")
    space = os.statvfs(R.LANDING)
    free = space.f_bavail * space.f_frsize
    need(21 * 1024**3 <= free <= 2**60, "K137_SPACE_STOP")
    need(R.read_small("/etc/machine-id", 64).strip() == machine, "K137_MACHINE_STOP")
    need(R.read_small("/proc/sys/kernel/random/boot_id", 64).strip() == boot, "K137_BOOT_STOP")
    need(cgroup() == limits and sandbox() == isolation, "K137_SERVICE_CHANGED_STOP")
    need(tradebot_evidence(R) == target, "K137_TRADEBOT_CHANGED_STOP")
    observed = int(time.time())
    need(observed < request["expires_at"], "K137_EXPIRED_STOP")
    return dict(task="R1162", verdict="K137_PAYLOAD_BOUNDED", ssh_login_prebounded=False,
                challenge=request["challenge"], expires_at=request["expires_at"], observed_at=observed,
                source_blobs=request["source_blobs"], provider_sha256=request["provider_sha256"],
                machine_sha256=sha(machine), boot_sha256=sha(boot), cgroup=limits,
                sandbox_sha256=isolation, tradebot=target, head=R.K137_STAGE_SHA,
                free_bytes=free, uid=1000, gid=1000, landing="READ_ONLY_0700",
                m2="NO_GO", cutover="NO_GO", oci_retirement="STRICT_NO_GO")


def run(request):
    try:
        print(json.dumps(probe(request), sort_keys=True, separators=(",", ":")))
    except Exception:
        # Fixed code only: no raw systemctl output, paths, or exception text.
        print('{"task":"R1162","code":"K137_GUEST_STOP","m2":"NO_GO","cutover":"NO_GO"}')
        raise SystemExit(42)
