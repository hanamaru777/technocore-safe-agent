"""R1139 immutable-original three-file export readiness WITNESS ONLY.

Never opens the selected source file contents, Oracle Vault, SQLite, network
sockets or signing material. Absolutely no source writes or service changes.
This is not a backup or authority to export or reactivate state.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
APP = Path("/opt/technocore-safe-agent")
STATE = Path("/var/lib/technocore-safe-agent")
FILES = (
    ("verified-did", ("verified-did.json",), 16 * 1024),
    ("nonces", ("nonces.json",), 1024 * 1024),
    ("signer-receipts", ("signer", "oracle-signer-receipts.json"), 8 * 1024 * 1024),
)
MAX_MOUNT_BYTES = 1024 * 1024
MAX_MOUNTS = 4096

class Stop(Exception):
    pass

def need(test, code):
    if not test:
        raise Stop(code)

def parse_mounts(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_MOUNT_BYTES, "MOUNT_STOP")
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
        need(0 < len(lines) <= MAX_MOUNTS, "MOUNT_STOP")
        parsed = []
        for line in lines:
            split = line.split(" - ")
            need(len(split) == 2, "MOUNT_STOP")
            l, r = split[0].split(), split[1].split()
            need(len(l) >= 6 and len(r) >= 3, "MOUNT_STOP")
            mount = l[4]
            need(not re.search(r"\\(?![0-7]{3})", mount), "MOUNT_STOP")
            mount = re.sub(r"\\([0-7]{3})",
                           lambda m: chr(int(m.group(1), 8)), mount)
            need(mount.startswith("/") and ".." not in Path(mount).parts,
                 "MOUNT_STOP")
            parsed.append((mount, r[0], r[1]))
        return tuple(sorted(parsed))
    except (ValueError, IndexError, UnicodeError):
        raise Stop("MOUNT_STOP") from None

def mount_guard(mounts):
    roots = [x for x in mounts if x[0] == "/"]
    need(len(roots) == 1 and roots[0][1] in ("ext4", "xfs", "btrfs")
         and roots[0][2].startswith("/dev/"), "ROOT_FS_STOP")
    for root in (APP, STATE):
        path = str(root)
        covering = [x for x in mounts if x[0] == "/" or
                    path == x[0] or path.startswith(x[0].rstrip("/") + "/")]
        need(len(covering) == 1 and covering[0][0] == "/" and
             not any(x[0] == path or x[0].startswith(path + "/") for x in mounts),
             "SOURCE_MOUNT_STOP")

def assert_source():
    need(sys.platform == "linux" and os.geteuid() == 0, "ORIGINAL_SCOPE_STOP")
    for root in (APP, STATE):
        for p in (root, *root.parents):
            need(not p.is_symlink(), "ORIGINAL_ROOT_LINK_STOP")
        need(stat.S_ISDIR(root.lstat().st_mode), "ORIGINAL_SCOPE_STOP")
    cmd = ["/usr/bin/git", "-c", "safe.directory=" + str(APP),
           "-C", str(APP), "rev-parse", "--verify", "HEAD"]
    result = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=5, check=False,
                            env={"PATH":"/usr/bin:/bin", "LANG":"C",
                                 "HOME":"/nonexistent",
                                 "GIT_CONFIG_NOSYSTEM":"1",
                                 "GIT_CONFIG_GLOBAL":"/dev/null",
                                 "GIT_OPTIONAL_LOCKS":"0"})
    need(result.returncode == 0 and result.stdout == (HEAD+"\n").encode(),
         "ORIGINAL_HEAD_STOP")
    before = parse_mounts(Path("/proc/self/mountinfo").read_bytes())
    mount_guard(before)
    dev = os.stat("/").st_dev
    need(APP.stat().st_dev == dev and STATE.stat().st_dev == dev,
         "SOURCE_DEVICE_STOP")
    return before, dev

def file_metadata(name, parts, limit):
    path=STATE.joinpath(*parts)
    for parent in (path, *path.parents):
        if parent == STATE.parent: break
        need(not parent.is_symlink(), "SOURCE_FILE_LINK_STOP")
    try:
        s=path.lstat()
    except FileNotFoundError:
        return {"exists":False,"regular":False,"single_link":False,
                "within_limit":False,"size_bytes":0}
    regular=stat.S_ISREG(s.st_mode)
    single=s.st_nlink == 1
    valid=regular and single and 0 < s.st_size <= limit
    return {"exists":True,"regular":regular,"single_link":single,
            "within_limit":bool(valid),"size_bytes":s.st_size if valid else 0}

def inventory():
    before, dev=assert_source()
    records = {name:file_metadata(name, parts, cap)
               for name, parts, cap in FILES}
    current = parse_mounts(Path("/proc/self/mountinfo").read_bytes())
    need(current == before, "MOUNT_RACE_STOP")
    mount_guard(current)
    need(APP.stat().st_dev == dev and STATE.stat().st_dev == dev,
         "DEVICE_RACE_STOP")
    machine=Path("/etc/machine-id").read_bytes().strip()
    need(1 <= len(machine) <= 128 and
         re.fullmatch(rb"[0-9a-f]{32}", machine), "MACHINE_ID_STOP")
    ready=all(x["within_limit"] for x in records.values())
    return {"phase":"R1139",
            "result":"SOURCE_PRESEED_METADATA_READY" if ready else "SOURCE_PRESEED_METADATA_GAPS",
            "action":"READ_ONLY",
            "source_head":HEAD,
            "machine_sha256":hashlib.sha256(machine).hexdigest(),
            "files":records,
            "data_bytes_exported":0,
            "common_sqlite_epoch":"NOT_PROVEN",
            "source_archive":"NO_GO",
            "cutover":"NO_GO",
            "oci_retirement":"STRICT_NO_GO"}

def main():
    try:
        report=inventory()
    except (Stop,OSError,ValueError,UnicodeError,subprocess.SubprocessError,
            TimeoutError) as e:
        safe={"MOUNT_STOP","ROOT_FS_STOP","SOURCE_MOUNT_STOP",
              "ORIGINAL_SCOPE_STOP","ORIGINAL_ROOT_LINK_STOP","ORIGINAL_HEAD_STOP",
              "SOURCE_DEVICE_STOP","SOURCE_FILE_LINK_STOP","MOUNT_RACE_STOP",
              "DEVICE_RACE_STOP","MACHINE_ID_STOP"}
        code=str(e) if type(e) is Stop and str(e) in safe else "SOURCE_METADATA_STOP"
        report={"phase":"R1139","result":"STOP","code":code,
                "source_archive":"NO_GO","cutover":"NO_GO",
                "oci_retirement":"STRICT_NO_GO"}
    sys.stdout.write(json.dumps(report,separators=(",",":"),sort_keys=True)+"\n")
    return 0 if report["result"] != "STOP" else 42

if __name__ == "__main__":
    raise SystemExit(main())
