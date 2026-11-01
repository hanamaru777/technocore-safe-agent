"""R1125: exact-original root-volume placement witness; READ ONLY, no archival authority.

This program reports classified filesystem metadata only. It does not enumerate
historical data, read SQLite contents, sign, transmit, write or stop services.
It cannot prove absence of symlinks inside state, external data references,
future writers, source archive completeness, or AWS restore readiness.
"""
from __future__ import annotations
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
FS_OK = frozenset({"ext4", "xfs", "btrfs"})
MAX_MOUNTS = 4096
MAX_BYTES = 1024 * 1024


class Stop(Exception):
    pass


def need(test: bool, code: str):
    if not test:
        raise Stop(code)


def decode_path(value: str) -> str:
    # Linux mountinfo escapes spaces, tabs, newlines and backslashes.
    need(len(value) <= 4096, "MOUNT_FORMAT_STOP")
    need(not re.search(r"\\(?![0-7]{3})", value), "MOUNT_FORMAT_STOP")
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), value)


def parse_mounts(raw: bytes):
    need(0 < len(raw) <= MAX_BYTES, "MOUNT_BOUND_STOP")
    out = []
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
        need(0 < len(lines) <= MAX_MOUNTS, "MOUNT_BOUND_STOP")
        for line in lines:
            chunks = line.split(" - ")
            need(len(chunks) == 2, "MOUNT_FORMAT_STOP")
            left, right = chunks[0].split(), chunks[1].split()
            need(len(left) >= 6 and len(right) >= 3, "MOUNT_FORMAT_STOP")
            where = decode_path(left[4])
            need(where.startswith("/") and ".." not in Path(where).parts,
                 "MOUNT_FORMAT_STOP")
            out.append((where, right[0], decode_path(right[1])))
        need(len(set(x[0] for x in out)) == len(out), "MOUNT_SCOPE_STOP")
        return tuple(sorted(out))
    except (UnicodeError, ValueError, IndexError):
        raise Stop("MOUNT_FORMAT_STOP") from None


def mount_scope(mounts, paths):
    need(any(where == "/" and fs in FS_OK and
             source.startswith("/dev/") for where, fs, source in mounts),
         "ROOT_FILESYSTEM_STOP")
    for path in paths:
        name = str(path)
        covering = [x for x in mounts if x[0] == "/" or
                    name == x[0] or name.startswith(x[0].rstrip("/") + "/")]
        need(len(covering) == 1 and covering[0][0] == "/",
             "NONROOT_MOUNT_STOP")
        need(not any(where == name or where.startswith(name + "/")
                     for where, _, _ in mounts), "NESTED_MOUNT_STOP")
    return True


def run():
    need(sys.platform == "linux" and os.geteuid() == 0, "ORIGINAL_ROOT_STOP")
    need(Path("/proc/self/mountinfo").is_file(), "MOUNT_UNAVAILABLE")
    for root in (APP, STATE):
        for ancestor in (root, *root.parents):
            need(not ancestor.is_symlink(), "ROOT_PATH_STOP")
        s = root.lstat()
        need(stat.S_ISDIR(s.st_mode), "ROOT_PATH_STOP")
    cmd = ["/usr/bin/git", "-c", "safe.directory=" + str(APP),
           "-C", str(APP), "rev-parse", "--verify", "HEAD"]
    res = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         timeout=5, check=False,
                         env={"PATH": "/usr/bin:/bin", "LANG": "C",
                              "GIT_CONFIG_NOSYSTEM": "1",
                              "GIT_CONFIG_GLOBAL": "/dev/null",
                              "GIT_OPTIONAL_LOCKS": "0"})
    need(res.returncode == 0 and res.stdout == (HEAD + "\n").encode(),
         "ORIGINAL_HEAD_STOP")
    mount_file = Path("/proc/self/mountinfo")
    before = parse_mounts(mount_file.read_bytes())
    mount_scope(before, (APP, STATE))
    root_dev = os.stat("/").st_dev
    need(APP.stat().st_dev == root_dev and STATE.stat().st_dev == root_dev,
         "DEVICE_SCOPE_STOP")
    after = parse_mounts(mount_file.read_bytes())
    need(before == after, "MOUNT_RACE_STOP")
    mount_scope(after, (APP, STATE))
    need(APP.stat().st_dev == root_dev and STATE.stat().st_dev == root_dev,
         "DEVICE_RACE_STOP")
    return {
        "phase": "R1125", "result": "PRIVATE_ROOT_MOUNT_WITNESS_ONLY",
        "action": "READ_ONLY", "source_head": HEAD,
        "app_on_root_fs": True, "state_on_root_fs": True,
        "root_local_block_fs": True, "mount_table_stable": True,
        "nested_mounts": 0,
        "internal_symlinks_complete": False,
        "two_sqlite_epoch": "NOT_PROVEN",
        "source_archive": "NO_GO", "cutover": "NO_GO",
        "oci_retirement": "STRICT_NO_GO",
    }


def main():
    try:
        value = run()
    except (Stop, OSError, ValueError, UnicodeError, subprocess.SubprocessError,
            TimeoutError) as exc:
        allowed = {
            "ORIGINAL_ROOT_STOP", "ROOT_PATH_STOP", "ORIGINAL_HEAD_STOP",
            "MOUNT_UNAVAILABLE", "MOUNT_BOUND_STOP", "MOUNT_FORMAT_STOP",
            "MOUNT_SCOPE_STOP", "ROOT_FILESYSTEM_STOP", "NONROOT_MOUNT_STOP",
            "NESTED_MOUNT_STOP", "DEVICE_SCOPE_STOP", "MOUNT_RACE_STOP",
            "DEVICE_RACE_STOP",
        }
        reason = str(exc) if type(exc) is Stop else "READ_ONLY_UNAVAILABLE"
        if reason not in allowed:
            reason = "READ_ONLY_UNAVAILABLE"
        value = {"phase": "R1125", "result": "STOP", "reason": reason,
                 "source_archive": "NO_GO", "cutover": "NO_GO",
                 "oci_retirement": "STRICT_NO_GO"}
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0 if value["result"] == "PRIVATE_ROOT_MOUNT_WITNESS_ONLY" else 42


if __name__ == "__main__":
    raise SystemExit(main())
