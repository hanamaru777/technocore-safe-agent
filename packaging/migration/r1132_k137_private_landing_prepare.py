"""R1132 one-time K137 private landing directory preparation.

Fixed path only. No SSH access, no secrets, no TradeBot interaction,
no cloud API, no systemctl, no runtime activation, no source-data transfer.
A mismatched pre-existing path always STOPs; never chmod/chown/replace it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import sys

BASE = Path("/var/lib")
PARENT_NAME = "flop-migration-r1066"
CHILD_NAME = "disarmed"
TARGET_UID = 1000
MIN_FREE_BYTES = 20 * 1024**3 + 1024**3 + 32 * 1024**2
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

class Stop(Exception):
    pass

def need(ok, code):
    if not ok:
        raise Stop(code)

def identity():
    user = pwd.getpwnam("ubuntu")
    need(user.pw_uid == TARGET_UID and user.pw_gid >= 1000,
         "OWNER_IDENTITY_STOP")
    return user.pw_uid, user.pw_gid

def check_machine(expected):
    need(type(expected) is str and HEX64.fullmatch(expected),
         "MACHINE_PIN_STOP")
    raw = Path("/etc/machine-id").read_bytes()
    need(1 <= len(raw) <= 128 and
         hashlib.sha256(raw.strip()).hexdigest() == expected,
         "MACHINE_PIN_STOP")

def base_fd():
    for path in (Path("/"), Path("/var"), BASE):
        s = path.lstat()
        need(stat.S_ISDIR(s.st_mode) and not path.is_symlink() and
             s.st_uid == 0 and not s.st_mode & 0o022,
             "BASE_PATH_STOP")
    return os.open(BASE, OPEN_FLAGS)

def inspect_entry(parent_fd, name, uid, gid):
    try:
        s = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == uid and
         s.st_gid == gid and stat.S_IMODE(s.st_mode) == 0o700,
         "EXISTING_PATH_MISMATCH_STOP")
    return True

def open_checked(parent_fd, name, uid, gid):
    fd = os.open(name, OPEN_FLAGS, dir_fd=parent_fd)
    s = os.fstat(fd)
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == uid and
         s.st_gid == gid and stat.S_IMODE(s.st_mode) == 0o700,
         "OPEN_PATH_RACE_STOP")
    return fd

def provision(expected_machine_sha256, *, apply=False):
    check_machine(expected_machine_sha256)
    owner, group = identity()
    need(shutil.disk_usage(BASE).free >= MIN_FREE_BYTES,
         "TRADEBOT_DISK_RESERVE_STOP")
    if apply:
        need(sys.platform == "linux" and os.geteuid() == 0, "ROOT_REQUIRED")
    created_parent = False
    created_child = False
    base = base_fd()
    parent = None
    child = None
    try:
        # Never normalize, chmod, chown, overwrite or delete existing objects.
        existing_parent = inspect_entry(base, PARENT_NAME, owner, group)
        if not existing_parent:
            if not apply:
                return {"phase":"R1132","result":"PLAN_NEW_PRIVATE_PARENT_AND_CHILD",
                        "apply":False,"ready":False,"files_written":0}
            old_umask = os.umask(0o077)
            try:
                os.mkdir(PARENT_NAME, 0o700, dir_fd=base)
                created_parent = True
            finally:
                os.umask(old_umask)
        expected_parent_owner = 0 if created_parent else owner
        expected_parent_group = os.getegid() if created_parent else group
        parent = open_checked(base, PARENT_NAME,
                              expected_parent_owner, expected_parent_group)
        existing_child = inspect_entry(parent, CHILD_NAME, owner, group)
        if not existing_child:
            if not apply:
                return {"phase":"R1132","result":"PLAN_NEW_PRIVATE_CHILD",
                        "apply":False,"ready":False,"files_written":0}
            old_umask = os.umask(0o077)
            try:
                os.mkdir(CHILD_NAME, 0o700, dir_fd=parent)
                created_child = True
            finally:
                os.umask(old_umask)
        if created_child:
            child = os.open(CHILD_NAME, OPEN_FLAGS, dir_fd=parent)
            s = os.fstat(child)
            need(s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o700,
                 "NEW_CHILD_RACE_STOP")
            os.fchown(child, owner, group)
        else:
            child = open_checked(parent, CHILD_NAME, owner, group)
        if created_parent:
            # Keep new parent root-owned until child is in place to limit race.
            os.fchown(parent, owner, group)
        for fd in (child, parent, base):
            os.fsync(fd)
        # Fresh no-follow checks after all changes.
        need(inspect_entry(base, PARENT_NAME, owner, group),
             "POST_PARENT_STOP")
        need(inspect_entry(parent, CHILD_NAME, owner, group),
             "POST_CHILD_STOP")
        need(shutil.disk_usage(BASE).free >= MIN_FREE_BYTES,
             "TRADEBOT_DISK_RESERVE_STOP")
        return {
            "phase":"R1132",
            "result":"PRIVATE_CIPHERTEXT_LANDING_READY",
            "apply":bool(apply),
            "ready":True,
            "created_parent":created_parent,
            "created_child":created_child,
            "files_written":0,
            "services_touched":0,
            "source_bytes_transferred":0,
            "cutover":"NO_GO",
            "oci_retirement":"STRICT_NO_GO",
        }
    finally:
        for fd in (child, parent, base):
            if fd is not None:
                os.close(fd)

def main(argv=None):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--expected-machine-sha256", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = provision(args.expected_machine_sha256, apply=args.apply)
    except Exception as exc:
        reason = str(exc) if type(exc) is Stop else "LANDING_PREP_STOP"
        safe = {"OWNER_IDENTITY_STOP","MACHINE_PIN_STOP",
                "BASE_PATH_STOP","EXISTING_PATH_MISMATCH_STOP",
                "OPEN_PATH_RACE_STOP","TRADEBOT_DISK_RESERVE_STOP",
                "ROOT_REQUIRED","NEW_CHILD_RACE_STOP","POST_PARENT_STOP",
                "POST_CHILD_STOP"}
        if reason not in safe: reason = "LANDING_PREP_STOP"
        result = {"phase":"R1132","result":"STOP","code":reason,
                  "ready":False,"cutover":"NO_GO",
                  "oci_retirement":"STRICT_NO_GO"}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["result"] != "STOP" else 42

if __name__ == "__main__":
    raise SystemExit(main())
