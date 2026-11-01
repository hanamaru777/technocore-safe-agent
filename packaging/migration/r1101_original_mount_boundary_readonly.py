"""R1101: independent OCI G4 mount namespace audit. Necessary ONLY, never a fence.

A RO bind view in a private namespace does NOT stop writers on PID1's
original mount. This tool never alters mounts, processes, authorizations or
state. The original R1089 and its historical Windows source pins stay frozen.
"""
from __future__ import annotations
import os
import stat
import sys
from pathlib import Path

ROOTS=(Path("/opt/technocore-safe-agent"),Path("/var/lib/technocore-safe-agent"))
PROC_INIT="/proc/1/ns/mnt"
PROC_SELF="/proc/self/ns/mnt"

class Stop(ValueError):pass

def need(condition,code="G4_MOUNT_VIEW_STOP"):
    if not condition:raise Stop(code)

def mount_namespace_identity(os_module=os):
    try:
        a=os_module.stat(PROC_SELF)
        b=os_module.stat(PROC_INIT)
    except OSError:
        raise Stop("G4_MOUNT_VIEW_STOP") from None
    result=(a.st_dev,a.st_ino)
    need(result==(b.st_dev,b.st_ino))
    return result

def inspect_original_ro_view(os_module=os,roots=ROOTS):
    """Necessary check only; no G4/G5 signed proof is created here."""
    need(sys.platform=="linux" and os_module.geteuid()==0,"G4_SOURCE_SCOPE_STOP")
    need(tuple(roots)==ROOTS,"G4_SOURCE_SCOPE_STOP")
    first=mount_namespace_identity(os_module)
    for path in roots:
        try:
            s=path.lstat()
            need(stat.S_ISDIR(s.st_mode) and not path.is_symlink())
            flags=os_module.statvfs(path).f_flag
        except OSError:
            raise Stop("G4_MOUNT_VIEW_STOP") from None
        need(bool(flags & os_module.ST_RDONLY))
    need(mount_namespace_identity(os_module)==first)
    return {"phase":"R1101","result":"NECESSARY_HOST_MOUNT_VIEW_ONLY",
            "original_mount_namespace":"MATCH","original_ro_view":"MATCH",
            "host_writers_fenced":"NOT_PROVEN",
            "relaunch_prevented":"NOT_PROVEN",
            "five_routes_final":"NOT_PROVEN",
            "owner_release":"NOT_PROVEN",
            "source_archival_authorized":False,
            "cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}
