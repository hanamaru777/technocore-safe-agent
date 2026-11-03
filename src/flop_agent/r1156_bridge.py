"""Read-only Resident integration; no signing, broker client or network write."""
import importlib.util
import os
from pathlib import Path
import sys
import time

from . import core,observer
_BASE=observer.atomic_json_write
_INSTALLED=False


def runtime():
    name="flop_r1156_local_bridge"
    if name not in sys.modules:
        path=Path("/usr/local/libexec/flop-r1155/packaging/migration/r1156_runtime.py")
        sp=importlib.util.spec_from_file_location(name,path)
        m=importlib.util.module_from_spec(sp);sys.modules[name]=m;sp.loader.exec_module(m)
    return sys.modules[name]


def install():
    global _INSTALLED
    if _INSTALLED:return
    m=runtime();m.H.need(core.STATE==m.STATE,"AUTONOMY_STATE_ROOT_STOP")
    def write(path,value,*args,**kwargs):
        path=Path(path)
        if path.is_relative_to(m.STATE):
            if args:args=(0o640,*args[1:])
            else:kwargs["mode"]=0o640
        result=_BASE(path,value,*args,**kwargs)
        if path==m.STATE/"observer/observer-state.json":
            _BASE(path.with_name("room-generation-status.json"),dict(observed_at=int(time.time()),
                room_generations=value.get("room_generations",{})),mode=0o640,compact=True)
        return result
    observer.atomic_json_write=write;_INSTALLED=True


def before_maintenance():
    # Imported in the original spawned maintenance child only in explicit R1156
    # mode. Expired admission pauses optional work; Observer reads continue.
    try:install();runtime().before_maintenance();return True
    except (ValueError,RuntimeError,OSError):return False
