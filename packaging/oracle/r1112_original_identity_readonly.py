"""R1112: original-host G1 effective-identity one-shot, STRICT READ ONLY.

Returns only counts and SHA256 digests, never unit names/config or credentials.
This DOES NOT prove continuous G4, G5, source archive, cutover or retirement.
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
import time

APP=Path("/opt/technocore-safe-agent")
STATE=Path("/var/lib/technocore-safe-agent")
HEAD="ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
EXPECTED=frozenset("""airdrop-monitor.service airdrop-monitor.timer airdrop-notifier.service airdrop-notifier.timer discord.service lobby-capture.service resident.service technocore-safe-agent-close1-approved-trade.service technocore-safe-agent-close1-auto-resident.service technocore-safe-agent-close1-batch-trade.service technocore-safe-agent-close1-standalone-watch.service technocore-safe-agent-metadata-block.service technocore-safe-agent-precontest-supervisor.service technocore-safe-agent-precontest-supervisor.timer technocore-safe-agent-signer.service technocore-safe-agent-tclk-accept@.service technocore-safe-agent-tclk-lock-watcher.service technocore-safe-agent-tclk-lock-watcher.timer technocore-safe-agent-tclk-preparer.service technocore-safe-agent-tclk-preparer.timer technocore-safe-agent-tclk-reveal-preparer.service technocore-safe-agent-tclk-reveal-preparer.timer technocore-safe-agent-tclk-reveal@.service technocore-safe-agent-tclk-stager.service technocore-safe-agent-tclk-stager.timer technocore-safe-agent-tclk-work-watcher.service technocore-safe-agent-tclk-work-watcher.timer""".split())
PREFIX=re.compile(r"^(?:technocore-safe-agent-|(?:airdrop-(?:monitor|notifier)|discord|lobby-capture|resident)\.)")
NAME=re.compile(r"^[A-Za-z0-9_.:@\\-]{1,220}\.(?:service|timer|socket|path|scope|mount|automount|target|slice)$")
PROPS=("Id","Names","LoadState","ActiveState","UnitFileState","FragmentPath","DropInPaths","ExecStart","ExecStartPre","ExecStartPost","Restart","Wants","Requires","PartOf","BindsTo","Triggers","TriggeredBy","Transient","ControlGroup","SourcePath")
MAX_SECONDS=35

class Stop(Exception):
    pass

def need(value):
    if not value:
        raise Stop()

def read_command(argv,deadline):
    need(time.monotonic() <= deadline)
    p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,timeout=8,shell=False,
        env={"PATH":"/usr/bin:/bin","LANG":"C","GIT_CONFIG_NOSYSTEM":"1",
             "GIT_CONFIG_GLOBAL":"/dev/null","GIT_OPTIONAL_LOCKS":"0"})
    need(p.returncode==0 and len(p.stdout)<=2*1024**2)
    return p.stdout

def parse_rows(raw,field):
    # The real original systemd may be v249; --output=json is not a
    # portable list-units format (it controls journal output). Reuse the
    # bounded, previously proven R1102 text-list API without executing it.
    need(field in ("unit_file","unit"))
    lines=raw.decode("utf-8","strict").splitlines()
    need(len(lines)<=8192)
    names=[]
    for line in lines:
        cols=line.lstrip("● ").split()
        if not cols:
            continue
        name=cols[0]
        if PREFIX.search(name):
            need(NAME.fullmatch(name))
            names.append(name)
    need(len(set(names))==len(names))
    return sorted(names)

def properties(name,deadline):
    need(NAME.fullmatch(name))
    raw=read_command(["/usr/bin/systemctl","--no-pager","--all","show",
        "--property="+",".join(PROPS),"--",name],deadline)
    result={}
    for line in raw.decode("utf-8","strict").splitlines():
        key,value=line.split("=",1)
        need(key in PROPS and key not in result and len(value)<=65536)
        result[key]=value
    need(set(result)==set(PROPS) and
        (name in result["Names"].split() or result["LoadState"]=="not-found"))
    return result

def witness():
    need(sys.platform=="linux" and os.geteuid()==0 and len(EXPECTED)==27)
    end=time.monotonic()+MAX_SECONDS
    for root in (APP,STATE):
        for ancestor in (root,*root.parents):
            need(not ancestor.is_symlink())
        need(stat.S_ISDIR(root.lstat().st_mode))
    head=read_command(["/usr/bin/git","-c","safe.directory="+str(APP),
                       "-C",str(APP),"rev-parse","--verify","HEAD"],end)
    need(head==(HEAD+"\n").encode())
    def get_names():
        files=parse_rows(read_command(["/usr/bin/systemctl","--no-pager",
            "--no-legend","--full","list-unit-files","--all"],end),"unit_file")
        loaded=parse_rows(read_command(["/usr/bin/systemctl","--no-pager",
            "--no-legend","--plain","--full","list-units","--all"],end),"unit")
        return files,loaded
    files,loaded=get_names()
    names=sorted(set(files)|set(loaded)|EXPECTED)
    need(len(names)<=1024)
    results={name:properties(name,end) for name in names}
    f2,l2=get_names()
    need(files==f2 and loaded==l2)
    need(all(results[name]==properties(name,end) for name in names))
    present=sorted(n for n in EXPECTED if n in files and results[n]["LoadState"]=="loaded")
    missing=sorted(EXPECTED-set(present))
    extras=sorted((set(files)|set(loaded))-EXPECTED)
    effective=hashlib.sha256(json.dumps(results,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    identities=hashlib.sha256(json.dumps({"files":files,"loaded":loaded},sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return {"phase":"R1112","result":"PRIVATE_G1_IDENTITY_WITNESS_ONLY",
        "action":"READ_ONLY","source_head":HEAD,"expected":len(EXPECTED),
        "recognized":len(present),"missing":len(missing),"extras":len(extras),
        "loaded":len(loaded),"effective_config_sha256":effective,
        "unit_identity_sha256":identities,"all_launchers_proven":False,
        "all_writers_fenced":False,"g5_finality":"NOT_PROVEN",
        "source_archive":"NO_GO","cutover":"NO_GO",
        "oci_retirement":"STRICT_NO_GO"}

def main():
    try:
        value=witness()
    except (Stop,OSError,ValueError,UnicodeError,subprocess.SubprocessError,
            TimeoutError,KeyError,TypeError):
        value={"phase":"R1112","result":"STOP",
               "reason":"READ_ONLY_WITNESS_UNAVAILABLE",
               "source_archive":"NO_GO","cutover":"NO_GO",
               "oci_retirement":"STRICT_NO_GO"}
    print(json.dumps(value,sort_keys=True,separators=(",",":")))
    return 0 if value["result"]=="PRIVATE_G1_IDENTITY_WITNESS_ONLY" else 42

if __name__=="__main__":
    raise SystemExit(main())
