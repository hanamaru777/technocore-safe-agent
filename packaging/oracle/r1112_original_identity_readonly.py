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
    def __init__(self, code="READ_ONLY_WITNESS_UNAVAILABLE"):
        super().__init__(code)

def need(value, code="READ_ONLY_WITNESS_UNAVAILABLE"):
    if not value:
        raise Stop(code)

def read_command(argv,deadline):
    need(time.monotonic() <= deadline, "TIME_BUDGET_STOP")
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
    need(NAME.fullmatch(name), "UNIT_NAME_STOP")
    try:
        raw=read_command(["/usr/bin/systemctl","--no-pager","--all","show",
            "--property="+",".join(PROPS),"--",name],deadline)
    except Stop:
        raise Stop("UNIT_SHOW_STOP") from None
    result={}
    try:
        for line in raw.decode("utf-8","strict").splitlines():
            key,value=line.split("=",1)
            need(key in PROPS and key not in result and len(value)<=65536,
                 "UNIT_SCHEMA_STOP")
            result[key]=value
    except (UnicodeError,ValueError):
        raise Stop("UNIT_SCHEMA_STOP") from None
    # systemd.service and systemd.timer expose different properties.
    # Only common identity/runtime keys are required; collect the rest if
    # present but do not silently fabricate unsupported keys.
    need({"Id","Names","LoadState","ActiveState"}.issubset(result),
         "UNIT_SCHEMA_STOP")
    need(name==result["Id"] or name in result["Names"].split(),
         "UNIT_IDENTITY_STOP")
    return result

def template_properties(name,deadline):
    # A bare foo@.service is a template, not an instance: systemctl show
    # may reject it. systemctl cat reads its backing unit file and drop-ins
    # without activating it. Only digest the content; never emit it.
    need(name.endswith("@.service"), "UNIT_NAME_STOP")
    try:
        body=read_command(["/usr/bin/systemctl","--no-pager","cat","--",name],
                          deadline)
    except Stop:
        raise Stop("TEMPLATE_CAT_STOP") from None
    need(0<len(body)<=131072,"TEMPLATE_CAT_STOP")
    # DISK-ONLY: systemctl cat may disagree with manager-loaded state
    # until daemon-reload. Never turn this digest into G1 runtime proof.
    return {"template_source_sha256":hashlib.sha256(body).hexdigest()}

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
    # Do NOT query missing expected unit names. R1102 already observed
    # eight missing templates on the actual original, and querying unknown
    # units can return nonzero or synthesize transient metadata.
    names=sorted(set(files)|set(loaded))
    need(len(names)<=1024, "UNIT_BOUND_STOP")
    def collect():
        result={}
        for name in names:
            need(time.monotonic()<=end,"TIME_BUDGET_STOP")
            if name.endswith("@.service"):
                result[name]=template_properties(name,end)
            else:
                result[name]=properties(name,end)
        return result
    results=collect()
    f2,l2=get_names()
    need(files==f2 and loaded==l2, "UNIT_RACE_STOP")
    need(results==collect(), "UNIT_RACE_STOP")
    present=sorted(n for n in EXPECTED if n in files)
    missing=sorted(EXPECTED-set(present))
    extras=sorted((set(files)|set(loaded))-EXPECTED)
    effective=hashlib.sha256(json.dumps(results,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    identities=hashlib.sha256(json.dumps({"files":files,"loaded":loaded},sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return {"phase":"R1112","result":"PRIVATE_G1_IDENTITY_WITNESS_ONLY",
        "action":"READ_ONLY","source_head":HEAD,"expected":len(EXPECTED),
        "recognized":len(present),"missing":len(missing),"extras":len(extras),
        "loaded":len(loaded),"unit_observation_sha256":effective,
        "unit_identity_sha256":identities,
        "template_source_scope":"DISK_ONLY_NOT_LIVE_EQUIVALENCE",
        "live_template_equivalence_proven":False,
        "all_launchers_proven":False,
        "all_writers_fenced":False,"g5_finality":"NOT_PROVEN",
        "source_archive":"NO_GO","cutover":"NO_GO",
        "oci_retirement":"STRICT_NO_GO"}

def main():
    try:
        value=witness()
    except (Stop,OSError,ValueError,UnicodeError,subprocess.SubprocessError,
            TimeoutError,KeyError,TypeError) as exc:
        # Public diagnostic contract is a fixed enum, never raw systemd
        # messages, file names, configuration, SSH stderr or key material.
        allowed=frozenset({"UNIT_NAME_STOP","UNIT_SHOW_STOP",
            "UNIT_SCHEMA_STOP","UNIT_IDENTITY_STOP","TEMPLATE_CAT_STOP",
            "UNIT_RACE_STOP","UNIT_BOUND_STOP","TIME_BUDGET_STOP"})
        code=str(exc) if type(exc) is Stop else "READ_ONLY_WITNESS_UNAVAILABLE"
        if code not in allowed:code="READ_ONLY_WITNESS_UNAVAILABLE"
        value={"phase":"R1112","result":"STOP",
               "reason":code,
               "source_archive":"NO_GO","cutover":"NO_GO",
               "oci_retirement":"STRICT_NO_GO"}
    print(json.dumps(value,sort_keys=True,separators=(",",":")))
    return 0 if value["result"]=="PRIVATE_G1_IDENTITY_WITNESS_ONLY" else 42

if __name__=="__main__":
    raise SystemExit(main())
