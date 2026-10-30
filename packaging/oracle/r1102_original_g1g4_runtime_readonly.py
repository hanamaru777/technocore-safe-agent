"""R1102 live original OCI, strictly read-only G1/G4 launcher/fd survey.

A host runtime snapshot is NOT continuous fence, all-launcher proof, G5
external finality, or a release authorization. No deletion, stop, restart,
mount, secret content, SQLite, signed nonce, or outbound traffic.
"""
from __future__ import annotations
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
EXPECTED=frozenset(["airdrop-monitor.service","airdrop-monitor.timer","airdrop-notifier.service","airdrop-notifier.timer","discord.service","lobby-capture.service","resident.service","technocore-safe-agent-close1-approved-trade.service","technocore-safe-agent-close1-auto-resident.service","technocore-safe-agent-close1-batch-trade.service","technocore-safe-agent-close1-standalone-watch.service","technocore-safe-agent-metadata-block.service","technocore-safe-agent-precontest-supervisor.service","technocore-safe-agent-precontest-supervisor.timer","technocore-safe-agent-signer.service","technocore-safe-agent-tclk-accept@.service","technocore-safe-agent-tclk-lock-watcher.service","technocore-safe-agent-tclk-lock-watcher.timer","technocore-safe-agent-tclk-preparer.service","technocore-safe-agent-tclk-preparer.timer","technocore-safe-agent-tclk-reveal-preparer.service","technocore-safe-agent-tclk-reveal-preparer.timer","technocore-safe-agent-tclk-reveal@.service","technocore-safe-agent-tclk-stager.service","technocore-safe-agent-tclk-stager.timer","technocore-safe-agent-tclk-work-watcher.service","technocore-safe-agent-tclk-work-watcher.timer"])
SPECIAL=frozenset((
    "technocore-safe-agent-close1-discord-activation.service",
    "technocore-safe-agent-close1-discord-activation.timer",
    "technocore-safe-agent-close1-standalone-watch.timer",
    "technocore-safe-agent-postreboot-check.service"))
MATCH=re.compile(r"^(?:technocore-safe-agent-|(?:airdrop-(?:monitor|notifier)|discord|lobby-capture|resident)\.)")
PATTERN=re.compile(rb"(?i:technocore|flop_agent|/opt/technocore|/var/lib/technocore)")
MAX_SECONDS=48
MAX_UNITS=2048
MAX_PROC=4096
MAX_FD=65536
MAX_CRON=2048

class Stop(Exception):pass
def need(ok,reason):
    if not ok:raise Stop(reason)
def deadline(start):
    need(time.monotonic()-start < MAX_SECONDS,"TIME_BOUND_STOP")

def original_check():
    need(sys.platform=="linux" and os.geteuid()==0,"ORIGINAL_ROOT_STOP")
    for path in (APP,STATE):
        for ancestor in (path,*path.parents):
            need(not ancestor.is_symlink(),"ROOT_ALIAS_STOP")
        need(stat.S_ISDIR(path.lstat().st_mode),"ROOT_TYPE_STOP")
    run=subprocess.run(["/usr/bin/git","-c","safe.directory="+str(APP),"-C",str(APP),
       "rev-parse","--verify","HEAD"],capture_output=True,stdin=subprocess.DEVNULL,
       timeout=8,env={"PATH":"/usr/bin:/bin","HOME":"/nonexistent","GIT_CONFIG_NOSYSTEM":"1",
                     "GIT_CONFIG_GLOBAL":"/dev/null","GIT_OPTIONAL_LOCKS":"0"})
    need(run.returncode==0 and run.stdout==(HEAD+"\n").encode(),"ORIGINAL_HEAD_STOP")

def units(start):
    roots=(Path("/etc/systemd/system"),Path("/run/systemd/system"),
       Path("/usr/lib/systemd/system"),Path("/lib/systemd/system"))
    recognized=set(); installed=set();extras=set();dropins=set()
    aliases=0;objects=0
    for d in roots:
        deadline(start)
        if not d.exists():continue
        need(not d.is_symlink() and stat.S_ISDIR(d.lstat().st_mode),"UNIT_ROOT_STOP")
        with os.scandir(d) as it:
            for ent in it:
                objects+=1;need(objects<=MAX_UNITS,"UNIT_BOUND_STOP")
                name=ent.name
                if name.endswith((".service",".timer")) and MATCH.search(name):
                    installed.add(name)
                    if name in EXPECTED:recognized.add(name)
                    else:extras.add(name)
                    if ent.is_symlink():aliases+=1
                elif name.endswith(".d") and MATCH.search(name):
                    dropins.add(name)
    proc=subprocess.run(["/usr/bin/systemctl","list-units","--all","--plain",
      "--no-legend","--no-pager"],stdin=subprocess.DEVNULL,capture_output=True,
      timeout=10,env={"PATH":"/usr/bin:/bin","LC_ALL":"C","SYSTEMD_PAGER":"cat"})
    need(proc.returncode==0 and len(proc.stdout)<=256000,"SYSTEMD_QUERY_STOP")
    active=set();dynamic=set();loaded=set()
    for row in proc.stdout.decode("utf-8","replace").splitlines():
        deadline(start)
        columns=row.lstrip("● ").split()
        if len(columns)<4:continue
        unit=columns[0]
        if not MATCH.search(unit):continue
        loaded.add(unit)
        if len(columns)>2 and columns[2]=="active":active.add(unit)
        if re.search(r"^technocore-safe-agent-tclk-(?:accept|reveal)@[^@]+\.service$",unit):
            dynamic.add(unit)
    return {"expected_source_templates":len(EXPECTED),
       "recognized_installed_templates":len(recognized),
       "missing_expected_templates":len(EXPECTED-recognized),
       "extra_installed_names":len(extras),
       "historical_four_extras_present":len(extras & SPECIAL),
       "dropin_directories":len(dropins),"symlink_unit_aliases":aliases,
       "loaded_matching_units":len(loaded),"active_matching_units":len(active),
       "dynamic_tclk_instances":len(dynamic),"unit_root_objects":objects,
       "unit_execstart_and_all_aliases_verified":False}

def cron(start):
    locations=(Path("/etc/crontab"),Path("/etc/cron.d"),Path("/var/spool/cron/crontabs"))
    objects=0;special=0;truncated=0;matches=0;denied=0
    for root in locations:
        deadline(start)
        if not root.exists():continue
        if root.is_symlink():denied+=1;continue
        paths=[root]
        if root.is_dir():
            try:
                with os.scandir(root) as it:paths=[Path(e.path) for e in it]
            except OSError:
                denied+=1;continue
        for p in paths:
            objects+=1;need(objects<=MAX_CRON,"CRON_BOUND_STOP")
            try:
                s=p.lstat()
                if not stat.S_ISREG(s.st_mode):
                    special+=1;continue
                if s.st_size>131072:
                    truncated+=1;continue
                with p.open("rb") as f:data=f.read(131073)
                if len(data)>131072:
                    truncated+=1;continue
                if PATTERN.search(data):matches+=1
            except OSError:denied+=1
    return {"cron_objects":objects,"cron_content_matches":matches,
            "cron_special_objects":special,"cron_oversize":truncated,
            "cron_unreadable":denied,
            "manual_and_transient_launchers_proven_absent":False}

def open_fds(start):
    matched_pids=set();rw=0;unknown=0;seen=0;matched=0
    try:
        pids=[p for p in Path("/proc").iterdir() if p.name.isdecimal()]
    except OSError:raise Stop("PROC_ROOT_STOP") from None
    need(len(pids)<=MAX_PROC,"PROC_BOUND_STOP")
    for p in pids:
        deadline(start)
        try:
            fds=list((p/"fd").iterdir())
        except FileNotFoundError:continue
        except OSError:
            unknown+=1;continue
        for fd in fds:
            seen+=1;need(seen<=MAX_FD,"FD_BOUND_STOP")
            try:
                target=os.readlink(fd)
            except OSError:
                unknown+=1;continue
            if not any(target==str(root) or target.startswith(str(root)+"/") for root in (APP,STATE)):
                continue
            matched+=1;matched_pids.add(p.name)
            try:
                info=(p/"fdinfo"/fd.name).read_bytes()
                need(len(info)<=4096,"FD_INFO_BOUND_STOP")
                flags=re.findall(rb"^flags:\s+([0-7]+)$",info,re.M)
                need(len(flags)==1,"FD_INFO_SCHEMA_STOP")
                if int(flags[0],8)&os.O_ACCMODE!=os.O_RDONLY:
                    rw+=1
            except (OSError,ValueError):
                unknown+=1
    return {"relevant_processes":len(matched_pids),
        "relevant_file_descriptors":matched,"writable_descriptors":rw,
        "proc_races_or_unknown_descriptors":unknown,
        "all_writers_fenced":False}

def namespaces():
    try:
        a=os.stat("/proc/self/ns/mnt")
        b=os.stat("/proc/1/ns/mnt")
        same=(a.st_dev,a.st_ino)==(b.st_dev,b.st_ino)
    except OSError:same=False
    return {"pid1_mount_namespace_matches":same,
            "all_original_mount_aliases_fenced":False}

def main():
    try:
        original_check()
        start=time.monotonic()
        result={"phase":"R1102","result":"LIVE_G1_G4_DIAGNOSTIC_ONLY",
          "action":"READ_ONLY","units":units(start),"cron":cron(start),
          "descriptors":open_fds(start),"mounts":namespaces(),
          "signed_g4":"NOT_PROVEN","all_five_upstream_post_verdicts":"NOT_PROVEN",
          "source_archive":"NOT_AUTHORIZED","cutover":"NO_GO",
          "oci_retirement":"STRICT_NO_GO"}
        print(json.dumps(result,separators=(",",":"),sort_keys=True))
        return 0
    except (Stop,OSError,subprocess.SubprocessError):
        print('{"phase":"R1102","result":"STOP","code":"READONLY_SURVEY_STOP"}')
        return 42

if __name__=="__main__":sys.exit(main())
