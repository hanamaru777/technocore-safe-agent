"""Executable ORIGINAL FLOP-only maintenance. Never powers off a VM.

Owner + independent scope admission is required BEFORE mutation. Masks stop
known systemd relaunches; a persistent UID egress deny quarantines old POSTs.
This is NOT arbitrary-root/global G4 and does NOT release R1089's old gates.
"""
from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import time
if sys.platform == "linux": import pwd

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    sp = importlib.util.spec_from_file_location(name, ROOT/path)
    module = importlib.util.module_from_spec(sp); sys.modules[name] = module; sp.loader.exec_module(module)
    return module


C = load("flop_r1107_contract", "packaging/migration/r1107_contract.py")
B = C.legacy("r1151_preseed_owner_bridge.py")
J = C.legacy("r1117_boundary.py")
P = C.legacy("r1107_g5_reconciliation.py")
WORK = Path("/var/lib/flop-r1154-app-hold")
UNITS = Path("/etc/systemd/system")
GUARD = "flop-r1154-post-deny.service"
PROTECTED = {"ssh.service", "sshd.service", "ssh.socket", "oracle-cloud-agent.service",
             "oracle-cloud-agent-updater.service", "technocore-safe-agent-metadata-block.service", GUARD}
USERS = {"technocore", "technocore-signer", "technocore-rpc"}
SURFACES = {"cron", "user_units", "generators", "manual", "transient", "namespaces", "external_writers"}
STOP_PROPERTIES = ("User", "PermissionsStartOnly", "NoNewPrivileges", "AmbientCapabilities",
    "ExecStop", "ExecStopPost", "FailureAction", "SuccessAction", "StartLimitAction", "JobTimeoutAction",
    "PropagatesStopTo", "ConsistsOf", "BoundBy", "RequiredBy", "OnFailure", "OnSuccess")
STOP_EDGES = ("PropagatesStopTo", "ConsistsOf", "BoundBy", "RequiredBy", "OnFailure", "OnSuccess")


class Stop(ValueError): pass


def need(ok, code):
    if not ok: raise Stop(code)


def shape(value, fields):
    need(type(value) is dict and set(value) == set(fields.split()), "WARM_SCHEMA_STOP")


def tool_blob():
    raw=Path(__file__).read_bytes().replace(b"\r\n",b"\n")
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()


class Authority:
    def __init__(self, profile, digest):
        need(C.G.sha(profile) == C.digest(digest), "WARM_ENROLLMENT_STOP")
        self.profile = C.decode(C.G.canonical(profile)); self.pin = digest
        self.trust = C.Enrollment(self.profile)
        need(self.trust.context["destination"]==B.K137,"WARM_DESTINATION_STOP")

    def verify(self, packet, kind, role, now):
        need(C.G.sha(self.profile) == self.pin, "WARM_ENROLLMENT_STOP")
        return self.trust.verify(packet, "r1154-"+kind, role, now, age=900)


def validate_scope(authority, scope, *, now):
    shape(scope, "version run_id source units users surfaces quarantine templates known_hosts_sha launcher_sha destination tool_blob owner witness")
    need(scope["tool_blob"]==tool_blob(),"WARM_TOOL_PIN_STOP")
    C.digest(scope["known_hosts_sha"])
    C.digest(scope["launcher_sha"])
    need(type(scope["version"]) is int and scope["version"] == 1 and type(scope["run_id"]) is str and
         re.fullmatch(r"[0-9a-f]{32}", scope["run_id"]), "WARM_SCOPE_STOP")
    need(scope["source"] == authority.trust.context, "WARM_SOURCE_STOP")
    shape(scope["users"], "technocore technocore-signer") if "technocore-rpc" not in scope["users"] else shape(scope["users"], "technocore technocore-signer technocore-rpc")
    values = list(scope["users"].values())
    need(all(type(uid) is int and 1001 <= uid < 65534 for uid in values) and len(set(values)) == len(values), "WARM_SHARED_UID_STOP")
    need(type(scope["units"]) is dict and 1 <= len(scope["units"]) <= 128, "WARM_UNIT_BOUND_STOP")
    for name, row in scope["units"].items():
        need(J.NAME.fullmatch(name) and "\\" not in name and name not in PROTECTED and
             (name.startswith("technocore-safe-agent-") or name in ("resident.service", "discord.service", "lobby-capture.service", "airdrop-monitor.service", "airdrop-monitor.timer", "airdrop-notifier.service", "airdrop-notifier.timer")), "WARM_PROTECTED_UNIT_STOP")
        shape(row, "properties_sha file_sha user targets stop_edges")
        C.digest(row["properties_sha"]); C.digest(row["file_sha"])
        need(row["user"] in scope["users"] or name.endswith((".timer", ".socket", ".path")), "WARM_SHARED_UID_STOP")
        need(type(row["targets"]) is list and len(row["targets"])<=16 and all(target in scope["units"] for target in row["targets"]),"WARM_ACTIVATOR_TARGET_STOP")
        if name.endswith((".timer", ".socket", ".path")): need(row["targets"],"WARM_ACTIVATOR_TARGET_STOP")
        need(type(row["stop_edges"]) is list and len(row["stop_edges"])<=128 and
             len(set(row["stop_edges"]))==len(row["stop_edges"]) and
             all(target in scope["units"] for target in row["stop_edges"]),"WARM_STOP_PROPAGATION_STOP")
    need(type(scope["templates"]) is dict and set(scope["templates"]) == C.U.EXPECTED, "WARM_TEMPLATE_COVERAGE_STOP")
    for name, aliases in scope["templates"].items():
        need(type(aliases) is list and len(aliases) <= 16 and len(aliases) == len(set(aliases)) and
             all(alias in scope["units"] or alias in PROTECTED for alias in aliases), "WARM_TEMPLATE_COVERAGE_STOP")
    need(scope["surfaces"] == {key: "INDEPENDENTLY_REVIEWED_NO_OUTSIDE_LAUNCHER" for key in SURFACES}, "WARM_LAUNCHER_UNKNOWN_STOP")
    shape(scope["quarantine"], "routes inventory_sha ledger_sha permanent loss_accepted")
    q = scope["quarantine"]
    need(q["routes"] == list(P.ROUTES) and q["permanent"] is True and q["loss_accepted"] is True, "WARM_QUARANTINE_STOP")
    C.digest(q["inventory_sha"]); C.digest(q["ledger_sha"])
    destination=authority.trust.verify(scope["destination"],"r1154-destination","destination",now,age=30)
    shape(destination,"machine free_bytes source_upper_bound_bytes memory_headroom_bytes cpu_psi_milli io_psi_milli disarmed_ready publisher_disarmed zero_cost_verified")
    for key in ("free_bytes","source_upper_bound_bytes","memory_headroom_bytes","cpu_psi_milli","io_psi_milli"):C.integer(destination[key])
    need(destination["machine"]==B.K137 and destination["disarmed_ready"] is True and destination["publisher_disarmed"] is True and
         destination["zero_cost_verified"] is True and 0<destination["source_upper_bound_bytes"]<=C.R.T.C.MAX_SOURCE_BYTES and
         destination["free_bytes"]>=20*C.R.GIB+2*destination["source_upper_bound_bytes"]+2*C.R.GIB and
         destination["memory_headroom_bytes"]>=512*1024**2 and destination["cpu_psi_milli"]<=5000 and
         destination["io_psi_milli"]<=10000,"WARM_K137_CAPACITY_STOP")
    binding = C.G.sha({k: v for k, v in scope.items() if k not in ("owner", "witness")})
    for key, role in (("owner", "owner"), ("witness", "independent")):
        need(authority.verify(scope[key], "hold", role, now) == dict(scope_sha=binding,
            downtime=True, keep_vm_running=True, keep_ssh=True, cost_cap="ZERO_NEW_BILLING",
            permanent_post_deny=True), "WARM_APPROVAL_STOP")
    return binding


def boot_unit(uids, names):
    lines = ["[Unit]", "Description=FLOP R1154 permanent old POST quarantine", "DefaultDependencies=no",
             "After=local-fs.target", "Before=network-pre.target "+" ".join(sorted(names)), "Wants=network-pre.target",
             "[Service]", "Type=oneshot", "RemainAfterExit=yes", "User=root", "NoNewPrivileges=yes",
             "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "CapabilityBoundingSet=CAP_NET_ADMIN"]
    for uid in sorted(uids):
        for binary in ("/usr/sbin/iptables", "/usr/sbin/ip6tables"):
            lines.append(f"ExecStart={binary} -w 5 -I OUTPUT 1 -m owner --uid-owner {uid} -m comment --comment FLOP_R1154 -j REJECT")
    return ("\n".join(lines)+"\n").encode()


class Linux:
    """Fixed commands, no shell and no arbitrary unit/UID/operation input."""
    def __init__(self, runner=subprocess.run):
        self.runner = runner; self.reader = J.MetadataReader(runner)

    def command(self, args, *, allowed=(0,)):
        try:
            r = self.runner(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=30, shell=False, env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LANG":"C", "HOME":"/nonexistent",
                    "GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null","GIT_OPTIONAL_LOCKS":"0"})
            need(r.returncode in allowed and len(r.stdout) <= 2*1024**2, "WARM_COMMAND_STOP")
            return r
        except (OSError, subprocess.SubprocessError): raise Stop("WARM_COMMAND_STOP") from None

    def identity(self, scope):
        need(sys.platform == "linux" and os.geteuid() == 0 and sys.version_info>=(3,12), "WARM_ROOT_REQUIRED")
        got = self.reader.identity()
        need(got["host_digest"] == scope["source"]["host"], "WARM_SOURCE_STOP")
        self.command(["/usr/bin/git","-c","safe.directory="+C.ROOTS[0],"-c","core.fsmonitor=false",
            "-C",C.ROOTS[0],"diff","--quiet","--no-ext-diff","--exit-code","HEAD","--"])
        for user, uid in scope["users"].items():
            need(pwd.getpwnam(user).pw_uid == uid, "WARM_SHARED_UID_STOP")

    def discovered(self):
        # One bounded bulk READ avoids 1000+ sequential `show` subprocesses.
        # Individual selected identities are still revalidated by unit().
        names=set(self.reader.unit_files())|set(self.reader.loaded())
        need(len(names)<=2048 and all(J.NAME.fullmatch(n) for n in names),"WARM_UNIT_BOUND_STOP")
        templates={n for n in names if n.endswith("@.service")}
        normal=sorted(names-templates)
        raw=self.command(["/usr/bin/systemctl","--no-pager","show","--all",
            "--property="+",".join(J.B.PROPERTIES),"--",*normal]).stdout
        blocks={};seen=set()
        for section in raw.decode("utf8","strict").strip().split("\n\n"):
            row={}
            for line in section.splitlines():
                key,value=line.split("=",1)
                need(key in J.B.PROPERTIES and key not in row,"WARM_UNIT_SCHEMA_STOP");row[key]=value
            identity=row.get("Id");need(identity and J.NAME.fullmatch(identity),"WARM_UNIT_SCHEMA_STOP")
            if identity in blocks:need(blocks[identity]==row,"WARM_UNIT_SCHEMA_STOP")
            blocks[identity]=row;seen.add(identity);seen.update(row.get("Names","").split())
        need(set(normal)<=seen,"WARM_UNIT_SCHEMA_STOP")
        candidates={name for name in templates if name.startswith(("technocore-","flop-")) or name in C.U.EXPECTED}
        for row in blocks.values():
            aliases={row["Id"],*row.get("Names","").split()} & names
            if row.get("LoadState")=="not-found":continue
            if any(n.startswith(("technocore-","flop-")) or n in C.U.EXPECTED for n in aliases) or any(root in C.G.canonical(row).decode() for root in C.ROOTS):
                candidates.update(aliases)
        need(names==set(self.reader.unit_files())|set(self.reader.loaded()),"WARM_SCOPE_DRIFT_STOP")
        return candidates-PROTECTED

    def unit(self, name):
        observed = self.reader.observed(name)
        if name.endswith("@.service"):
            options=[UNITS/name,Path("/lib/systemd/system")/name,Path("/usr/lib/systemd/system")/name]
            path=next((p for p in options if p.is_file() and not p.is_symlink()),None)
            need(path is not None and path.stat().st_size<=131072,"WARM_UNIT_FILE_STOP")
            raw=path.read_bytes()
            merged=self.command(["/usr/bin/systemctl","--no-pager","cat","--",name]).stdout
            users=re.findall(rb"^User=([a-z0-9_-]+)$",merged,re.M)
            need(len(users)==1,"WARM_SHARED_UID_STOP")
            # No template is stopped; every loaded instance is separately
            # checked below. Still reject ambiguous User overrides/resets.
            need(len(re.findall(rb"^User=",merged,re.M))==1,"WARM_SHARED_UID_STOP")
            return dict(properties_sha=C.G.sha(observed),file_sha=hashlib.sha256(raw).hexdigest(),user=users[0].decode(),targets=[],stop_edges=[])
        # No raw properties or unit bodies are returned to the owner log.
        extra=self.command(["/usr/bin/systemctl","--no-pager","show","--all",
            "--property="+",".join(STOP_PROPERTIES),"--",name]).stdout
        fields={}
        for line in extra.decode("utf8","strict").splitlines():
            key,value=line.split("=",1)
            need(key in STOP_PROPERTIES and key not in fields,"WARM_STOP_PROPERTIES_STOP");fields[key]=value
        need(set(fields)==set(STOP_PROPERTIES),"WARM_STOP_PROPERTIES_STOP")
        p=fields["User"]
        for action in ("FailureAction","SuccessAction","StartLimitAction","JobTimeoutAction"):
            need(fields[action]=="none","WARM_HOST_ACTION_STOP")
        if name.endswith(".service"):
            need(fields["PermissionsStartOnly"] in ("no","false") and fields["NoNewPrivileges"] in ("yes","true") and
                 not fields["AmbientCapabilities"],"WARM_PRIVILEGED_STOP_STOP")
            merged=self.command(["/usr/bin/systemctl","--no-pager","cat","--",name]).stdout
            merged=merged.replace(b"\r\n",b"\n").replace(b"\\\n",b" ")
            need(not re.search(rb"^\s*Exec[A-Za-z]+=\s*[-:@|]*[+!]",merged,re.M),"WARM_PRIVILEGED_STOP_STOP")
        fragment = self.command(["/usr/bin/systemctl", "--no-pager", "show", "--property=FragmentPath", "--value", "--", name]).stdout.decode().strip()
        path = Path(fragment)
        if not name.endswith((".timer", ".socket", ".path", "@.service")):
            need(any(root in C.G.canonical(observed).decode() for root in C.ROOTS), "WARM_UNRELATED_UNIT_STOP")
        need(path.is_absolute() and not path.is_symlink() and path.is_file() and path.stat().st_size <= 131072, "WARM_UNIT_FILE_STOP")
        targets=observed.get("properties",{}).get("Triggers","").split() if name.endswith((".timer",".socket",".path")) else []
        edges=sorted({target for key in STOP_EDGES for target in fields[key].split()})
        return dict(properties_sha=C.G.sha(dict(observed=observed,stop_properties=fields)),
            file_sha=hashlib.sha256(path.read_bytes()).hexdigest(),user=p,targets=targets,stop_edges=edges)

    def protected(self):
        # Hash-only machine/boot identity and fixed protected service metadata;
        # no command lines, environment or arbitrary process inspection.
        snapshot={"boot":hashlib.sha256(Path("/proc/sys/kernel/random/boot_id").read_bytes()).hexdigest(),"units":{}}
        for name in sorted(PROTECTED-{GUARD}):
            raw=self.command(["/usr/bin/systemctl","--no-pager","show","--all",
                "--property=LoadState,ActiveState,MainPID","--",name]).stdout
            fields={}
            for line in raw.decode("ascii","strict").splitlines():
                key,value=line.split("=",1)
                need(key in ("LoadState","ActiveState","MainPID") and key not in fields,"WARM_PROTECTED_STATE_STOP");fields[key]=value
            need(set(fields)=={"LoadState","ActiveState","MainPID"} and fields["MainPID"].isdigit(),"WARM_PROTECTED_STATE_STOP")
            snapshot["units"][name]=fields
        need(any(snapshot["units"][name]["ActiveState"]=="active" for name in ("ssh.service","sshd.service")),"WARM_SSH_NOT_ACTIVE")
        return snapshot

    def protected_unchanged(self, before):
        after=self.protected()
        if before["boot"]==after["boot"]:
            need(after==before,"WARM_PROTECTED_STATE_CHANGED")
        else:
            need({n:(v["LoadState"],v["ActiveState"]) for n,v in after["units"].items()}==
                 {n:(v["LoadState"],v["ActiveState"]) for n,v in before["units"].items()},"WARM_PROTECTED_STATE_CHANGED")

    def launchers(self):
        # Hash-only, bounded comparison against independently reviewed launch
        # surfaces. Never print cron bodies or interpret their commands.
        roots=[Path(p) for p in ("/etc/crontab","/etc/cron.d","/etc/cron.hourly","/etc/cron.daily","/etc/cron.weekly","/etc/cron.monthly",
            "/var/spool/cron/atjobs","/var/spool/at/jobs")]
        roots.extend(Path("/var/spool/cron/crontabs")/user for user in sorted(USERS))
        result={};total=0
        for root in roots:
            if not root.exists():
                need(not root.is_symlink(),"WARM_LAUNCHER_UNKNOWN_STOP");result[str(root)]="ABSENT";continue
            need(not root.is_symlink(),"WARM_LAUNCHER_UNKNOWN_STOP")
            paths=sorted(root.iterdir()) if root.is_dir() else [root]
            need(len(paths)<=2048,"WARM_LAUNCHER_BOUND_STOP")
            for path in paths:
                s=path.lstat();need(stat.S_ISREG(s.st_mode) and s.st_size<=1048576,"WARM_LAUNCHER_UNKNOWN_STOP")
                total+=s.st_size;need(total<=16*1024**2,"WARM_LAUNCHER_BOUND_STOP")
                result[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest()
        return C.G.sha(result)

    def post_deny(self, users):
        for uid in sorted(users.values()):
            for binary in ("/usr/sbin/iptables", "/usr/sbin/ip6tables"):
                args = [binary, "-w", "5", "-C", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-m", "comment", "--comment", "FLOP_R1154", "-j", "REJECT"]
                if self.command(args, allowed=(0,1)).returncode:
                    args[3:5] = ["-I", "OUTPUT", "1"]
                    self.command(args)

    def verify_deny(self, users):
        for uid in users.values():
            for binary in ("/usr/sbin/iptables", "/usr/sbin/ip6tables"):
                self.command([binary, "-w", "5", "-C", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-m", "comment", "--comment", "FLOP_R1154", "-j", "REJECT"])

    def stop(self, name):
        need(name not in PROTECTED and J.NAME.fullmatch(name), "WARM_PROTECTED_UNIT_STOP")
        if "@." not in name: self.command(["/usr/bin/systemctl", "stop", "--", name])

    def quiet(self, scope):
        self.identity(scope); self.verify_deny(scope["users"])
        need(self.launchers()==scope["launcher_sha"],"WARM_LAUNCHER_DRIFT_STOP")
        for name in scope["units"]:
            if "@." not in name:
                r = self.command(["/usr/bin/systemctl", "is-active", "--", name], allowed=(0,3,4))
                need(r.returncode in (3,4), "WARM_UNIT_STILL_ACTIVE")
        for pid in Path("/proc").iterdir():
            if not pid.name.isdigit(): continue
            try:
                with (pid/"status").open("rb") as f: value=f.read(65537)
                need(len(value)<=65536,"WARM_PROCESS_BOUND_STOP")
                match=re.search(rb"^Uid:\s+(\d+)",value,re.M)
                need(match is not None,"WARM_PROCESS_UNKNOWN_STOP")
                need(int(match[1]) not in scope["users"].values(),"WARM_PROCESS_STILL_ALIVE")
            except FileNotFoundError: raise Stop("WARM_PROCESS_RACE_STOP") from None
        state = J.B.kernel_observation([Path(x) for x in C.ROOTS])
        # The authenticated controller may map its Python extension libraries
        # PRIVATE/COW. They cannot write source files; shared or other-process
        # writable mappings still stop. Never subtract an unknown/deleted map.
        own_private=0
        with Path("/proc/self/maps").open("rb") as f: maps=f.read(1024**2+1)
        need(len(maps)<=1024**2,"WARM_PROCESS_BOUND_STOP")
        for line in maps.decode("utf8","strict").splitlines():
            cols=line.split(None,5)
            if len(cols)==6 and "w" in cols[1] and cols[1].endswith("p") and any(cols[5].startswith(root+"/") for root in C.ROOTS):
                path=Path(cols[5]); info=path.stat()
                major,minor=cols[3].split(":")
                need(info.st_ino==int(cols[4]) and info.st_dev==os.makedev(int(major,16),int(minor,16)),"WARM_PROCESS_UNKNOWN_STOP")
                own_private+=1
        need(state["writable_mappings"]==own_private and all(state[k] == 0 for k in
            ("writable_fds", "directory_fds", "unknown_or_raced", "external_hardlinks")), "WARM_OUTSIDE_WRITER_STOP")


def private_dir(path):
    path = Path(path)
    for parent in (path, *path.parents): need(not parent.is_symlink(), "WARM_CUSTODY_STOP")
    if not path.exists(): path.mkdir(mode=0o700)
    return C.R.T.private_dir(path)


def exclusive(path, data):
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,"wb") as out: out.write(data); out.flush(); os.fsync(out.fileno())
    fd = os.open(path.parent, os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


class Controller:
    def __init__(self, authority, driver=None): self.authority=authority; self.driver=driver or Linux()

    def hold(self, scope, *, now):
        binding=validate_scope(self.authority,scope,now=now)
        self.driver.identity(scope)
        need(self.driver.launchers()==scope["launcher_sha"],"WARM_LAUNCHER_DRIFT_STOP")
        need(self.driver.discovered() == set(scope["units"]), "WARM_SCOPE_DRIFT_STOP")
        need(all(self.driver.unit(n) == row for n,row in scope["units"].items()),"WARM_UNIT_DRIFT_STOP")
        protected=self.driver.protected()
        validate_scope(self.authority,scope,now=int(time.time()))
        need(not WORK.exists() and not WORK.is_symlink() and not (UNITS/GUARD).exists() and not (UNITS/GUARD).is_symlink(),"WARM_ATTEMPT_ALREADY_EXISTS")
        # Persist exact intent BEFORE masks/firewall/stop. Never auto-resume.
        root=private_dir(WORK); records=private_dir(root/"records"); saved=private_dir(root/"saved")
        exclusive(root/"scope.json", C.G.canonical(scope))
        exclusive(root/"authority.sha", self.authority.pin.encode())
        journal=J.UndoJournal(records)
        initial=[]
        for name in sorted(scope["units"]):
            path=UNITS/name
            initial.append(dict(name=name,present=path.exists() or path.is_symlink(),
                sha=hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and not path.is_symlink() else None,
                target=os.readlink(path) if path.is_symlink() else None))
        journal.save(dict(phase="APPLYING_NO_AUTO_RETRY",binding=binding,units=initial,protected=protected))
        try:
            unit=boot_unit(scope["users"].values(),scope["units"]); exclusive(UNITS/GUARD,unit)
            wants=UNITS/"sysinit.target.wants"
            need(wants.is_dir() and not wants.is_symlink(),"WARM_BOOT_PATH_STOP")
            os.symlink("../"+GUARD,wants/GUARD)
            sync(wants)
            self.driver.post_deny(scope["users"])
            for row in initial:
                path=UNITS/row["name"]
                if row["present"]: os.rename(path,saved/row["name"])
                os.symlink("/dev/null",path)
                sync(saved); sync(UNITS)
            self.driver.command(["/usr/bin/systemctl","daemon-reload"])
            order=sorted(scope["units"],key=lambda n:(not n.endswith((".timer",".socket",".path")),n))
            for name in order: self.driver.stop(name)
            self.driver.quiet(scope)
            self.driver.protected_unchanged(protected)
            journal.save(dict(phase="HELD",binding=binding,units=initial,protected=protected))
        except Exception:
            journal.save(dict(phase="INCOMPLETE_HOLD_REVIEW_REQUIRED",binding=binding,units=initial,protected=protected))
            raise Stop("WARM_HOLD_INCOMPLETE_NO_AUTO_ROLLBACK") from None
        return {**result("HELD_VM_AND_SSH_UNCHANGED"),"scope_sha":C.G.sha(scope),"journal_sha":journal.previous}

    def verify(self):
        journal=J.UndoJournal(WORK/"records"); scope=C.decode((WORK/"scope.json").read_bytes())
        need(scope["tool_blob"]==tool_blob(),"WARM_TOOL_PIN_STOP")
        need((WORK/"authority.sha").read_bytes() == self.authority.pin.encode(),"WARM_ENROLLMENT_STOP")
        need(journal.latest and journal.latest["phase"] == "HELD","WARM_NOT_HELD")
        self.driver.identity(scope)
        need((UNITS/GUARD).read_bytes() == boot_unit(scope["users"].values(),scope["units"]) and
             os.readlink(UNITS/"sysinit.target.wants"/GUARD) == "../"+GUARD,"WARM_BOOT_DENY_LOST")
        for name in scope["units"]:
            need((UNITS/name).is_symlink() and os.readlink(UNITS/name)=="/dev/null","WARM_MASK_LOST")
        self.driver.quiet(scope)
        self.driver.protected_unchanged(journal.latest["protected"])
        return {**result("HELD_VM_AND_SSH_UNCHANGED"),"scope_sha":C.G.sha(scope),"journal_sha":journal.previous}

    def status(self):
        journal=J.UndoJournal(WORK/"records");scope=C.decode((WORK/"scope.json").read_bytes())
        need((WORK/"authority.sha").read_bytes()==self.authority.pin.encode() and scope["tool_blob"]==tool_blob(),"WARM_ENROLLMENT_STOP")
        self.driver.identity(scope)
        # A journal observation alone is never a healthy/fenced verdict.
        return {**result("SOURCE_HOLD_STATUS_REQUIRES_VERIFY"),"scope_sha":C.G.sha(scope),"journal_sha":journal.previous}

    def rollback(self, owner, witness, *, now):
        journal=J.UndoJournal(WORK/"records"); scope=C.decode((WORK/"scope.json").read_bytes())
        need(scope["tool_blob"]==tool_blob(),"WARM_TOOL_PIN_STOP")
        need((WORK/"authority.sha").read_bytes() == self.authority.pin.encode(),"WARM_ENROLLMENT_STOP")
        need(journal.latest is not None,"WARM_ROLLBACK_UNKNOWN")
        self.driver.identity(scope)
        binding=dict(journal_sha=journal.previous,scope_sha=C.G.sha(scope),aws_publishers_disabled=True,
                     permanent_old_post_deny_retained=True,auto_restart=False)
        for packet,role in ((owner,"owner"),(witness,"independent")):
            need(self.authority.verify(packet,"rollback",role,now)==binding,"WARM_ROLLBACK_APPROVAL_STOP")
        rows=journal.latest["units"]
        protected=journal.latest["protected"]
        journal.save(dict(phase="ROLLBACK_ATTEMPTING",binding=journal.latest["binding"],units=rows,protected=protected))
        try:
            for row in rows:
                path=UNITS/row["name"]; saved=WORK/"saved"/row["name"]
                if saved.exists() or saved.is_symlink():
                    need(path.is_symlink() and os.readlink(path)=="/dev/null","WARM_ROLLBACK_DRIFT")
                    need((row["target"] is not None and saved.is_symlink() and os.readlink(saved)==row["target"]) or
                         (row["sha"] is not None and not saved.is_symlink() and hashlib.sha256(saved.read_bytes()).hexdigest()==row["sha"]),"WARM_ROLLBACK_DRIFT")
                    path.unlink(); os.rename(saved,path)
                elif row["present"]:
                    # An incomplete apply may not have moved this original;
                    # missing backup AND missing/drifted original is not undo.
                    need((row["target"] is not None and path.is_symlink() and os.readlink(path)==row["target"]) or
                         (row["sha"] is not None and path.is_file() and not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest()==row["sha"]),"WARM_ROLLBACK_DRIFT")
                elif path.exists() or path.is_symlink():
                    need(path.is_symlink() and os.readlink(path)=="/dev/null","WARM_ROLLBACK_DRIFT"); path.unlink()
            sync(UNITS); sync(WORK/"saved")
            self.driver.command(["/usr/bin/systemctl","daemon-reload"])
            self.driver.verify_deny(scope["users"])
            self.driver.protected_unchanged(protected)
            journal.save(dict(phase="RESTORED_DISARMED_POST_DENY_RETAINED",binding=journal.latest["binding"],units=rows,protected=protected))
        except Exception:
            journal.save(dict(phase="ROLLBACK_FAILED_REVIEW_REQUIRED",binding=journal.latest["binding"],units=rows,protected=protected))
            raise Stop("WARM_ROLLBACK_FAILED") from None
        return {**result("RESTORED_DISARMED_POST_DENY_RETAINED"),"scope_sha":C.G.sha(scope),"journal_sha":journal.previous}


def result(code):
    return dict(phase="R1154",code=code,vm_stop="NOT_IMPLEMENTED",source_archive="NO_GO",
                aws_publisher="DISARMED",cutover="NO_GO",oci_retirement="STRICT_NO_GO")


def capture_checkpointed(controller, owner, witness, destination_policy, recovery, output, *, clock=time.time,
                         sqlite_validator=None, metadata=None):
    """Full R1089 encryption library adapter; never an old-gate GO forgery.

    Only after real APP HOLD. Non-empty WAL requires a separately reviewed
    RO-validation worker and is refused here. A clean DB need not have SHM.
    Windows streaming owner coordinator is NOT wired to this library yet.
    """
    held=controller.verify();authority=controller.authority
    binding=authority.verify(owner,"preserve","owner",int(clock()))
    shape(binding,"scope_sha hold_journal_sha roots_sha inventory_sha ledger_sha epoch source_cap_bytes destination_policy_sha recovery_confirmed cost_cap")
    need(authority.verify(witness,"preserve","independent",int(clock()))==binding and
         binding["scope_sha"]==held["scope_sha"] and binding["hold_journal_sha"]==held["journal_sha"] and
         binding["roots_sha"]==C.G.sha(C.ROOTS) and binding["recovery_confirmed"] is True and binding["cost_cap"]=="ZERO_NEW_BILLING","WARM_CAPTURE_APPROVAL_STOP")
    C.digest(binding["epoch"]);C.integer(binding["source_cap_bytes"],1,C.R.T.C.MAX_SOURCE_BYTES)
    installed=authority.verify(destination_policy,"permanent-no-replay","destination",int(clock()))
    need(installed==dict(policy_sha=binding["destination_policy_sha"],inventory_sha=binding["inventory_sha"],
        ledger_sha=binding["ledger_sha"],all_five_routes=True,survives_reboot=True,unknown_remains_unknown=True),"WARM_AWS_NO_REPLAY_NOT_INSTALLED")
    need(type(recovery) is bytes and 32<=len(recovery)<=1024,"WARM_ARCHIVE_RECOVERY_STOP")
    records=private_dir(WORK/"archive-records");journal=J.UndoJournal(records)
    need(journal.latest is None,"WARM_ARCHIVE_ALREADY_ATTEMPTED")
    roots=dict(zip(("app","state"),(Path(path) for path in C.ROOTS)))
    last=[None]
    def guard(force=False):
        now=int(clock())
        # Scope grant is NOT silently renewed by a local bool.
        need(authority.verify(owner,"preserve","owner",now)==binding and
             authority.verify(witness,"preserve","independent",now)==binding,"WARM_CAPTURE_LEASE_STOP")
        if force or last[0] is None or now-last[0]>=5:
            checked=controller.verify();need(checked["journal_sha"]==binding["hold_journal_sha"],"WARM_HOLD_CHANGED")
            last[0]=now
    def census():
        guard(True)
        return C.R.T._census_roots(roots,C.G.SOURCE_HEAD,epoch="FROZEN:"+binding["epoch"])
    roots,manifest,ids=census()
    state_hashes={r["path"][6:]:r["sha256"] for r in manifest["entries"] if r["kind"]=="file" and r["path"].startswith("state/")}
    files={};total=0
    for name in state_hashes:
        if name.startswith(("signer/","autopilot/","close1/")) or name in ("verified-did.json","nonces.json","activities.jsonl"):
            path=roots["state"]/name;size=path.stat().st_size;total+=size
            need(size<=16*1024**2 and total<=64*1024**2,"WARM_LEDGER_MEMORY_BOUND_STOP")
            files[name]=b"".join(C.R.T.read_blocks(path,ids["state/"+name]))
    need(P.ledger_digest(files,state_hashes)==binding["ledger_sha"] and
         C.G.sha(P.original_attempts(files,authority.profile["source_did"]))==binding["inventory_sha"],"WARM_EXACT_ATTEMPTS_STOP")
    need(C.decode(files["verified-did.json"])["did"]==authority.profile["source_did"],"WARM_CAPTURE_DID_STOP")
    cursors=sqlite_validator(roots,manifest,ids,guard) if sqlite_validator is not None else []
    for name in (() if sqlite_validator is not None else sorted(C.G.DATABASES)):
        candidates=[row for row in manifest["entries"] if row["path"].rsplit("/",1)[-1]==name and row["kind"]=="file"]
        need(len(candidates)==1,"WARM_TWO_SQLITE_STOP")
        db=C.R.T.resolve_source(roots,candidates[0]["path"])
        for suffix in ("-wal","-journal"):
            side=Path(str(db)+suffix)
            need(not side.exists() or side.is_file() and not side.is_symlink() and side.stat().st_size==0,"WARM_NONEMPTY_WAL_REQUIRES_RO_WORKER")
        try:
            con=sqlite3.connect(db.as_uri()+"?mode=ro&immutable=1",uri=True)
            try:
                con.execute("PRAGMA trusted_schema=OFF");con.execute("PRAGMA query_only=ON")
                need(con.execute("PRAGMA integrity_check").fetchall()==[("ok",)],"WARM_SQLITE_INTEGRITY_STOP")
                cursors.append(con.execute("SELECT count(*),coalesce(max(seq),0) FROM messages").fetchone())
            finally:con.close()
        except sqlite3.Error:raise Stop("WARM_SQLITE_INTEGRITY_STOP") from None
    need(sum(row["size"] for row in manifest["entries"])<=binding["source_cap_bytes"],"WARM_CAPTURE_QUOTA_STOP")
    need(census()[1]==manifest,"WARM_CAPTURE_CHANGED")
    journal.save(dict(phase="ARCHIVE_ATTEMPTING",binding_sha=C.G.sha(binding)))
    class CheckedOutput:
        def isatty(self):return False
        def write(self,block):guard();return output.write(block)
    try:
        if metadata is not None:
            metadata(dict(schema_version=1,epoch=manifest["epoch"],manifest_sha256=C.G.sha(manifest),
                files=len(manifest["entries"]),bytes=sum(r["size"] for r in manifest["entries"]),
                symlinks=sum(r["kind"]=="symlink" for r in manifest["entries"]),
                sqlite_cursors=[list(x) for x in cursors],ledger_sha256=C.R.state_ledger_digest(manifest)))
        C.R.W.seal_manifest_to_stream(roots,manifest,ids,recovery,CheckedOutput(),recensus=census)
        guard(True);output.flush()
    except Exception:
        journal.save(dict(phase="ARCHIVE_UNKNOWN_NO_RETRY",binding_sha=C.G.sha(binding)))
        raise Stop("WARM_ARCHIVE_UNKNOWN_NO_RETRY") from None
    journal.save(dict(phase="ENCRYPTED_OFFHOST_RESTORE_UNPROVEN",binding_sha=C.G.sha(binding),manifest_sha=C.G.sha(manifest)))
    return {**result("ENCRYPTED_OFFHOST_RESTORE_UNPROVEN"),"manifest_sha":C.G.sha(manifest)}


def peer(request):
    shape(request,"enrollment enrollment_sha operation scope owner witness")
    authority=Authority(request["enrollment"],request["enrollment_sha"])
    controller=Controller(authority); operation=request["operation"]
    need(operation in ("hold","verify","rollback","status"),"WARM_OPERATION_STOP")
    if operation=="hold": return controller.hold(request["scope"],now=int(time.time()))
    if operation=="rollback": return controller.rollback(request["owner"],request["witness"],now=int(time.time()))
    if operation=="status": return controller.status()
    return controller.verify()


if __name__=="__main__":
    print(C.G.canonical(result("OWNER_SIGNED_SSH_ENTRYPOINT_REQUIRED")).decode())
    raise SystemExit(42)
