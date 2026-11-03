"""Signed root-only identities, private signer setup and derived Resident stage.

No automatic resume, unseal, POST or old writer start. No resource creation.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import time

sp=importlib.util.spec_from_file_location("r1156_setup_runtime",Path(__file__).with_name("r1156_runtime.py"))
M=importlib.util.module_from_spec(sp);sys.modules[sp.name]=M;sp.loader.exec_module(M)
S=M.S;N=M.N;H=M.H;C=M.C
A=M.load("r1156_old_activation","r1155_activation.py")
NAMES=("technocore-signer","flop-r1155-publisher","flop-r1156-resident")
FILES={"verified-did.json","observer/observer-state.json","observer/observer-config.json","observer/resident-state.json",
       "observer/resident-config.json","observer/resident-control.json","autopilot/autopilot-outbox.json"}


def dual(authority,document,kind,now):
    data={k:v for k,v in document.items() if k not in ("owner","witness")}
    for key,role in (("owner","owner"),("witness","independent")):
        H.need(authority.trust.verify(document[key],"r1156-"+kind,role,now,age=900)==dict(document_sha=C.G.sha(data),no_start=True,zero_cost=True),"SETUP_APPROVAL_STOP")


def promote_databases(hashes,restored,target,uid,gid,*,journal):
    """Move, NEVER duplicate DB/WAL/SHM, after full restore admission.

    Original OCI + authenticated Windows archive remain unchanged. K137 inert
    landing is intentionally promoted; partial move is journaled NO_GO, never
    silently repaired or started. Both locations must share one filesystem.
    """
    allowed={"observer/"+name+suffix for name in C.G.DATABASES for suffix in ("","-wal","-shm")}
    H.need(type(hashes) is dict and set(hashes)<=allowed and {"observer/"+name for name in C.G.DATABASES}<=set(hashes),"SETUP_DB_MAP_STOP")
    moves=[]
    for name in sorted(allowed):
        src=restored/"state"/name;dst=target/name
        if src.exists():H.need(name in hashes,"SETUP_DB_SIDECAR_MISSING")
        if name not in hashes:continue
        C.digest(hashes[name]);info=src.lstat()
        H.need(stat.S_ISREG(info.st_mode) and not src.is_symlink() and info.st_nlink==1 and
            not dst.exists() and not dst.is_symlink() and info.st_dev==dst.parent.stat().st_dev,"SETUP_DB_MOVE_STOP")
        sha=hashlib.sha256()
        with src.open("rb") as stream:
            while block:=stream.read(1024**2):sha.update(block)
        H.need(sha.hexdigest()==hashes[name],"SETUP_DB_HASH_STOP")
        moves.append(dict(name=name,sha=hashes[name]))
    journal(dict(phase="DB_PROMOTION_ATTEMPTING_NO_AUTO_RETRY",moves=moves))
    try:
        for row in moves:
            src=restored/"state"/row["name"];dst=target/row["name"]
            os.rename(src,dst);os.chown(dst,uid,gid);os.chmod(dst,0o600)
            H.sync(dst.parent);H.sync(src.parent)
    except Exception:
        journal(dict(phase="DB_PROMOTION_UNKNOWN_NO_AUTO_RETRY",moves=moves));raise
    journal(dict(phase="DB_PROMOTED_ORIGINAL_BACKUP_RETAINED",moves=moves))


def owned_directory(path,uid,gid,mode):
    for parent in path.parents:H.need(not parent.is_symlink(),"SETUP_PARENT_LINK_STOP")
    if path.exists():
        info=path.lstat();H.need(stat.S_ISDIR(info.st_mode) and not path.is_symlink() and
            info.st_uid==uid and info.st_gid==gid and stat.S_IMODE(info.st_mode)==mode,"SETUP_EXISTING_DIRECTORY_STOP")
        return
    # Created ROOT-private first; only after validation is custody assigned.
    path.mkdir(mode=0o700);os.chown(path,uid,gid);os.chmod(path,mode);H.sync(path.parent)


def identities(request):
    A.current_host();H.shape(request,"enrollment enrollment_sha boot_sha uids recipient owner witness")
    a=H.Authority(request["enrollment"],request["enrollment_sha"]);dual(a,request,"identities",int(time.time()))
    H.need(request["boot_sha"]==hashlib.sha256(Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()).hexdigest(),"SETUP_BOOT_STOP")
    H.need(type(request["uids"]) is dict and set(request["uids"])==set(NAMES),"SETUP_USERS_STOP")
    values=list(request["uids"].values());H.need(len(set(values))==3,"SETUP_SHARED_UID_STOP")
    for uid in values:C.integer(uid,1001,65533)
    import pwd,grp
    driver=H.Linux()
    for name,uid in request["uids"].items():
        users=[p for p in pwd.getpwall() if p.pw_name==name or p.pw_uid==uid]
        groups=[g for g in grp.getgrall() if g.gr_name==name or g.gr_gid==uid]
        H.need(not groups or len(groups)==1 and groups[0].gr_name==name and groups[0].gr_gid==uid,"SETUP_SHARED_GID_STOP")
        H.need(not users or len(users)==1 and users[0].pw_name==name and users[0].pw_uid==uid and
            users[0].pw_gid==uid and users[0].pw_shell=="/usr/sbin/nologin","SETUP_EXISTING_USER_STOP")
        if not groups:driver.command(["/usr/sbin/groupadd","--system","--gid",str(uid),name])
        if not users:driver.command(["/usr/sbin/useradd","--system","--no-create-home","--shell","/usr/sbin/nologin","--uid",str(uid),"--gid",name,name])
        H.need(set(os.getgrouplist(name,uid))=={uid},"SETUP_SUPPLEMENTARY_GROUP_STOP")
    gid=request["uids"]["flop-r1155-publisher"]
    owned_directory(S.STORE,request["uids"]["technocore-signer"],gid,0o700)
    owned_directory(M.P.STATE,gid,gid,0o700)
    admission=Path("/etc/flop-r1155-admission")
    if admission.exists():
        info=admission.lstat()
        if stat.S_ISDIR(info.st_mode) and info.st_uid==0 and info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700 and not admission.is_symlink():
            os.chown(admission,0,gid);os.chmod(admission,0o750)
    owned_directory(admission,0,gid,0o750)
    H.shape(request["recipient"],"enrollment enrollment_sha run_id owner witness")
    H.need(request["recipient"]["enrollment"]==request["enrollment"] and request["recipient"]["enrollment_sha"]==a.pin,"SETUP_RECIPIENT_AUTHORITY_STOP")
    path=admission/"recipient.json"
    if path.exists():H.need(S.secured(path)==request["recipient"],"SETUP_RECIPIENT_ALREADY_EXISTS")
    else:
        H.exclusive(path,C.G.canonical(request["recipient"]));os.chown(path,0,gid);os.chmod(path,0o640)
    return dict(code="ISOLATED_IDENTITIES_PREPARED_NO_START")


def stage(request):
    A.current_host();H.shape(request,"config scope run_id source_packet capability initial owner witness")
    config=request["config"];a=S.activation(config,int(time.time()));dual(a,request,"stage",int(time.time()))
    cap=request["capability"];g=cap["generation"];anchor=cap["anchor"]
    N.anchor_ok(a,anchor)
    H.need(anchor["runtime_sha"]==C.G.sha(config) and anchor["generation_sha"]==C.G.sha(g) and
        anchor["epoch"]==config["baseline"]["epoch"],"SETUP_CAPABILITY_STOP")
    for key,role in (("owner","owner"),("witness","independent")):
        H.need(a.trust.verify(cap[key],"r1156-autonomy",role,int(time.time()),age=900)==dict(anchor_sha=C.G.sha(anchor),generation_sha=C.G.sha(g)),"SETUP_CAPABILITY_STOP")
    H.need(type(g["source_hashes"]) is dict and set(g["source_hashes"])<=FILES and
        FILES-{"observer/resident-control.json"}<=set(g["source_hashes"]),"SETUP_SOURCE_FILES_STOP")
    restored=C.R.D.ROOT/request["run_id"]
    H.need(C.G.re.fullmatch(r"[a-f0-9]{32}",request["run_id"]),"SETUP_RUN_STOP")
    total=0
    for name,digest in g["source_hashes"].items():
        path=restored/"state"/name
        H.need(path.is_file() and not path.is_symlink() and path.stat().st_size<=64*1024**2,"SETUP_ACTIVE_STATE_BOUND_STOP")
        for parent in path.parents:H.need(not parent.is_symlink(),"SETUP_SOURCE_LINK_STOP")
        total+=path.stat().st_size;C.digest(digest)
    H.need(total<=64*1024**2,"SETUP_ACTIVE_STATE_BOUND_STOP")
    # Measured staging budget, before starting ANY job. Existing full restore
    # stays inert; only bounded selected JSON is copied, never SQLite again.
    A.fresh_resources(total)
    available=int(next(x for x in Path("/proc/meminfo").read_text().splitlines() if x.startswith("MemAvailable:")).split()[1])
    H.need(available>=1024*1024,"SETUP_1GIB_HEADROOM_STOP")
    import pwd
    resident=pwd.getpwnam("flop-r1156-resident");pub=pwd.getpwnam("flop-r1155-publisher")
    H.need(resident.pw_uid==g["resident_uid"] and resident.pw_uid not in (config["signer_uid"],config["publisher_uid"],1000,0),"SETUP_RESIDENT_UID_STOP")
    H.need(not N.ROOT.exists() and not M.STATE.parent.exists(),"SETUP_ALREADY_STAGED_STOP")
    # Original installer re-verifies the COMPLETE restored state and source
    # HOLD and installs original permanent five-route deny. Never fabricate GO.
    A.prepare(config,request["scope"],restored,request["source_packet"])
    owned_directory(N.ROOT,0,pub.pw_gid,0o750)
    H.exclusive(N.ROOT/"capability.json",C.G.canonical(cap));os.chown(N.ROOT/"capability.json",0,pub.pw_gid);os.chmod(N.ROOT/"capability.json",0o640)
    N.install_runtime(config,request["initial"])
    owned_directory(M.STATE.parent,resident.pw_uid,pub.pw_gid,0o2750)
    owned_directory(M.STATE,resident.pw_uid,pub.pw_gid,0o2750)
    for folder in ("observer","autopilot","signer","capture"):
        owned_directory(M.STATE/folder,resident.pw_uid,pub.pw_gid,0o2750)
    owned_directory(M.ACKS,pub.pw_uid,pub.pw_gid,0o750)
    for name,digest in g["source_hashes"].items():
        raw=(restored/"state"/name).read_bytes();H.need(hashlib.sha256(raw).hexdigest()==digest,"SETUP_SOURCE_HASH_STOP")
        H.exclusive(M.STATE/name,raw);os.chown(M.STATE/name,resident.pw_uid,pub.pw_gid);os.chmod(M.STATE/name,0o640)
    observed=C.decode((M.STATE/"observer/observer-state.json").read_bytes())
    local=C.decode((M.STATE/"observer/resident-state.json").read_bytes())
    auto=C.decode((M.STATE/"autopilot/autopilot-outbox.json").read_bytes())
    H.need(observed["cursors"]==g["frozen_cursors"] and observed.get("room_generations",{})==g["room_generations"] and
        sorted(local["candidates"])==sorted(g["old_candidates"]) and bool(auto.get("first_contact_enabled"))==g["first_contact_enabled"],"SETUP_GENERATION_SOURCE_STOP")
    promote_databases(g["database_hashes"],restored,M.STATE,resident.pw_uid,pub.pw_gid,
        journal=lambda value:C.R.checkpoint(N.ROOT,"db-promotion.json",value))
    # Active projection label/quarantine does not rewrite preserved originals.
    for identity,item in auto["outbox"].items():
        if identity in config["baseline"]["old_ids"][S.ROUTES[0]] and item.get("status","queued") in ("queued","posted","prepared","ambiguous"):
            item["status"]="quarantined"
    C.R.checkpoint(M.STATE/"autopilot","autopilot-outbox.json",auto)
    os.chown(M.STATE/"autopilot/autopilot-outbox.json",resident.pw_uid,pub.pw_gid);os.chmod(M.STATE/"autopilot/autopilot-outbox.json",0o640)
    # Replace ONLY byte-exact units installed by A.prepare in this same call.
    for role in ("signer","publisher","guard-monitor"):
        target=A.UNITS/("flop-r1155-"+role+".service")
        H.need(target.read_bytes()==(H.ROOT/"packaging/oracle"/target.name).read_bytes(),"SETUP_UNIT_DRIFT_STOP")
        source=H.ROOT/"packaging/oracle"/("flop-r1156-"+role+".service")
        C.R.checkpoint(A.CONF,"unit-audit-"+role+".json",dict(previous_sha=hashlib.sha256(target.read_bytes()).hexdigest()))
        temporary=A.UNITS/(target.name+".r1156")
        H.exclusive(temporary,source.read_bytes());os.chmod(temporary,0o644);os.replace(temporary,target)
    for role in ("resident","capture"):
        name="flop-r1156-"+role+".service";H.exclusive(A.UNITS/name,(H.ROOT/"packaging/oracle"/name).read_bytes());os.chmod(A.UNITS/name,0o644)
    H.Linux().command(["/usr/bin/systemctl","daemon-reload"])
    H.exclusive(N.ROOT/"STAGED",C.G.canonical(dict(code="STAGED_DISABLED",source_manifest=anchor["manifest_sha"])))
    return dict(code="RESIDENT_PARITY_STAGED_DISABLED",cutover="NO_GO")


def main():
    try:
        H.need(sys.argv[1:] in (["--identities"],["--stage"],["--start-reader"],["--start-signer"],["--start-publisher"]),"SETUP_ARGUMENT_STOP")
        A.current_host()
        if sys.argv[1:]==["--identities"]:result=identities(S.secured(Path("/etc/flop-r1155-admission/identities.json")))
        elif sys.argv[1:]==["--stage"]:result=stage(S.secured(Path("/etc/flop-r1155-admission/parity.json")))
        else:
            config=S.secured(S.CONFIG);N.runtime_admit(config,int(time.time()));A.fresh_resources(0)
            H.need((N.ROOT/"STAGED").is_file(),"SETUP_NOT_STAGED")
            actor=sys.argv[1];driver=H.Linux()
            marker=N.ROOT/(actor[2:]+"-attempt.json");H.exclusive(marker,C.G.canonical(dict(config_sha=C.G.sha(config),no_auto_retry=True)))
            if actor=="--start-reader":
                driver.command(["/usr/bin/systemctl","start","flop-r1156-capture.service"])
                driver.command(["/usr/bin/systemctl","start","flop-r1156-resident.service"])
            else:
                driver.command(["/usr/bin/systemctl","start","flop-r1155-guard-monitor.service"])
                if actor=="--start-publisher":
                    info=S.SOCKET.lstat();H.need(stat.S_ISSOCK(info.st_mode) and info.st_uid==config["signer_uid"],"SETUP_SIGNER_NOT_UNLOCKED")
                driver.command(["/usr/bin/systemctl","start","flop-r1155-"+("signer" if actor=="--start-signer" else "publisher")+".service"])
            result=dict(code="PARITY_START_REQUESTED_VERIFY_REQUIRED",cutover="NO_GO")
        print(C.G.canonical(result).decode());return 0
    except Exception:
        print('{"code":"PARITY_SETUP_STOP","cutover":"NO_GO"}');return 42


if __name__=="__main__":raise SystemExit(main())
