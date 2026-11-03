"""Root owner-reviewed K137 install/activation. Never stops original Oracle.

Does NOT start restored legacy units. New signer has AF_UNIX only; publisher
has no key/Vault privilege and only NEW dual-approved fixed-template replies.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import time

sp=importlib.util.spec_from_file_location("r1155_activation_signer",Path(__file__).with_name("r1155_signer.py"))
S=importlib.util.module_from_spec(sp);sys.modules[sp.name]=S;sp.loader.exec_module(S)
H=S.H;C=S.C
CONF=Path("/etc/flop-r1155")
LIB=Path("/usr/local/libexec/flop-r1155")
UNITS=Path("/etc/systemd/system")
GUARD="flop-r1155-old-post-deny.service"


def current_host():
    H.need(sys.platform=="linux" and os.geteuid()==0 and H.C.R.D.machine_digest()==H.B.K137,"ACTIVATION_ROOT_HOST_STOP")


def source_hold(config,packet,now):
    a=S.activation(config,now)
    value=a.trust.verify(packet,"r1155-source-held","independent",now,age=30)
    H.need(value==dict(hold_sha=config["lease"]["source_hold_sha"],all_scoped_units_masked=True,
        dual_stack_uid_deny=True,source_vm_running=True,ssh_retained=True,old_attempts_permanently_denied=True),"ACTIVATION_SOURCE_HOLD_STOP")


def fresh_resources(upper):
    import shutil
    from decimal import Decimal
    H.need(shutil.disk_usage(C.R.D.ROOT.parent).free>=20*C.R.GIB+upper+C.R.D.SQLITE_ALLOWANCE,"ACTIVATION_DISK_STOP")
    available=int(next(x for x in Path("/proc/meminfo").read_text().splitlines() if x.startswith("MemAvailable:")).split()[1])
    H.need(available>=512*1024,"ACTIVATION_MEMORY_STOP")
    for name,limit in (("cpu",5),("io",10)):
        row=Path("/proc/pressure/"+name).read_text().splitlines()[0]
        H.need(Decimal(dict(x.split("=",1) for x in row.split()[1:])["avg10"])<=limit,"ACTIVATION_PRESSURE_STOP")


def prepare(config,scope,restored,source_packet,*,runner=None):
    """Explicit owner execution only; no fetch/deploy/default auto activation.

    Missing installed private signer custody is a start blocker, not silently
    replaced by another DID or by Windows plaintext key entry.
    """
    current_host();now=int(time.time());a=S.activation(config,now);source_hold(config,source_packet,now)
    H.need(config["lease"]["boot_sha"]==hashlib.sha256(Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()).hexdigest(),"ACTIVATION_BOOT_STOP")
    restored=Path(restored)
    H.need(restored.parent==C.R.D.ROOT and C.R.re.fullmatch(r"[a-f0-9]{32}",restored.name) and not restored.is_symlink(),"ACTIVATION_RESTORE_SCOPE_STOP")
    receipt=C.decode((restored/"DISARMED-STREAM-RECEIPT.json").read_bytes())
    H.need(receipt["manifest_sha256"]==config["lease"]["restored_manifest_sha"] and
        receipt["source_epoch"]=="FROZEN:"+config["baseline"]["epoch"] and receipt["runtime_started"] is False,"ACTIVATION_RESTORE_STOP")
    H.need(scope["source"]==a.trust.context and config["baseline"]["ledger_sha"]==scope["quarantine"]["ledger_sha"] and
        config["lease"]["scope_sha"]==C.G.sha(scope) and
        C.G.sha(config["baseline"]["inventory"])==scope["quarantine"]["inventory_sha"],"ACTIVATION_LEDGER_STOP")
    # Re-hash the actual restored state, not a caller's self-attested baseline.
    hashes={};files={};total=0
    root=restored/"state"
    for path in sorted(root.rglob("*")):
        H.need(not path.is_symlink(),"ACTIVATION_STATE_LINK_STOP")
        if not path.is_file():continue
        name=path.relative_to(root).as_posix();sha=hashlib.sha256()
        with path.open("rb") as f:
            while block:=f.read(1024**2):sha.update(block)
        hashes[name]=sha.hexdigest()
        if name.startswith(("signer/","autopilot/","close1/")) or name in ("nonces.json","activities.jsonl","verified-did.json"):
            total+=path.stat().st_size;H.need(path.stat().st_size<=16*1024**2 and total<=64*1024**2,"ACTIVATION_LEDGER_BOUND_STOP")
            files[name]=path.read_bytes()
    H.need(S.baseline(files,hashes,a.profile["source_did"],config["baseline"]["epoch"])==config["baseline"],"ACTIVATION_ACTUAL_LEDGER_STOP")
    # The complete inert archive is ALREADY restored; do not reserve a second
    # full copy. New bounded projection space is measured by the R1156 caller.
    fresh_resources(0)
    driver=H.Linux() if runner is None else H.Linux(runner)
    import pwd
    # Never reuse an admin/shared/TradeBot UID or alter existing supplementary
    # groups. Creation/enrollment is a separate root owner provisioning step.
    signer=pwd.getpwnam("technocore-signer");publisher=pwd.getpwnam("flop-r1155-publisher")
    H.need(signer.pw_uid==config["signer_uid"] and publisher.pw_uid==config["publisher_uid"] and
        signer.pw_uid not in (0,1000) and publisher.pw_uid not in scope["users"].values(),"ACTIVATION_USER_STOP")
    oldusers={name:pwd.getpwnam(name).pw_uid for name in scope["users"]}
    H.need(publisher.pw_uid not in oldusers.values() and all(sum(p.pw_uid==uid for p in pwd.getpwall())==1
        for uid in (*oldusers.values(),publisher.pw_uid)),"ACTIVATION_SHARED_UID_STOP")
    import grp
    forbidden={g.gr_gid for g in grp.getgrall() if g.gr_name in ("root","sudo","adm","technocore","ubuntu")}
    H.need(not (set(os.getgrouplist(signer.pw_name,signer.pw_gid))|set(os.getgrouplist(publisher.pw_name,publisher.pw_gid)))&forbidden,
        "ACTIVATION_PRIVILEGED_GROUP_STOP")
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():continue
        try:raw=(proc/"status").read_bytes()
        except FileNotFoundError:raise H.Stop("ACTIVATION_PROCESS_RACE_STOP") from None
        match=C.G.re.search(rb"^Uid:\s+(\d+)",raw,C.G.re.M)
        H.need(match and int(match[1]) not in oldusers.values(),"ACTIVATION_SHARED_PROCESS_STOP")
    H.need(not CONF.exists() and not LIB.exists() and not (UNITS/GUARD).exists(),"ACTIVATION_ALREADY_PREPARED")
    companion=restored.parent/(restored.name+"-custody.json")
    H.need(companion.is_file() and not companion.is_symlink() and companion.stat().st_size<=16384,"ACTIVATION_CUSTODY_MISSING")
    custody=C.decode(companion.read_bytes())
    H.need(C.G.sha(custody["envelope"])==config["lease"]["custody_sha"],"ACTIVATION_CUSTODY_STOP")
    store=S.STORE
    meta=store.lstat()
    H.need(stat.S_ISDIR(meta.st_mode) and not store.is_symlink() and meta.st_uid==signer.pw_uid and
        stat.S_IMODE(meta.st_mode)==0o700 and (store/"recipient.pem.enc").is_file(),"ACTIVATION_RECIPIENT_NOT_PREPARED")
    H.need(not (store/"custody.json").exists(),"ACTIVATION_CUSTODY_ALREADY_EXISTS")
    for name in scope["units"]:
        H.need(name not in H.PROTECTED and not (UNITS/name).exists() and not (UNITS/name).is_symlink(),"ACTIVATION_EXISTING_SERVICE_STOP")
    # Every step below is irreversible-admission journaled first; failure is
    # UNKNOWN. No auto undo or old egress release on restore/activation failure.
    CONF.mkdir(mode=0o750);os.chown(CONF,0,publisher.pw_gid)
    H.exclusive(CONF/"PREPARING",C.G.canonical(dict(baseline_sha=config["baseline_sha"],source_hold_sha=config["lease"]["source_hold_sha"])))
    LIB.mkdir(mode=0o755)
    # Only locally pin-verified PUBLIC source bundle, never restored executable
    # metadata or an arbitrary release path supplied by the caller.
    spec=importlib.util.spec_from_file_location("r1155_activation_transfer",Path(__file__).with_name("r1155_transfer.py"))
    transport=importlib.util.module_from_spec(spec);sys.modules[spec.name]=transport;spec.loader.exec_module(transport)
    for name,text in transport.bundle().items():
        path=LIB/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
        H.exclusive(path,text.encode());os.chmod(path,0o644)
    public=CONF/"runtime.json";H.exclusive(public,C.G.canonical(config));os.chown(public,0,publisher.pw_gid);os.chmod(public,0o640)
    public=CONF/"scope.json";H.exclusive(public,C.G.canonical(scope));os.chown(public,0,publisher.pw_gid);os.chmod(public,0o640)
    H.exclusive(store/"custody.json",C.G.canonical(custody));os.chown(store/"custody.json",signer.pw_uid,signer.pw_gid)
    driver.post_deny(oldusers)
    for name in scope["units"]:os.symlink("/dev/null",UNITS/name)
    H.exclusive(UNITS/GUARD,H.boot_unit(oldusers.values(),scope["units"]))
    os.symlink("../"+GUARD,UNITS/"sysinit.target.wants"/GUARD)
    for name in ("signer","publisher","guard-monitor"):
        target=UNITS/("flop-r1155-"+name+".service")
        data=(H.ROOT/"packaging/oracle"/target.name).read_bytes()
        H.need(not target.exists(),"ACTIVATION_EXISTING_SERVICE_STOP");H.exclusive(target,data);os.chmod(target,0o644)
    H.sync(UNITS);driver.command(["/usr/bin/systemctl","daemon-reload"])
    H.exclusive(CONF/"PREPARED",C.G.canonical(dict(config_sha=C.G.sha(config),cutover="NO_GO")))
    return dict(code="K137_PREPARED_DISARMED",cutover="NO_GO")


def start(config,source_packet,*,publisher=False,runner=None):
    current_host();source_hold(config,source_packet,int(time.time()))
    installed=S.secured(S.CONFIG)
    H.need(installed==config and (CONF/"PREPARED").is_file(),"ACTIVATION_PREPARED_STOP")
    fresh_resources(0)
    driver=H.Linux() if runner is None else H.Linux(runner)
    if publisher:
        meta=S.SOCKET.lstat();H.need(stat.S_ISSOCK(meta.st_mode) and meta.st_uid==config["signer_uid"] and
            stat.S_IMODE(meta.st_mode)==0o660,"ACTIVATION_SIGNER_NOT_UNLOCKED")
        H.need(driver.command(["/usr/bin/systemctl","is-active","flop-r1155-signer.service"]).stdout.strip()==b"active","ACTIVATION_SIGNER_NOT_ACTIVE")
    name="publisher" if publisher else "signer"
    marker=CONF/("STARTING-"+name)
    H.exclusive(marker,C.G.canonical(dict(config_sha=C.G.sha(config),no_auto_retry=True)))
    if not publisher:driver.command(["/usr/bin/systemctl","start","flop-r1155-guard-monitor.service"])
    driver.command(["/usr/bin/systemctl","start","flop-r1155-"+name+".service"])
    return dict(code="NEW_"+name.upper()+"_START_REQUESTED_VERIFY_REQUIRED",oci_retirement="STRICT_NO_GO")


def main():
    try:
        H.need(sys.argv[1:] in (["--prepare"],["--start-signer"],["--start-publisher"]),"ACTIVATION_ARGUMENT_STOP")
        current_host()
        request=S.secured(Path("/etc/flop-r1155-admission/activation.json"))
        H.shape(request,"config scope run_id source_packet")
        H.need(C.G.re.fullmatch(r"[0-9a-f]{32}",request["run_id"]),"ACTIVATION_RUN_STOP")
        if sys.argv[1:]==["--prepare"]:
            result=prepare(request["config"],request["scope"],C.R.D.ROOT/request["run_id"],request["source_packet"])
        else:result=start(request["config"],request["source_packet"],publisher=sys.argv[1:]==["--start-publisher"])
        print(C.G.canonical(result).decode());return 0
    except Exception:
        print('{"code":"ACTIVATION_STOP_NO_AUTO_RETRY","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}');return 42


if __name__=="__main__":raise SystemExit(main())
