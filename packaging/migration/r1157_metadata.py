"""Fixed READ ONLY host metadata. Never a G4/G5 completeness attestation."""
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import sys
import time
from decimal import Decimal

sp=importlib.util.spec_from_file_location("r1157_metadata_hold",Path(__file__).with_name("r1154_app_hold.py"))
H=importlib.util.module_from_spec(sp);sys.modules[sp.name]=H;sp.loader.exec_module(H);C=H.C


def logical_size(roots,*,clock=time.monotonic):
    """No file contents, no SQLite connection; symlinks are never followed.

    This is a recent live bound, NOT a coherent archive. The existing held
    capture re-censuses and refuses to exceed it. Growth requires a new grant.
    """
    end=clock()+30;count=0;total=0
    def walk(path,depth):
        nonlocal count,total
        count+=1;H.need(count<=500000 and depth<=64 and clock()<=end,"METADATA_SIZE_BOUND_STOP")
        before=path.lstat()
        if stat.S_ISDIR(before.st_mode):
            for child in path.iterdir():walk(child,depth+1)
        elif stat.S_ISREG(before.st_mode):total+=before.st_size
        elif not stat.S_ISLNK(before.st_mode):raise H.Stop("METADATA_SPECIAL_OBJECT_STOP")
        after=path.lstat()
        H.need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==
            (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),"METADATA_SIZE_RACE_STOP")
    for path in roots:
        H.need(not path.is_symlink() and path.is_dir(),"METADATA_ROOT_STOP");walk(path,0)
    C.integer(total,1,C.R.T.C.MAX_SOURCE_BYTES)
    return total


def peer(request):
    H.shape(request,"enrollment enrollment_sha operation role challenge endpoint")
    a=H.Authority(request["enrollment"],request["enrollment_sha"]);role=request["role"]
    H.need(sys.platform=="linux" and request["operation"]=="r1157-readonly-metadata" and role in ("oci","k137"),"METADATA_ROLE_STOP")
    C.digest(request["challenge"]);endpoint=request["endpoint"]
    expected=a.trust.context["host"] if role=="oci" else H.B.K137
    machine=hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()
    H.need(machine==expected==endpoint["machine_sha256"] and os.geteuid()==endpoint["uid"]==
        (0 if role=="oci" else 1000),"METADATA_HOST_STOP")
    boot=hashlib.sha256(Path("/proc/sys/kernel/random/boot_id").read_bytes()).hexdigest()
    cgroup=hashlib.sha256(Path("/proc/self/cgroup").read_bytes()).hexdigest()
    H.need(cgroup==endpoint["cgroup_sha256"],"METADATA_CGROUP_STOP")
    available=int(next(row for row in Path("/proc/meminfo").read_text().splitlines()
        if row.startswith("MemAvailable:")).split()[1])*1024
    pressure={}
    for name in ("cpu","io"):
        fields=dict(x.split("=",1) for x in (Path("/proc/pressure")/name).read_text().splitlines()[0].split()[1:])
        pressure[name]=int(Decimal(fields["avg10"])*1000)
    value=dict(version=1,role=role,challenge=request["challenge"],machine=machine,boot=boot,cgroup=cgroup,
        uid=os.geteuid(),observed_at=int(time.time()),memory_headroom_bytes=available,
        cpu_psi_milli=pressure["cpu"],io_psi_milli=pressure["io"],writer_proof="NOT_PROVEN")
    if role=="oci":
        driver=H.Linux();identity=driver.reader.identity()
        H.need(identity["source_head"]==C.G.SOURCE_HEAD==endpoint["head"],"METADATA_HEAD_STOP")
        held=None;templates=None
        if H.WORK.exists():
            # Reuse the actual read-only held verifier. Masked units cannot be
            # inventoried as if their original fragments were still installed.
            H.need(not H.WORK.is_symlink(),"METADATA_HOLD_PATH_STOP")
            held=H.Controller(a,driver).verify()
            path=H.WORK/"scope.json"
            H.need(not path.is_symlink() and 0<path.stat().st_size<=1024**2,"METADATA_HOLD_PATH_STOP")
            scope=C.decode(path.read_bytes())
            at=max(scope[k]["body"]["observed_at"] for k in ("owner","witness"))
            H.validate_scope(a,scope,now=at)
            H.need(held["scope_sha"]==C.G.sha(scope),"METADATA_HOLD_SCOPE_STOP")
            units=scope["units"];names=set(units);templates=scope["templates"]
        else:
            names=driver.discovered();H.need(0<len(names)<=128,"METADATA_UNIT_BOUND_STOP")
            units={name:driver.unit(name) for name in sorted(names)}
        import pwd
        users={name:pwd.getpwnam(name).pw_uid for name in sorted(H.USERS) if any(row["user"]==name for row in units.values())}
        H.need({"technocore","technocore-signer"}<=set(users),"METADATA_USERS_STOP")
        driver.identity(dict(source=a.trust.context,users=users))
        # Reuse existing exact protected identity and launcher hash readers.
        protected=driver.protected()
        value.update(head=identity["source_head"],units=units,users=users,
            templates=templates if templates is not None else {name:sorted(n for n in names if n==name or "@." in name and n.startswith(name.split("@",1)[0]+"@")
                and n.endswith(".service")) for name in sorted(C.U.EXPECTED)},
            launcher_sha=driver.launchers(),protected_sha=C.G.sha(protected),
            source_bytes=logical_size([Path(p) for p in C.ROOTS]),held=held)
    else:
        # Only fixed filesystem free-space. Never inspect TradeBot or secrets.
        value.update(free_bytes=shutil.disk_usage("/var/lib").free)
    return value
