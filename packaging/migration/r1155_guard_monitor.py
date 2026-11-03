"""Root READ monitor of actual K137 kernel deny/masks. No signing or repair."""
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import time
import socket

sp=importlib.util.spec_from_file_location("r1155_guard_signer",Path(__file__).with_name("r1155_signer.py"))
S=importlib.util.module_from_spec(sp);sys.modules[sp.name]=S;sp.loader.exec_module(S)
H=S.H;C=S.C
UNITS=Path("/etc/systemd/system")
BOOT=Path("/proc/sys/kernel/random/boot_id")


def observe(config,scope,driver,*,now,admit=S.activation):
    admit(config,now)
    H.need(C.G.sha(scope)==config["lease"]["scope_sha"],"GUARD_SCOPE_STOP")
    H.validate_scope(H.Authority(config["enrollment"],config["enrollment_sha"]),scope,
        now=scope["owner"]["body"]["observed_at"])
    import pwd
    users={name:pwd.getpwnam(name).pw_uid for name in scope["users"]}
    driver.verify_deny(users)  # fixed iptables/ip6tables -C only, never insert
    for name in scope["units"]:
        p=UNITS/name
        H.need(p.is_symlink() and os.readlink(p)=="/dev/null","GUARD_MASK_LOST")
    boot=hashlib.sha256(BOOT.read_bytes().strip()).hexdigest()
    H.need(boot==config["lease"]["boot_sha"],"GUARD_BOOT_STOP")
    return dict(config_sha=C.G.sha(config),scope_sha=C.G.sha(scope),boot_sha=boot,observed_at=now,status="READY")


def main(*,admit=S.activation):
    try:
        H.need(sys.platform=="linux" and os.geteuid()==0 and not sys.argv[1:] and
            C.R.D.machine_digest()==H.B.K137,"GUARD_HOST_STOP")
        import pwd
        gid=pwd.getpwnam("flop-r1155-publisher").pw_gid
        ready=False
        while True:
            config=S.secured(S.CONFIG);scope=S.secured(S.CONFIG.with_name("scope.json"))
            value=observe(config,scope,H.Linux(),now=int(time.time()),admit=admit)
            C.R.checkpoint(S.CONFIG.parent,"guard-health.json",value)
            p=S.CONFIG.with_name("guard-health.json");os.chown(p,0,gid);os.chmod(p,0o640)
            if not ready and os.environ.get("NOTIFY_SOCKET"):
                target=os.environ["NOTIFY_SOCKET"]
                with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as notify:
                    notify.connect("\0"+target[1:] if target.startswith("@") else target);notify.sendall(b"READY=1")
                ready=True
            time.sleep(5)
    except Exception:
        # Previous positive expires after 20s; no stale bool can enable writes.
        print('{"code":"GUARD_MONITOR_STOP","cutover":"NO_GO"}');return 42


if __name__=="__main__":raise SystemExit(main())
