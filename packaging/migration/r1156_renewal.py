"""Real bounded signed renewal, used by live archive guards and AWS runtime.

No signing keys, fabricated evidence, network discovery or authority extension.
Every version needs distinct enrolled owner AND independent signatures <=900s.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import time

sp=importlib.util.spec_from_file_location("r1156_signer",Path(__file__).with_name("r1155_signer.py"))
S=importlib.util.module_from_spec(sp);sys.modules[sp.name]=S;sp.loader.exec_module(S)
H=S.H;C=S.C
ROOT=Path("/etc/flop-r1156")
SOURCE=H.WORK/"renewal"


def anchor_ok(authority,anchor):
    H.shape(anchor,"purpose authority_sha source_machine target_machine source_boot target_boot source_head scope_sha hold_journal_sha manifest_sha epoch did_sha ledger_sha nonce_file_sha nonce_state_sha capture_sha runtime_sha generation_sha")
    H.need(anchor["purpose"] in ("archive","runtime") and anchor["source_machine"]==authority.trust.context["host"] and
        anchor["authority_sha"]==authority.pin and anchor["target_machine"]==H.B.K137 and anchor["source_head"]==C.G.SOURCE_HEAD and anchor["did_sha"]==authority.trust.context["did"],"RENEWAL_CONTEXT_STOP")
    for name,value in anchor.items():
        if name in ("purpose","source_head"):continue
        if name in ("runtime_sha","generation_sha") and anchor["purpose"]=="archive":H.need(value is None,"RENEWAL_CONTEXT_STOP")
        else:C.digest(value)


class Reader:
    def __init__(self,authority,anchor,read,journal,*,boot=None):
        anchor_ok(authority,anchor)
        self.authority=authority;self.anchor=C.decode(C.G.canonical(anchor));self.read=read;self.journal=journal;self.boot=boot

    def check(self,now):
        packet=self.read()
        if H.solo(self.authority):
            path=H.WORK/"scope.json" if self.anchor["purpose"]=="archive" else S.CONFIG.with_name("scope.json")
            scope=S.secured(path,mode=0o600 if self.anchor["purpose"]=="archive" else 0o640)
            H.need(C.G.sha(scope)==self.anchor["scope_sha"],"SOLO_MACHINE_BINDING_STOP")
            return H.solo_module().check_reader(self,packet,now,scope)
        H.shape(packet,"owner witness")
        data=self.authority.trust.verify(packet["owner"],"r1156-renewal","owner",now,age=900)
        H.need(self.authority.trust.verify(packet["witness"],"r1156-renewal","independent",now,age=900)==data,"RENEWAL_WITNESS_STOP")
        H.shape(data,"anchor_sha seq previous metrics")
        H.need(data["anchor_sha"]==C.G.sha(self.anchor),"RENEWAL_ANCHOR_STOP")
        C.integer(data["seq"],0,1000000)
        metrics=data["metrics"];H.shape(metrics,"observed_at source_running ssh_retained source_deny target_deny free_bytes remaining_bytes memory_headroom_bytes cpu_psi_milli io_psi_milli zero_cost")
        issued=max(packet[k]["body"]["observed_at"] for k in ("owner","witness"))
        expires=min(packet[k]["body"]["expires_at"] for k in ("owner","witness"))
        C.fresh(metrics["observed_at"],issued,age=30)
        for key in ("source_running","ssh_retained","source_deny","target_deny","zero_cost"):H.need(metrics[key] is True,"RENEWAL_EVIDENCE_STOP")
        for key in ("free_bytes","remaining_bytes","memory_headroom_bytes","cpu_psi_milli","io_psi_milli"):C.integer(metrics[key])
        H.need(metrics["free_bytes"]>=20*C.R.GIB+metrics["remaining_bytes"]+C.R.GIB and metrics["memory_headroom_bytes"]>=256*1024**2 and
            metrics["cpu_psi_milli"]<=5000 and metrics["io_psi_milli"]<=10000,"RENEWAL_RESOURCES_STOP")
        token=C.G.sha(packet);last=self.journal.latest
        if last is not None:
            H.need(last["anchor_sha"]==data["anchor_sha"],"RENEWAL_ANCHOR_STOP")
            if token==last["packet_sha"]:H.need(data["seq"]==last["seq"],"RENEWAL_REPLAY_STOP")
            else:
                H.need(data["seq"]==last["seq"]+1 and data["previous"]==last["packet_sha"] and
                    last["issued"]<=issued<=last["expires"],"RENEWAL_GAP_OR_REPLAY_STOP")
        else:H.need(data["seq"]==0 and data["previous"] is None,"RENEWAL_INITIAL_STOP")
        if self.boot is not None:
            expected=self.anchor["source_boot" if self.anchor["purpose"]=="archive" else "target_boot"]
            H.need(self.boot()==expected,"RENEWAL_REBOOT_STOP")
        if last is None or token!=last["packet_sha"]:
            self.journal.save(dict(anchor_sha=data["anchor_sha"],seq=data["seq"],packet_sha=token,issued=issued,expires=expires))
        return data

    def check_capture(self,binding,now):
        H.need(self.anchor["purpose"]=="archive" and C.G.sha(binding)==self.anchor["capture_sha"] and
            binding["scope_sha"]==self.anchor["scope_sha"] and binding["hold_journal_sha"]==self.anchor["hold_journal_sha"] and
            binding["epoch"]==self.anchor["epoch"] and binding["ledger_sha"]==self.anchor["ledger_sha"],"RENEWAL_CAPTURE_STOP")
        self.check(now)

    def bind_capture(self,binding,manifest_sha,nonce_sha,now):
        self.check_capture(binding,now)
        H.need(manifest_sha==self.anchor["manifest_sha"] and nonce_sha==self.anchor["nonce_file_sha"],"RENEWAL_MANIFEST_NONCE_STOP")


def source_reader(authority,anchor,*,initial=None):
    root=H.private_dir(SOURCE);records=H.private_dir(root/"records")
    path=root/"current.json";pin=root/"anchor.json"
    if not pin.exists():
        H.need(initial is not None,"RENEWAL_NOT_INSTALLED")
        reader=Reader(authority,anchor,lambda:initial,H.J.UndoJournal(records),
            boot=lambda:hashlib.sha256(Path("/proc/sys/kernel/random/boot_id").read_bytes()).hexdigest())
        reader.check(int(time.time()))
        H.exclusive(pin,C.G.canonical(anchor));H.exclusive(path,C.G.canonical(initial))
    H.need(not pin.is_symlink() and C.decode(pin.read_bytes())==anchor,"RENEWAL_ANCHOR_STOP")
    return Reader(authority,anchor,lambda:S.secured(path,mode=0o600),H.J.UndoJournal(records),
        boot=lambda:hashlib.sha256(Path("/proc/sys/kernel/random/boot_id").read_bytes()).hexdigest())


def install_source(authority,anchor,packet):
    # Called only by the original root pinned RPC; never re-enroll an anchor.
    H.need(sys.platform=="linux" and os.geteuid()==0 and C.decode((SOURCE/"anchor.json").read_bytes())==anchor,"RENEWAL_INSTALL_STOP")
    reader=source_reader(authority,anchor)
    pending=Reader(authority,anchor,lambda:packet,reader.journal,boot=reader.boot)
    pending.check(int(time.time()))
    C.R.checkpoint(SOURCE,"current.json",packet)
    return dict(code="SIGNED_RENEWAL_INSTALLED")


def peek(authority,anchor,packet,now):
    """Read-only current signed version for inert restore/owner preflight.

    Source/runtime INSTALL always uses durable monotonic CAS. This does not
    install or roll back a chain, allocate a nonce or authorise a new capture.
    """
    body=packet["owner"]["body"];data=body["data"]
    class Seen:
        latest=dict(anchor_sha=C.G.sha(anchor),seq=data["seq"],packet_sha=C.G.sha(packet),
            issued=body["observed_at"],expires=body["expires_at"])
        def save(self,_):raise H.Stop("RENEWAL_READ_ONLY_STOP")
    return Reader(authority,anchor,lambda:packet,Seen()).check(now)


def runtime_admit(config,now):
    # Immutable original admission remains authenticated, not extended. A NEW
    # owner+witness signature pair is mandatory for every subsequent interval.
    at=config["owner"]["body"]["observed_at"]
    authority=S.activation(config,at)
    cap=S.secured(ROOT/"capability.json")
    H.shape(cap,"anchor generation owner witness")
    anchor=cap["anchor"];anchor_ok(authority,anchor)
    H.need(sys.platform=="linux" and C.R.D.machine_digest()==H.B.K137 and
        hashlib.sha256(Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()).hexdigest()==anchor["target_boot"],"RENEWAL_RUNTIME_HOST_BOOT_STOP")
    H.need(anchor["purpose"]=="runtime" and anchor["runtime_sha"]==C.G.sha(config) and
        anchor["generation_sha"]==C.G.sha(cap["generation"]) and anchor["manifest_sha"]==config["lease"]["restored_manifest_sha"] and
        anchor["epoch"]==config["baseline"]["epoch"] and anchor["ledger_sha"]==config["baseline"]["ledger_sha"] and
        anchor["nonce_state_sha"]==C.G.sha(config["baseline"]["nonces"]) and anchor["target_boot"]==config["lease"]["boot_sha"],"RENEWAL_RUNTIME_STOP")
    at=max(cap[k]["body"]["observed_at"] for k in (("owner",) if H.solo(authority) else ("owner","witness")))
    H.need(H.approval_pair(authority,cap["owner"],cap["witness"],"r1156-autonomy",at)==
        dict(anchor_sha=C.G.sha(anchor),generation_sha=C.G.sha(cap["generation"])),"RENEWAL_CAPABILITY_STOP")
    packet=S.secured(ROOT/"current.json")
    # Root owns persistent CAS state; unprivileged consumers must see exactly
    # that admitted version, not silently accept an older signed response.
    admitted=S.secured(ROOT/"admitted.json")
    H.need(admitted["packet_sha"]==C.G.sha(packet) and admitted["anchor_sha"]==C.G.sha(anchor),"RENEWAL_NOT_ADMITTED")
    class Seen:
        latest=admitted
        def save(self,_):raise H.Stop("RENEWAL_ROOT_INSTALL_REQUIRED")
    Reader(authority,anchor,lambda:packet,Seen()).check(now)
    return authority


def install_runtime(config,packet):
    H.need(sys.platform=="linux" and os.geteuid()==0,"RENEWAL_ROOT_REQUIRED")
    authority=S.activation(config,config["owner"]["body"]["observed_at"])
    cap=S.secured(ROOT/"capability.json");anchor=cap["anchor"]
    H.need(anchor["runtime_sha"]==C.G.sha(config),"RENEWAL_RUNTIME_STOP")
    records=H.private_dir(ROOT/"renewal-records")
    journal=H.J.UndoJournal(records)
    Reader(authority,anchor,lambda:packet,journal,
        boot=lambda:hashlib.sha256(Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()).hexdigest()).check(int(time.time()))
    import pwd
    gid=pwd.getpwnam("flop-r1155-publisher").pw_gid
    for name,value in (("current.json",packet),("admitted.json",journal.latest)):
        C.R.checkpoint(ROOT,name,value);os.chown(ROOT/name,0,gid);os.chmod(ROOT/name,0o640)
    return dict(code="SIGNED_RENEWAL_INSTALLED")


def main():
    try:
        H.need(sys.argv[1:] in (["--install-runtime"],) and sys.platform=="linux" and os.geteuid()==0,"RENEWAL_ARGUMENT_STOP")
        config=S.secured(S.CONFIG);raw=sys.stdin.buffer.read(65537);H.need(0<len(raw)<=65536,"RENEWAL_INPUT_BOUND_STOP");packet=C.decode(raw)
        print(C.G.canonical(install_runtime(config,packet)).decode());return 0
    except Exception:
        print('{"code":"SIGNED_RENEWAL_STOP","cutover":"NO_GO"}');return 42


if __name__=="__main__":raise SystemExit(main())
