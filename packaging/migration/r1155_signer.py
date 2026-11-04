"""K137 AF_UNIX isolated signer. Original DID only; no Vault/network/seed env.

Manual recipient unseal after every restart. Five typed application lanes;
each exact application request needs separate owner + independent admission.
No unrestricted byte-signing endpoint and no imported historical queue.
"""
import getpass
import hashlib
import importlib.util
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import time
import warnings
if sys.platform=="linux":import fcntl

sp=importlib.util.spec_from_file_location("r1155_custody",Path(__file__).with_name("r1154_custody.py"))
K=importlib.util.module_from_spec(sp);sys.modules[sp.name]=K;sp.loader.exec_module(K)
H=K.H;C=H.C
CONFIG=Path("/etc/flop-r1155/runtime.json")
STORE=Path("/var/lib/flop-r1155-signer")
SOCKET=Path("/run/flop-r1155-signer/sign.sock")
ROUTES=tuple(H.P.ROUTES)
MAX_PACKET=65536


def secured(path,*,uid=0,mode=0o640):
    for parent in path.parents:
        info=parent.lstat();H.need(not parent.is_symlink() and not info.st_mode&0o022,"RUNTIME_PATH_STOP")
    s=path.lstat()
    H.need(stat.S_ISREG(s.st_mode) and s.st_uid==uid and s.st_nlink==1 and
        stat.S_IMODE(s.st_mode)==mode and 0<s.st_size<=1024**2,"RUNTIME_FILE_STOP")
    return C.decode(path.read_bytes())


def activation(config,now):
    H.shape(config,"enrollment enrollment_sha baseline baseline_sha lease owner witness signer_uid publisher_uid")
    a=H.Authority(config["enrollment"],config["enrollment_sha"])
    H.need(C.G.sha(config["baseline"])==config["baseline_sha"],"RUNTIME_BASELINE_STOP")
    b=config["baseline"];H.shape(b,"epoch did inventory ledger_sha nonces old_ids rate_history")
    C.digest(b["epoch"]);C.digest(b["ledger_sha"])
    H.need(b["did"]==a.profile["source_did"] and set(b["inventory"])==set(ROUTES) and set(b["old_ids"])==set(ROUTES),"RUNTIME_DID_STOP")
    for uid in (config["signer_uid"],config["publisher_uid"]):C.integer(uid,1001,65533)
    H.need(config["signer_uid"]!=config["publisher_uid"],"RUNTIME_SHARED_UID_STOP")
    lease=config["lease"];H.shape(lease,"baseline_sha destination boot_sha source_hold_sha restored_manifest_sha custody_sha activated_at original_post_deny new_only zero_cost runtime_head scope_sha signer_uid publisher_uid")
    H.need(lease["signer_uid"]==config["signer_uid"] and lease["publisher_uid"]==config["publisher_uid"],"RUNTIME_UID_BINDING_STOP")
    C.digest(lease["scope_sha"])
    H.need(type(lease["runtime_head"]) is str and C.G.re.fullmatch(r"[a-f0-9]{40}",lease["runtime_head"]),"RUNTIME_CODE_PIN_STOP")
    H.need(lease["baseline_sha"]==config["baseline_sha"] and lease["destination"]==H.B.K137 and
        lease["new_only"] is True and lease["original_post_deny"] is True and lease["zero_cost"] is True,"RUNTIME_LEASE_STOP")
    for field in ("boot_sha","source_hold_sha","restored_manifest_sha","custody_sha"):C.digest(lease[field])
    C.integer(lease["activated_at"],1,now)
    H.need(H.approval_pair(a,config["owner"],config["witness"],"r1155-activate",now)==lease,"RUNTIME_APPROVAL_STOP")
    return a


def ensure_runtime(config):
    path="/opt/flop-r1155-runtime"
    driver=H.Linux()
    args=["/usr/bin/git","-c","safe.directory="+path,"-c","core.fsmonitor=false","-C",path]
    H.need(driver.command([*args,"rev-parse","--verify","HEAD"]).stdout==(config["lease"]["runtime_head"]+"\n").encode(),"RUNTIME_CODE_PIN_STOP")
    driver.command([*args,"diff","--quiet","--no-ext-diff","--exit-code","HEAD","--"])
    sys.path.insert(0,path+"/src")


def local_gate(config,*,publisher=False,now=None,admit=activation):
    now=int(time.time()) if now is None else now
    a=admit(config,now)
    H.need(sys.platform=="linux" and os.geteuid()==config["publisher_uid" if publisher else "signer_uid"],"RUNTIME_USER_STOP")
    H.need(hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()==H.B.K137 and
        hashlib.sha256(Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()).hexdigest()==config["lease"]["boot_sha"],"RUNTIME_HOST_BOOT_STOP")
    health=secured(CONFIG.with_name("guard-health.json"))
    H.shape(health,"config_sha boot_sha scope_sha observed_at status")
    C.fresh(health["observed_at"],now,age=20)
    H.need(health["status"]=="READY" and health["config_sha"]==C.G.sha(config) and
        health["boot_sha"]==config["lease"]["boot_sha"] and health["scope_sha"]==config["lease"]["scope_sha"],"RUNTIME_GUARD_NOT_READY")
    return a


def baseline(files,hashes,did,epoch):
    """Original bytes only; preserves UNKNOWN, never manufactures finality."""
    inventory=H.P.original_attempts(files,did)
    old={route:sorted({item["id"] for item in rows}) for route,rows in inventory.items()}
    box=C.decode(files["autopilot/autopilot-outbox.json"])
    old[ROUTES[0]]=sorted(set(old[ROUTES[0]])|set(box["outbox"]))
    return dict(epoch=epoch,did=did,inventory=inventory,ledger_sha=H.P.ledger_digest(files,hashes),
        nonces=C.decode(files["nonces.json"]),old_ids=old,rate_history=box.get("rate_history",[]))


def approved(config,request,now):
    a=activation(config,now)
    H.shape(request,"route id room nonce payload owner witness")
    route=request["route"];H.need(route in ROUTES,"RUNTIME_ROUTE_STOP")
    H.need(type(request["id"]) is str and C.G.re.fullmatch(r"[a-f0-9]{20,64}",request["id"]),"RUNTIME_ID_STOP")
    H.need(request["id"] not in config["baseline"]["old_ids"][route],"RUNTIME_OLD_REQUEST_STOP")
    C.V.ROOM_RE.fullmatch(request["room"]) or H.need(False,"RUNTIME_ROOM_STOP")
    H.need(C.V.NONCE_RE.fullmatch(request["nonce"]),"RUNTIME_NONCE_STOP")
    key=a.profile["source_did"]+"|"+request["room"]
    H.need(int(request["nonce"])>int(config["baseline"]["nonces"].get(key,0)),"RUNTIME_OLD_NONCE_STOP")
    binding=dict(epoch=config["baseline"]["epoch"],activation_sha=C.G.sha(config["lease"]),
        request_sha=C.G.sha({k:v for k,v in request.items() if k not in ("owner","witness")}))
    packets=[request["owner"]] if H.solo(a) else [request["owner"],request["witness"]]
    H.need(all(packet["body"]["observed_at"]>=config["lease"]["activated_at"] for packet in packets) and
        H.approval_pair(a,request["owner"],request["witness"],"r1155-new-request",now)==binding,"RUNTIME_NEW_APPROVAL_STOP")
    return a


def render(request,did,key=None):
    """Room-bound protocols only. No arbitrary preimage signing verb."""
    route,room,p=request["route"],request["room"],request["payload"]
    from flop_agent import core,autopilot_transport
    H.need(core.signer_matches_pinned(),"RUNTIME_SIGNER_PIN_STOP")
    if route==ROUTES[0]:
        H.shape(p,"intent")
        intent=autopilot_transport.validate_intent(p["intent"])
        H.need(intent["category"]!="controlled_e2e" and intent["room"]==room and intent["intent_id"]==request["id"],"RUNTIME_INTENT_STOP")
        text=autopilot_transport.render(intent)
        # The existing renderer includes outbound DLP; no local replacement.
    elif route in ROUTES[1:3]:
        raise H.Stop("RUNTIME_TCLK_NEW_WRITE_NOT_ADMITTED")
    else:
        raise H.Stop("RUNTIME_CLOSE1_NEW_TRADE_NOT_ADMITTED")
    H.need(core.clean_text(text)==text and 0<len(text)<=4096,"RUNTIME_TEXT_STOP")
    return text


class Broker:
    def __init__(self,config,open_seed,journal,*,clock=time.time,gate=local_gate,admission=approved,renderer=render):
        self.config=config;self.open_seed=open_seed;self.journal=journal;self.clock=clock;self.gate=gate
        self.admission=admission;self.renderer=renderer
        H.need(callable(open_seed),"RUNTIME_KEY_PROVIDER_STOP")

    def sign(self,request,peer_uid):
        now=int(self.clock());a=self.gate(self.config,now=now)
        H.need(peer_uid==self.config["publisher_uid"],"RUNTIME_PEER_STOP")
        self.admission(self.config,request,now)
        text=self.renderer(request,a.profile["source_did"])
        state=self.journal.latest or dict(used={},nonces=dict(self.config["baseline"]["nonces"]),history=list(self.config["baseline"]["rate_history"]))
        state=C.decode(C.G.canonical(state))
        H.need(len(state["used"])<10000,"RUNTIME_STATE_BOUND_STOP")
        token=request["route"]+":"+request["id"];noncekey=a.profile["source_did"]+"|"+request["room"]
        H.need(token not in state["used"] and int(request["nonce"])>int(state["nonces"].get(noncekey,0)),"RUNTIME_PERMANENT_NO_RETRY")
        if request["route"]==ROUTES[0]:
            from flop_agent import autopilot_core
            intent=request["payload"]["intent"]
            internal=dict(room=request["room"],fingerprint=intent["source_fingerprint"])
            policy=dict(rate_history=state["history"])
            ok,_=autopilot_core.rate_ok(policy,internal)
            H.need(ok,"RUNTIME_RATE_STOP")
            state["history"]=policy["rate_history"]
            from datetime import datetime,UTC
            state["history"].append(dict(room=internal["room"],fingerprint=internal["fingerprint"],at=datetime.fromtimestamp(now,UTC).isoformat()))
        # Reserve before signature leaves process, even if publisher disappears
        # before POST. Never re-sign a request/nonce after disconnect or reboot.
        state["nonces"][noncekey]=int(request["nonce"])
        state["used"][token]=dict(status="PREPARED_NO_RETRY",payload_sha=C.G.sha(request["payload"]))
        key=None
        with self.open_seed() as seed:
            H.need(type(seed) is bytearray and len(seed)==32,"RUNTIME_KEY_STOP")
            try:
                official=K.S.original();key=official.Ed25519PrivateKey.from_private_bytes(bytes(seed))
                H.need(official.did_of(key)==a.profile["source_did"],"RUNTIME_DID_STOP")
                self.journal.save(state)
                self.gate(self.config,now=int(self.clock()))
                signature=official.signature(key,f"{request['room']}|{request['nonce']}|{text}")
            finally:seed[:]=b"\0"*len(seed);key=None
        return dict(did=a.profile["source_did"],nonce=request["nonce"],text=text,sig=signature)


def read_packet(stream):
    raw=stream.read(4);H.need(len(raw)==4,"RUNTIME_PACKET_STOP")
    n=struct.unpack(">I",raw)[0];H.need(0<n<=MAX_PACKET,"RUNTIME_PACKET_STOP")
    return C.decode(C.R.exact(stream,n))


def send_packet(stream,value):
    raw=C.G.canonical(value);H.need(len(raw)<=MAX_PACKET,"RUNTIME_PACKET_STOP")
    stream.write(struct.pack(">I",len(raw))+raw);stream.flush()


def serve(broker,server,*,once=False):
    while True:
        connection,_=server.accept()
        with connection:
            connection.settimeout(5)
            _,uid,_=struct.unpack("3i",connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            with connection.makefile("rwb",buffering=0) as stream:
                try:reply=broker.sign(read_packet(stream),uid)
                except Exception:reply={"code":"SIGNING_STOP_NO_RETRY"}
                send_packet(stream,reply)
        if once:return


def receive_unlock():
    path=SOCKET.with_name("unlock.sock")
    H.need(not path.exists() and not path.is_symlink(),"RUNTIME_UNLOCK_SOCKET_EXISTS")
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(str(path));os.chmod(path,0o600);server.listen(1);server.settimeout(300)
        try:
            connection,_=server.accept()
            with connection:
                connection.settimeout(5)
                _,uid,_=struct.unpack("3i",connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                H.need(uid==0,"RUNTIME_UNLOCK_PEER_STOP")
                with connection.makefile("rb",buffering=0) as stream:
                    n=struct.unpack(">I",C.R.exact(stream,4))[0];H.need(32<=n<=1024,"RUNTIME_UNLOCK_BOUND_STOP")
                    return bytearray(C.R.exact(stream,n))
        finally:path.unlink()


def unlock_local(admit=activation):
    H.need(sys.platform=="linux" and os.geteuid()==0 and sys.stdin.isatty() and
        hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()==H.B.K137,"RUNTIME_LOCAL_ROOT_TTY_REQUIRED")
    config=secured(CONFIG);admit(config,int(time.time()))
    path=SOCKET.with_name("unlock.sock");meta=path.lstat()
    H.need(stat.S_ISSOCK(meta.st_mode) and meta.st_uid==config["signer_uid"] and stat.S_IMODE(meta.st_mode)==0o600,"RUNTIME_UNLOCK_SOCKET_STOP")
    with warnings.catch_warnings():
        warnings.simplefilter("error",getpass.GetPassWarning)
        password=bytearray(getpass.getpass("R1155 LOCAL encrypted recipient unlock (NOT DID seed): ").encode())
    try:
        H.need(32<=len(password)<=1024,"RUNTIME_UNLOCK_BOUND_STOP")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.settimeout(5);sock.connect(str(path));sock.sendall(struct.pack(">I",len(password))+password)
        return 0
    finally:password[:]=b"\0"*len(password)


def main(*,broker_type=Broker,gate=local_gate,admit=activation):
    password=None
    try:
        if sys.argv[1:]==["--unlock-local"]:return unlock_local(admit)
        H.need(sys.platform=="linux" and not sys.argv[1:],"RUNTIME_ARGUMENT_STOP")
        config=secured(CONFIG);a=gate(config);ensure_runtime(config)
        H.private_dir(STORE)
        lock=(STORE/"lock").open("ab");fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        # Secret passphrase is entered by the LOCAL K137 owner. No Windows
        # unseal, env variable, credential discovery or automatic availability.
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        password=receive_unlock()
        pem=STORE/"recipient.pem.enc";s=pem.lstat()
        H.need(stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=8192,"RUNTIME_RECIPIENT_CUSTODY_STOP")
        try:recipient=load_pem_private_key(pem.read_bytes(),bytes(password))
        finally:password[:]=b"\0"*len(password)
        document=secured(STORE/"custody.json",uid=os.geteuid(),mode=0o600)
        H.need(C.G.sha(document["envelope"])==config["lease"]["custody_sha"],"RUNTIME_CUSTODY_STOP")
        # Old independently signed custody is immutable history. Current
        # activation is a separate fresh dual authorization to unseal here.
        at=document["owner"]["body"]["observed_at"]
        def open_seed():return K.unseal(a,document["binding"],document["owner"],document["witness"],document["envelope"],recipient,now=at)
        with open_seed():pass  # startup continuity check; immediately wiped
        broker=broker_type(config,open_seed,H.J.UndoJournal(H.private_dir(STORE/"records")),gate=gate)
        H.need(not SOCKET.exists() and not SOCKET.is_symlink(),"RUNTIME_SOCKET_EXISTS_STOP")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
            server.bind(str(SOCKET));os.chmod(SOCKET,0o660);server.listen(4)
            try:serve(broker,server)
            finally:SOCKET.unlink()
        return 0
    except Exception:
        print('{"code":"ISOLATED_SIGNER_STOP","cutover":"NO_GO"}');return 42
    finally:
        if password is not None:password[:]=b"\0"*len(password)


if __name__=="__main__":raise SystemExit(main())
