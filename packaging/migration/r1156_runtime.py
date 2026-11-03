"""Original Resident -> NEW-only queue -> isolated Broker -> durable ACK.

Observer never connects to signer. Publisher cannot write Resident queues.
No imported intent is dispatched; no TCLK/Close1 financial lane is enabled.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import time

def load(name,leaf):
    sp=importlib.util.spec_from_file_location(name,Path(__file__).with_name(leaf))
    m=importlib.util.module_from_spec(sp);sys.modules[name]=m;sp.loader.exec_module(m);return m
N=load("r1156_runtime_renewal","r1156_renewal.py");S=N.S;H=S.H;C=S.C
P=load("r1156_original_publisher","r1155_publisher.py")
STATE=Path("/var/lib/flop-r1156-resident/state")
ACKS=Path("/var/lib/flop-r1156-acks")


def gate(config,*,publisher=False,now=None):return S.local_gate(config,publisher=publisher,now=now,admit=N.runtime_admit)


def capability(config,now):
    a=N.runtime_admit(config,now);cap=S.secured(N.ROOT/"capability.json");g=cap["generation"]
    H.shape(g,"epoch started_at resident_uid source_hashes database_hashes frozen_cursors room_generations old_candidates first_contact_enabled topics")
    H.need(g["epoch"]==config["baseline"]["epoch"] and type(g["first_contact_enabled"]) is bool and
        type(g["old_candidates"]) is list and len(g["old_candidates"])<=20000,"AUTONOMY_GENERATION_STOP")
    C.integer(g["resident_uid"],1001,65533);C.integer(g["started_at"],1,now)
    H.need(g["resident_uid"] not in (config["signer_uid"],config["publisher_uid"]),"AUTONOMY_UID_STOP")
    H.need(type(g["frozen_cursors"]) is dict and len(g["frozen_cursors"])<=1000 and
        type(g["room_generations"]) is dict and len(g["room_generations"])<=1000,"AUTONOMY_CURSOR_STOP")
    for key,value in g["frozen_cursors"].items():H.need(C.V.ROOM_RE.fullmatch(key),"AUTONOMY_ROOM_STOP");C.integer(value)
    from flop_agent import autopilot_transport
    H.need(type(g["topics"]) is list and set(g["topics"])<=autopilot_transport.TOPICS,"AUTONOMY_TOPIC_STOP")
    return a,g


def active_json(name,uid):
    path=STATE/name
    for parent in (path.parent,*path.parents):H.need(not parent.is_symlink(),"AUTONOMY_PATH_STOP")
    info=path.lstat()
    H.need(stat.S_ISREG(info.st_mode) and info.st_uid==uid and not info.st_mode&0o027 and
        0<info.st_size<=16*1024**2,"AUTONOMY_STATE_STOP")
    return C.decode(path.read_bytes())


def snapshot(generation):
    uid=generation["resident_uid"]
    return (active_json("observer/resident-state.json",uid),active_json("autopilot/autopilot-outbox.json",uid),
        active_json("observer/room-generation-status.json",uid))


def origin(config,wire,*,now,snapshots=None,cap=None):
    snapshots=snapshots or snapshot;cap=cap or capability
    H.shape(wire,"mode epoch intent_id")
    H.need(wire["mode"]=="resident" and type(wire["intent_id"]) is str and C.G.re.fullmatch(r"[a-f0-9]{20}",wire["intent_id"]),"AUTONOMY_REQUEST_STOP")
    a,g=cap(config,now)
    H.need(wire["epoch"]==g["epoch"] and wire["intent_id"] not in config["baseline"]["old_ids"][S.ROUTES[0]],"AUTONOMY_IMPORTED_STOP")
    local,auto,rooms=snapshots(g)
    H.need(auto.get("enabled") is True and auto.get("paused") is False and local.get("control",{}).get("paused") is not True,"AUTONOMY_PAUSED_STOP")
    item=auto.get("outbox",{}).get(wire["intent_id"])
    H.need(type(item) is dict and item.get("status","queued")=="queued" and wire["intent_id"] not in auto.get("receipts",{}),"AUTONOMY_NOT_QUEUED_STOP")
    candidate=local.get("candidates",{}).get(item.get("source_candidate_id"))
    H.need(type(candidate) is dict and candidate.get("candidate_id") not in g["old_candidates"],"AUTONOMY_IMPORTED_STOP")
    from flop_agent import autopilot,autopilot_core,observer,knowledge_guard
    C.fresh(rooms["observed_at"],now,age=120)
    room=item["room"];seq=item["seq"]
    H.need(type(seq) is int and seq>g["frozen_cursors"].get(room,0) and candidate.get("seq")==seq and candidate.get("room")==room,"AUTONOMY_OLD_SOURCE_STOP")
    if room in g["room_generations"]:
        H.need(rooms["room_generations"].get(room)==g["room_generations"][room],"AUTONOMY_ROOM_EPOCH_STOP")
    stamp=observer.parse_time(candidate.get("created_at"));created=observer.parse_time(item.get("created_at"))
    H.need(stamp is not None and created is not None and int(stamp.timestamp())>=g["started_at"] and int(created.timestamp())>=g["started_at"],"AUTONOMY_OLD_SOURCE_STOP")
    allowed,reason,topic=knowledge_guard.guarded_eligible(candidate)
    H.need(allowed,"AUTONOMY_ELIGIBILITY_STOP")
    trusted=allowed and autopilot.sender_trusted_for_autopilot(candidate,local,auto)
    if not trusted:
        H.need(g["first_contact_enabled"] is True and auto.get("first_contact_enabled") is True,"AUTONOMY_TRUST_STOP")
        allowed,reason,topic=autopilot.first_contact_eligible(candidate)
        marker=auto.get("first_contact_intents",{}).get(item["id"],{})
        H.need(marker.get("candidate_id")==candidate["candidate_id"] and marker.get("fingerprint")==candidate["fingerprint"],"AUTONOMY_BOOTSTRAP_MARKER_STOP")
        others=dict(auto);others["outbox"]={k:v for k,v in auto["outbox"].items() if k!=item["id"]}
        H.need(not autopilot.autopilot_policy._has_live_first_contact(others,candidate["fingerprint"]) and
            not autopilot.autopilot_policy._first_contact_global_cooldown_active(auto),"AUTONOMY_FIRST_CONTACT_COOLDOWN")
    H.need(allowed and topic in g["topics"] and candidate.get("status")=="pending","AUTONOMY_ELIGIBILITY_STOP")
    expected=autopilot.make_intent(candidate,topic,reason)
    for key in ("id","source_candidate_id","source_did","fingerprint","room","seq","category","topic","safety_decision"):
        H.need(expected[key]==item.get(key),"AUTONOMY_INTENT_CHANGED")
    new_queued=[k for k,v in auto["outbox"].items() if v.get("status","queued")=="queued" and k not in config["baseline"]["old_ids"][S.ROUTES[0]]]
    H.need(new_queued==[item["id"]],"AUTONOMY_QUEUE_SLOT_STOP")
    ok,_=autopilot_core.rate_ok_preview(auto,item);H.need(ok,"AUTONOMY_RATE_STOP")
    fields=autopilot.export_intent(item)
    # Existing exact deterministic renderer includes DLP. No excerpt reflection.
    from flop_agent import autopilot_transport
    autopilot_transport.render(fields)
    return dict(route=S.ROUTES[0],id=item["id"],room=room,nonce="AUTO",payload=dict(intent=fields),owner=None,witness=None)


class Broker(S.Broker):
    def __init__(self,*args,**kwargs):
        kwargs.update(admission=self.admit,renderer=S.render)
        super().__init__(*args,**kwargs);self.current=None

    def admit(self,config,mapped,now):
        current=origin(config,self.current,now=now)
        current["nonce"]=mapped["nonce"]
        H.need(current==mapped,"AUTONOMY_TOCTOU_STOP")
        return N.runtime_admit(config,now)

    def sign(self,wire,peer_uid):
        H.need(peer_uid==self.config["publisher_uid"],"RUNTIME_PEER_STOP")
        self.current=wire
        try:
            mapped=origin(self.config,wire,now=int(self.clock()))
            key=self.config["baseline"]["did"]+"|"+mapped["room"]
            state=self.journal.latest or {};floor=state.get("nonces",self.config["baseline"]["nonces"]).get(key,0)
            mapped["nonce"]=str(max(int(self.clock())*1000,int(floor)+1))
            return super().sign(mapped,peer_uid)
        finally:self.current=None


def write_ack(config,wire,journal,code):
    # Publisher-only local output. The Resident cannot create these files.
    info=ACKS.lstat()
    H.need(stat.S_ISDIR(info.st_mode) and not ACKS.is_symlink() and info.st_uid==config["publisher_uid"] and
        stat.S_IMODE(info.st_mode)==0o750,"AUTONOMY_ACK_DIRECTORY_STOP")
    path=ACKS/(wire["intent_id"]+".json")
    value=dict(epoch=wire["epoch"],intent_id=wire["intent_id"],code=code,record=journal.latest.get("record") if journal.latest else None)
    if path.exists():H.need(C.decode(path.read_bytes())==value,"AUTONOMY_ACK_CONFLICT")
    else:H.exclusive(path,C.G.canonical(value));os.chmod(path,0o640)


def publish_cycle(config,*,sign=P.signer_request,post=None,clock=time.time,root=None):
    a,g=capability(config,int(clock()));local,auto,rooms=snapshot(g)
    root=root or P.STATE
    for identity,item in list(auto.get("outbox",{}).items()):
        if identity in config["baseline"]["old_ids"][S.ROUTES[0]] or item.get("status","queued")!="queued":continue
        wire=dict(mode="resident",epoch=g["epoch"],intent_id=identity)
        folder=H.private_dir(root/C.G.sha(dict(route=S.ROUTES[0],id=identity)));journal=H.J.UndoJournal(folder)
        if journal.latest is not None:
            # ACK recovery only; never re-sign/re-POST an attempted intent.
            code="acknowledged" if journal.latest["phase"]=="POSTED_ACKNOWLEDGED_NO_RETRY" else "ambiguous"
            write_ack(config,wire,journal,code);continue
        try:mapped=origin(config,wire,now=int(clock()))
        except (ValueError,RuntimeError):continue
        def admission(cfg,req,now):
            expected=origin(cfg,wire,now=now);H.need(req==expected,"AUTONOMY_TOCTOU_STOP")
        try:
            P.publish(config,mapped,journal,sign=lambda _:sign(wire),post=post,clock=clock,gate=gate,
                admission=admission,auto_nonce=True)
        except Exception:
            if journal.latest is not None:write_ack(config,wire,journal,"ambiguous")
            continue
        write_ack(config,wire,journal,"acknowledged")


def before_maintenance():
    config=S.secured(S.CONFIG);_,g=capability(config,int(time.time()))
    H.need(os.geteuid()==g["resident_uid"],"AUTONOMY_RESIDENT_UID_STOP")
    from flop_agent import autopilot,core,oracle_signer,public_record
    H.need(core.STATE==STATE,"AUTONOMY_STATE_ROOT_STOP")
    auto=autopilot.load(allow_legacy=False);changed=False
    # Derived active projection only; original restored bytes/UNKNOWN stay intact.
    for identity in config["baseline"]["old_ids"][S.ROUTES[0]]:
        item=auto["outbox"].get(identity)
        if item and item.get("status","queued") in ("queued","prepared","posted","ambiguous"):
            item["status"]="quarantined";changed=True
    if changed:autopilot.save(auto,allow_legacy=False)
    if not ACKS.exists():return
    import pwd
    uid=pwd.getpwnam("flop-r1155-publisher").pw_uid
    paths=sorted(ACKS.glob("*.json"));H.need(len(paths)<=10000,"AUTONOMY_ACK_BOUND_STOP")
    receipts=oracle_signer.load_receipts()
    for path in paths:
        ack=S.secured(path,uid=uid);H.shape(ack,"epoch intent_id code record")
        identity=ack["intent_id"]
        if ack["epoch"]!=g["epoch"] or identity in config["baseline"]["old_ids"][S.ROUTES[0]]:continue
        item=auto["outbox"].get(identity)
        if item is None or item.get("status")=="acknowledged":continue
        if ack["code"]!="acknowledged":
            if item.get("status")!="ambiguous":item["status"]="ambiguous";autopilot.save(auto,allow_legacy=False)
            continue
        row=ack["record"];public_record.verify_signed_record(item["room"],row)
        text=P.S.render(dict(route=S.ROUTES[0],room=item["room"],id=identity,payload=dict(intent=autopilot.export_intent(item))),config["baseline"]["did"])
        H.need(row["from"]==config["baseline"]["did"] and row["text"]==text,"AUTONOMY_ACK_BINDING_STOP")
        receipt=dict(state="posted",prepared_at=row["ts"],posted_at=row["ts"],did=row["from"],nonce=row["nonce"],text_hash=hashlib.sha256(text.encode()).hexdigest(),
            receipt_hash=oracle_signer.receipt_hash(dict(intent_id=identity),row["from"],row["nonce"],text))
        receipts["receipts"][identity]=receipt
        oracle_signer.mark_acknowledged(auto,receipts,autopilot.export_intent(item),receipt)


def main():
    try:
        H.need(sys.argv[1:] in (["observe"],["capture"],["publisher"],["signer"],["guard"],["--unlock-local"]),"AUTONOMY_ARGUMENT_STOP")
        mode=sys.argv[1];sys.argv=[sys.argv[0]]+([mode] if mode=="--unlock-local" else [])
        config=S.secured(S.CONFIG);S.ensure_runtime(config)
        if mode in ("signer","--unlock-local"):return S.main(broker_type=Broker,gate=gate,admit=N.runtime_admit)
        if mode=="guard":
            def live(config,now):
                a=N.runtime_admit(config,now)
                from decimal import Decimal
                import shutil
                available=int(next(x for x in Path("/proc/meminfo").read_text().splitlines() if x.startswith("MemAvailable:")).split()[1])
                H.need(available>=256*1024 and shutil.disk_usage(STATE).free>=21*C.R.GIB,"AUTONOMY_RESOURCE_STOP")
                for name,limit in (("cpu",5),("io",10)):
                    fields=dict(x.split("=",1) for x in Path("/proc/pressure/"+name).read_text().splitlines()[0].split()[1:])
                    H.need(Decimal(fields["avg10"])<=limit,"AUTONOMY_RESOURCE_STOP")
                return a
            G=load("r1156_guard","r1155_guard_monitor.py");return G.main(admit=live)
        if mode in ("observe","capture"):
            _,g=capability(config,int(time.time()));H.need(os.geteuid()==g["resident_uid"],"AUTONOMY_RESIDENT_UID_STOP")
            from flop_agent import core,r1156_bridge
            H.need(core.STATE==STATE,"AUTONOMY_STATE_ROOT_STOP");r1156_bridge.install()
            if mode=="observe":
                from flop_agent import resident_daemon
                resident_daemon.main()
            else:
                from flop_agent import observer_lobby_capture_service
                observer_lobby_capture_service.main()
            return 0
        gate(config,publisher=True)
        H.private_dir(P.STATE)
        import fcntl,signal
        lock=(P.STATE/"lock").open("ab");fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        import threading
        stop=threading.Event()
        for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,lambda *_:stop.set())
        while not stop.is_set():
            try:publish_cycle(config)
            except (ValueError,RuntimeError):pass
            stop.wait(5)
        return 0
    except Exception:
        print('{"code":"AUTONOMY_DISARMED","cutover":"NO_GO"}');return 42


if __name__=="__main__":raise SystemExit(main())
