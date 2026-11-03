"""Public signed-renewal relay in the EXISTING Windows owner session.

Reuses its pinned SSH and short-lived R987 custody; never generates approvals.
Renewal failure aborts the current binary child, not a new encryption attempt.
"""
import importlib.util
import threading
from pathlib import Path
import sys
import time

sp=importlib.util.spec_from_file_location("r1156_relay_renewal",Path(__file__).with_name("r1156_renewal.py"))
N=importlib.util.module_from_spec(sp);sys.modules[sp.name]=N;sp.loader.exec_module(N)
H=N.H;C=N.C;R=C.R


class Session:
    def __init__(self,control):
        self.control=control;plan=control["plan"];self.plan=plan
        self.authority=H.Authority(plan["enrollment"],plan["enrollment_sha"])
        self.anchor=plan["renewal"]["anchor"]
        parent=Path(plan["offhost_parent"])
        self.path=parent/("r1156-renewal-"+plan["run_id"]+".json")
        if not self.path.exists():R.checkpoint(parent,self.path.name,plan["renewal"]["initial"])
        state=parent/("r1156-seen-"+plan["run_id"]+".json")
        H.need(not state.exists() or not state.is_symlink() and state.is_file() and state.stat().st_size<=16384,"RENEWAL_OWNER_STATE_STOP")
        class Journal:
            latest=C.decode(state.read_bytes()) if state.exists() else None
            def save(self,value):R.checkpoint(parent,state.name,value);self.latest=value
        self.reader=N.Reader(self.authority,self.anchor,self.packet,Journal())
        self.stop=threading.Event();self.failed=threading.Event();self.thread=None;self.active=None
        self.lock=threading.RLock()

    def packet(self):
        H.need(self.path.is_file() and not self.path.is_symlink() and 0<self.path.stat().st_size<=65536,"RENEWAL_OWNER_FILE_STOP")
        return C.decode(self.path.read_bytes())

    def check(self,now):
        H.need(not self.failed.is_set(),"RENEWAL_RELAY_ABORTED")
        with self.lock:return self.reader.check(now)

    def attach(self,process):
        self.active=process
        if self.failed.is_set() and process.poll() is None:process.kill()

    def start(self,source,sources):
        if self.thread is not None:return
        def loop():
            sent=self.plan["renewal"]["initial"]
            try:
                from importlib.util import spec_from_file_location,module_from_spec
                spec=spec_from_file_location("r1156_relay_transfer",Path(__file__).with_name("r1155_transfer.py"))
                T=module_from_spec(spec);spec.loader.exec_module(T)
                while not self.stop.is_set():
                    self.check(int(time.time()));packet=self.packet()
                    if C.G.sha(packet)!=C.G.sha(sent):
                        request=dict(enrollment=self.plan["enrollment"],enrollment_sha=self.authority.pin,
                            operation="renew-source",plan=self.plan,meta=None,renewal_packet=packet)
                        argv=T.command(source,"renew-source",sources,self.anchor["source_machine"],self.authority.pin)
                        with R.child(argv,timeout=30) as process:
                            R.send_request(process,sources,request)
                            result=R.frame_read(process.stdout,R.META)
                            H.need(process.wait(timeout=5)==0 and result==dict(code="SIGNED_RENEWAL_INSTALLED"),"RENEWAL_RELAY_STOP")
                        sent=packet
                    self.stop.wait(5)
            except Exception:
                self.failed.set()
                process=self.active
                if process is not None and process.poll() is None:process.kill()
        self.thread=threading.Thread(target=loop,daemon=True);self.thread.start()

    def __enter__(self):self.check(int(time.time()));return self
    def __exit__(self,*_):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(40);H.need(not self.thread.is_alive(),"RENEWAL_RELAY_SHUTDOWN_STOP")
