"""One NEW dual-approved fixed-template Oracle reply; no historical queue.

Other four write lanes remain denied. This does not dispatch trades or TCLK.
Permanent signature reservation + local pre-POST fence prohibit blind retry.
"""
import importlib.util
import os
from pathlib import Path
import socket
import sys
import time

sp=importlib.util.spec_from_file_location("r1155_signer",Path(__file__).with_name("r1155_signer.py"))
S=importlib.util.module_from_spec(sp);sys.modules[sp.name]=S;sp.loader.exec_module(S)
H=S.H;C=S.C
STATE=Path("/var/lib/flop-r1155-publisher")
REQUEST=Path("/etc/flop-r1155/new-request.json")


def signer_request(request):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
        sock.settimeout(10);sock.connect(str(S.SOCKET))
        with sock.makefile("rwb",buffering=0) as stream:
            S.send_packet(stream,request);reply=S.read_packet(stream)
    H.shape(reply,"did nonce text sig");return reply


def publish(config,request,journal,*,sign=signer_request,post=None,clock=time.time,gate=S.local_gate,
            admission=S.approved,renderer=S.render,auto_nonce=False):
    from flop_agent import core,public_record
    now=int(clock());a=gate(config,publisher=True,now=now);admission(config,request,now)
    H.need(request["route"]==S.ROUTES[0],"PUBLISHER_NEW_ROUTE_NOT_ADMITTED")
    H.need(journal.latest is None,"PUBLISHER_PERMANENT_NO_RETRY")
    expected=renderer(request,a.profile["source_did"])
    journal.save(dict(phase="SIGN_REQUESTED_NO_RETRY",request_sha=C.G.sha(request)))
    try:
        body=sign(request)
        H.need(body["did"]==a.profile["source_did"] and
            ((auto_nonce and C.V.NONCE_RE.fullmatch(body["nonce"])) or body["nonce"]==request["nonce"]) and body["text"]==expected,"PUBLISHER_SIGNATURE_STOP")
        public_record.verify_signed_record(request["room"],dict(body,**{"from":body["did"]}))
        gate(config,publisher=True,now=int(clock()));admission(config,request,int(clock()))
        journal.save(dict(phase="POST_ATTEMPTING_NO_RETRY",request_sha=C.G.sha(request),body_sha=C.G.sha(body)))
        # No signed URL. No environment token, seed, redirects or automatic
        # HTTP retry. All exceptions after here conservatively become UNKNOWN.
        sender=post or core.httpx.post
        response=sender(core.BASE_URL+"/r/"+request["room"]+"?format=json",json=body,timeout=20,follow_redirects=False,trust_env=False)
        response.raise_for_status();row=response.json().get("posted")
        H.need(type(row) is dict and type(row.get("seq")) is int and row["seq"]>0 and
            type(row.get("ts")) is str and row["ts"] and all(row.get(k)==v for k,v in
                dict(**{"from":body["did"]},nonce=body["nonce"],text=body["text"],sig=body["sig"]).items()),"PUBLISHER_RECEIPT_STOP")
        public_record.verify_signed_record(request["room"],row)
        from datetime import datetime
        H.need(datetime.fromisoformat(row["ts"].replace("Z","+00:00")).utcoffset() is not None,"PUBLISHER_TIME_STOP")
        journal.save(dict(phase="POSTED_ACKNOWLEDGED_NO_RETRY",request_sha=C.G.sha(request),record=row))
        return dict(code="NEW_REQUEST_POSTED_ACKNOWLEDGED",oci_retirement="STRICT_NO_GO")
    except Exception:
        journal.save(dict(phase="UNKNOWN_NO_RETRY",request_sha=C.G.sha(request)))
        raise H.Stop("PUBLISHER_UNKNOWN_NO_RETRY") from None


def main():
    try:
        H.need(not sys.argv[1:],"PUBLISHER_ARGUMENT_STOP")
        config=S.secured(S.CONFIG);S.local_gate(config,publisher=True);S.ensure_runtime(config)
        request=S.secured(REQUEST)
        # Root-owned current request is never any restored queue/receipt file.
        H.private_dir(STATE)
        import fcntl
        lock=(STATE/"lock").open("ab");fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        root=H.private_dir(STATE/C.G.sha(dict(route=request["route"],id=request["id"])))
        result=publish(config,request,H.J.UndoJournal(root))
        print(C.G.canonical(result).decode());return 0
    except Exception:
        print('{"code":"NEW_PUBLISHER_STOP_NO_RETRY","oci_retirement":"STRICT_NO_GO"}');return 42


if __name__=="__main__":raise SystemExit(main())
