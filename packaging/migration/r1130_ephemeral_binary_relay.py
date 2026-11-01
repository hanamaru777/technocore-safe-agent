"""R1130 ephemeral binary relay: internal library only; no owner CLI.

A separate approved owner carrier must construct both host-pinned SSH commands.
This module does NOT authenticate hosts or authorize source data export.
"""
import json
import os
import subprocess
import threading

MAGIC=b"FLOPST01"
CHUNK=64*1024
MAX_BYTES=32*1024**2
MAX_SOURCE_INPUT=4*1024**2
MAX_REPORT=4096
MAX_RUNTIME=180

class Stop(Exception): pass

def need(ok, code):
    if not ok: raise Stop(code)

def _pairs(pairs):
    out={}
    for k,v in pairs:
        need(k not in out,"DUPLICATE_REPORT_KEY")
        out[k]=v
    return out

def strict_receipt(data):
    need(type(data) is bytes and 20<len(data)<=MAX_REPORT and data.isascii()
         and b"\0" not in data,"REPORT_SIZE_STOP")
    try:
        p=json.loads(data.decode("ascii"),object_pairs_hook=_pairs,
                     parse_constant=lambda v: (_ for _ in ()).throw(Stop("REPORT_STOP")))
    except (ValueError,UnicodeError,RecursionError):
        raise Stop("REPORT_STOP") from None
    need(type(p) is dict and set(p)=={
        "phase","result","files","bytes","aead_verified",
        "source_complete","sqlite_epoch","history_finality",
        "signer_portability","activated","cutover","oci_retirement"
    },"REPORT_SCHEMA_STOP")
    need(p["phase"]=="R1129" and
         p["result"]=="PROVISIONAL_CIPHERTEXT_STORED_ONLY" and
         type(p["files"]) is int and 3<=p["files"]<=258 and
         type(p["bytes"]) is int and 1<=p["bytes"]<=MAX_BYTES and
         p["aead_verified"] is False and p["source_complete"] is False and
         p["sqlite_epoch"]=="NOT_PROVEN" and p["history_finality"]=="UNKNOWN" and
         p["signer_portability"]=="NOT_PROVEN" and p["activated"] is False and
         p["cutover"]=="NO_GO" and p["oci_retirement"]=="STRICT_NO_GO",
         "REPORT_RELEASE_STOP")
    return {"phase":"R1130","result":"CIPHERTEXT_RELAY_ONLY",
            "ciphertext_bytes":p["bytes"],"ciphertext_files":p["files"],
            "aead_verified":False,"source_complete":False,
            "activated":False,"cutover":"NO_GO",
            "oci_retirement":"STRICT_NO_GO"}

def safe_argv(argv):
    need(type(argv) in (tuple,list) and 2<=len(argv)<=70 and
         all(type(x) is str and 0<len(x)<=16000 and "\0" not in x for x in argv),
         "SSH_ARGV_STOP")
    need(os.path.isabs(argv[0]) and os.path.isfile(argv[0]),
         "SSH_BINARY_STOP")
    return list(argv)

def relay(source_argv,dest_argv,source_input,*,timeout=MAX_RUNTIME):
    """Only verified ciphertext is forwarded in RAM. No Windows disk writes.

    Caller MUST independently verify original and K137 host keys, SSH argv,
    original signed owner grant and destination custody before invoking.
    """
    # Prelaunch validation is a failure path too. Do not retain the mutable
    # owner-controlled source request if argv/timeouts are rejected.
    try:
        need(type(source_input) is bytearray and
             1<=len(source_input)<=MAX_SOURCE_INPUT,"SOURCE_INPUT_STOP")
        need(type(timeout) is int and 5<=timeout<=MAX_RUNTIME,"TIMEOUT_STOP")
        source=safe_argv(source_argv);dest=safe_argv(dest_argv)
        env={"LANG":"C"}
        if os.name=="nt":
            for key in ("SystemRoot","ProgramData"):
                value=os.environ.get(key)
                need(type(value) is str and os.path.isabs(value),
                     "WINDOWS_ENV_STOP")
                env[key]=value
    except Exception:
        if type(source_input) is bytearray:
            source_input[:] = b"\x00" * len(source_input)
        raise
    procs=[]
    timed_out=threading.Event()
    errors=[]
    def kill_both():
        timed_out.set()
        for p in procs:
            if p.poll() is None:
                try:p.kill()
                except OSError:pass
    alarm=threading.Timer(timeout,kill_both)
    alarm.daemon=True
    try:
        dst=subprocess.Popen(dest,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL,env=env,shell=False)
        procs.append(dst)
        src=subprocess.Popen(source,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL,env=env,shell=False)
        procs.append(src)
        def feed():
            try:
                src.stdin.write(source_input)
                src.stdin.close()
            except (OSError,ValueError):
                errors.append("SOURCE_STDIN")
                try:src.stdin.close()
                except OSError:pass
        feeder=threading.Thread(target=feed,daemon=True)
        feeder.start()
        alarm.start()
        marker=src.stdout.read(len(MAGIC))
        need(marker==MAGIC and not timed_out.is_set(),
             "SOURCE_MAGIC_STOP")
        dst.stdin.write(marker)
        count=len(marker)
        while True:
            chunk=src.stdout.read(CHUNK)
            need(type(chunk) is bytes,"SOURCE_TYPE_STOP")
            if not chunk:break
            count+=len(chunk)
            need(count<=MAX_BYTES and not timed_out.is_set(),
                 "WIRE_BOUND_STOP")
            dst.stdin.write(chunk)
        dst.stdin.close()
        need(src.wait(timeout=10)==0 and dst.wait(timeout=10)==0 and
             not timed_out.is_set(),"CHILD_EXIT_STOP")
        feeder.join(timeout=3)
        need(not feeder.is_alive() and not errors,"SOURCE_INPUT_STOP")
        reply=dst.stdout.read(MAX_REPORT+1)
        need(len(reply)<=MAX_REPORT and dst.stdout.read(1)==b"",
             "DEST_REPORT_BOUND_STOP")
        receipt=strict_receipt(reply)
        need(receipt["ciphertext_bytes"]<=count,"RECEIPT_BYTES_STOP")
        return receipt
    except (OSError,subprocess.TimeoutExpired):
        raise Stop("RELAY_IO_STOP") from None
    finally:
        alarm.cancel()
        for i in range(len(source_input)):source_input[i]=0
        for p in procs:
            if p.poll() is None:p.kill()
            p.wait()
            for name in ("stdin","stdout"):
                stream=getattr(p,name)
                if stream is not None:
                    try:stream.close()
                    except (OSError,ValueError):pass
