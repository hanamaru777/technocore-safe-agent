"""R1151 independently anchored preseed admission and binary peer contracts.

No enrolled production roots or executable SSH carrier. The owner CLI is
READINESS_STOP only. Trust is a caller-pinned object, NEVER parsed from the
source stdin packet. All real source/receiver paths remain R1128/R1129's.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
# Public machine / SSH host-key digests, not credential values. Split as in
# existing pinned tooling so the broad bare-64-hex secret heuristic is usable.
K137=("e2692bd8b11c4021e3ddaebe9e5d49e28"
      "3ac00584737bc5b7145e657f438d514")
K137_KEY=("74f7cca65d477fd7b7af0e5a17a74e404"
          "57481457ae70190e653d29e9f6d195a")
HEAD="ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
MAGIC=b"R1151S01"
PUBLIC_MAGIC=b"FLOPR189"
MAX_CONTROL=1024**2
MAX_WIRE=32*1024**2
MAX_AGE=300
PROFILE_FIELDS="version context owner_public_hex witness_public_hex excluded_key_ids source_ssh_fingerprint destination_ssh_fingerprint source_metadata_enrollment_digest"
REQUEST_FIELDS="archive_id source_approval transfer_approval metadata_proof metadata_report"


class Stop(ValueError):pass


def need(ok,code):
    if not ok:raise Stop(code)


def canonical(value):return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()
def sha(value):return hashlib.sha256(canonical(value)).hexdigest()
def digest(value):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}",value),"ENROLLMENT_PIN_STOP")
    return value
def shape(value,fields):need(type(value) is dict and set(value)==set(fields.split()),"PUBLIC_SCHEMA_STOP")


def decode(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAX_CONTROL,"PUBLIC_INPUT_BOUND_STOP")
    def pairs(rows):
        out={}
        for k,v in rows:
            need(k not in out,"DUPLICATE_FIELD_STOP");out[k]=v
        return out
    try:return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(Stop("PUBLIC_JSON_STOP")))
    except (ValueError,UnicodeError,RecursionError):raise Stop("PUBLIC_JSON_STOP") from None


def load(name):
    paths={"G":"packaging/migration/r1063_release_gates.py","P":"packaging/migration/r1128_provisional_preseed.py",
        "R":"packaging/migration/r1129_k137_ciphertext_receive.py","M":"packaging/oracle/r1139_source_preseed_metadata_readonly.py",
        "RECEIPT":"packaging/migration/r1130_ephemeral_binary_relay.py"}
    path=ROOT/paths[name]
    pins=decode((Path(__file__).with_name("r1151_source_pins.json")).read_bytes())
    raw=path.read_bytes().replace(b"\r\n",b"\n")
    need(hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==pins[paths[name]],"SOURCE_PIN_STOP")
    spec=importlib.util.spec_from_file_location("r1151_"+name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    return module


class Enrollment:
    """Independent operator-private PUBLIC config, hash supplied separately.

    Current repository enrolls NOTHING. Do not generate an approver or adopt
    keys from an SSH reply/request to populate this object.
    """
    def __init__(self,profile,expected_sha):
        need(type(profile) is dict and type(profile.get("context")) is dict and profile["context"].get("host") is not None,
             "SOURCE_IDENTITY_STOP")
        shape(profile,PROFILE_FIELDS)
        need(sha(profile)==digest(expected_sha),"ENROLLMENT_PIN_STOP")
        need(type(profile["version"]) is int and profile["version"]==1,"PUBLIC_SCHEMA_STOP")
        G=load("G")
        try:G.context_valid(profile["context"])
        except G.Deny:raise Stop("SOURCE_CONTEXT_STOP") from None
        need(profile["context"]["source_head"]==HEAD and profile["context"]["destination"]==K137 and
             profile["destination_ssh_fingerprint"]==K137_KEY,"DESTINATION_IDENTITY_STOP")
        digest(profile["source_ssh_fingerprint"]);digest(profile["source_metadata_enrollment_digest"])
        need(type(profile["excluded_key_ids"]) is list and 1<=len(profile["excluded_key_ids"])<=16,"INDEPENDENT_OWNER_ENROLLMENT_STOP")
        excluded=frozenset(digest(k) for k in profile["excluded_key_ids"])
        keys={}
        for field,role in (("owner_public_hex","owner"),("witness_public_hex","local")):
            public=bytes.fromhex(digest(profile[field]));kid=hashlib.sha256(public).hexdigest()
            need(kid not in excluded and kid not in keys,"INDEPENDENT_OWNER_ENROLLMENT_STOP")
            keys[kid]=(public,frozenset({role}))
        self.profile=decode(canonical(profile));self.pin=expected_sha
        self.G=G;self.trust=G.Trust(self.profile["context"],keys,excluded)


def selected():return [name for name,_ in load("P").SELECTED]


def source_binding(enrolled):
    P=load("P")
    return enrolled.G.sha(dict(purpose="provisional_preseed_ciphertext_only",source=enrolled.trust.context["host"],
        destination=K137,source_head=HEAD,files=selected(),max_plaintext_bytes=P.MAX_TOTAL,non_authoritative=True))


def transfer_binding(enrolled,request):
    return sha(dict(purpose="R1151_ONE_SHOT_CIPHERTEXT_ONLY",enrollment_sha256=enrolled.pin,
        archive_id=request["archive_id"],source_approval_sha256=sha(request["source_approval"]),
        metadata_proof_sha256=sha(request["metadata_proof"]),metadata_report_sha256=sha(request["metadata_report"]),
        source_binding=source_binding(enrolled),max_wire_bytes=MAX_WIRE,max_seconds=180,
        destination_name="r1129-"+request["archive_id"],recovery_purpose="INDEPENDENT_R1128_ONLY"))


def metadata_report(enrolled,report):
    shape(report,"phase result action source_head machine_sha256 files data_bytes_exported common_sqlite_epoch source_archive cutover oci_retirement")
    need(report["phase"]=="R1139" and report["result"]=="SOURCE_PRESEED_METADATA_READY" and report["action"]=="READ_ONLY" and
         report["source_head"]==HEAD and report["machine_sha256"]==enrolled.trust.context["host"] and
         type(report["data_bytes_exported"]) is int and report["data_bytes_exported"]==0 and
         report["common_sqlite_epoch"]=="NOT_PROVEN" and report["source_archive"]=="NO_GO" and
         report["cutover"]=="NO_GO" and report["oci_retirement"]=="STRICT_NO_GO","SOURCE_METADATA_STOP")
    caps={"verified-did":16384,"nonces":1048576,"signer-receipts":8388608}
    shape(report["files"]," ".join(caps))
    for name,cap in caps.items():
        row=report["files"][name];shape(row,"exists regular single_link within_limit size_bytes")
        need(all(row[k] is True for k in ("exists","regular","single_link","within_limit")) and
             type(row["size_bytes"]) is int and 0<row["size_bytes"]<=cap,"SOURCE_METADATA_STOP")


def validate(enrolled,request,*,now):
    need(isinstance(enrolled,Enrollment) and sha(enrolled.profile)==enrolled.pin,"INDEPENDENT_OWNER_ENROLLMENT_STOP")
    need(type(now) is int and now>=0,"CLOCK_STOP")
    shape(request,REQUEST_FIELDS)
    need(type(request["archive_id"]) is str and re.fullmatch(r"[0-9a-f]{32}",request["archive_id"]),"ARCHIVE_ID_STOP")
    metadata_report(enrolled,request["metadata_report"])
    need(sha(request["metadata_report"])==enrolled.profile["source_metadata_enrollment_digest"],"SOURCE_METADATA_ENROLLMENT_STOP")
    try:
        G=enrolled.G
        proof=G.verify(request["metadata_proof"],"local",enrolled.trust)
        shape(proof,"kind context archive_id report_sha256 observed_at expires_at")
        need(proof["kind"]=="R1151_INDEPENDENT_METADATA" and proof["context"]==enrolled.trust.context and
             proof["archive_id"]==request["archive_id"] and proof["report_sha256"]==sha(request["metadata_report"]) and
             type(proof["observed_at"]) is int and type(proof["expires_at"]) is int and
             proof["observed_at"]<=now<proof["expires_at"]<=proof["observed_at"]+MAX_AGE,"SOURCE_METADATA_FRESHNESS_STOP")
        G.authorization(request["source_approval"],"provisional_preseed_offhost",source_binding(enrolled),enrolled.trust,now)
        G.authorization(request["transfer_approval"],"r1151_preseed_once",transfer_binding(enrolled,request),enrolled.trust,now)
        for key in ("source_approval","transfer_approval"):
            body=request[key]["body"]
            need(body["expires_at"]<=body["approved_at"]+MAX_AGE,"OWNER_APPROVAL_EXPIRED_STOP")
    except G.Deny:raise Stop("OWNER_SIGNATURE_OR_BINDING_STOP") from None
    return {"archive_id":request["archive_id"],"binding_sha256":transfer_binding(enrolled,request)}


def pack_request(enrolled,request,recovery,*,now):
    """Exact binary stdin, no code/text interpretation and no disk staging."""
    try:
        validate(enrolled,request,now=now)
        need(type(recovery) is bytearray and 32<=len(recovery)<=1024,"INDEPENDENT_RECOVERY_STOP")
        public=canonical(request);need(len(public)<=MAX_CONTROL,"PUBLIC_INPUT_BOUND_STOP")
        return bytearray(MAGIC+struct.pack(">I",len(public))+public+struct.pack(">I",len(recovery))+recovery)
    finally:
        if type(recovery) is bytearray:recovery[:]=b"\0"*len(recovery)


def unpack_request(stream):
    def exact(n):
        out=bytearray()
        try:
            while len(out)<n:
                value=stream.read(n-len(out));need(type(value) is bytes and value,"SOURCE_CONTROL_TRUNCATED_STOP");out.extend(value)
            return out
        except Exception:
            out[:]=b"\0"*len(out)
            raise
    recovery=None
    try:
        need(exact(8)==MAGIC,"SOURCE_CONTROL_MAGIC_STOP")
        n=struct.unpack(">I",exact(4))[0];need(0<n<=MAX_CONTROL,"PUBLIC_INPUT_BOUND_STOP")
        public=decode(bytes(exact(n)))
        n=struct.unpack(">I",exact(4))[0];need(32<=n<=1024,"INDEPENDENT_RECOVERY_STOP")
        recovery=exact(n);need(stream.read(1)==b"","SOURCE_CONTROL_TRAILING_STOP")
        return public,recovery
    except Exception:
        if recovery is not None:recovery[:]=b"\0"*len(recovery)
        raise


def produce(enrolled,stream,output,*,now=None):
    """Library peer only. Independently trusted config is NOT in stdin."""
    need(isinstance(enrolled,Enrollment),"INDEPENDENT_OWNER_ENROLLMENT_STOP")
    request,recovery=unpack_request(stream)
    try:
        validate(enrolled,request,now=int(time.time()) if now is None else now)
        P=load("P")
        scope=dict(expected_machine_sha256=enrolled.trust.context["host"],destination_machine_sha256=K137,
            independent_trust=enrolled.trust,signed_owner_approval=request["source_approval"])
        # Verify the unchanged original guard before any metadata or file read.
        P._original_host(scope)
        fresh=load("M").inventory()
        need(sha(fresh)==sha(request["metadata_report"]),"SOURCE_METADATA_CHANGED_STOP")
        return P.preseed_live_to_stream(scope,bytes(recovery),output)
    finally:recovery[:]=b"\0"*len(recovery)


def receive(enrolled,request,incoming,*,now=None):
    validate(enrolled,request,now=int(time.time()) if now is None else now)
    return load("R").receive(incoming,request["archive_id"],K137)


def checked_receipt(raw,forwarded):
    result=load("RECEIPT").strict_receipt(raw)
    need(type(forwarded) is int and 8<=forwarded<=MAX_WIRE and result["ciphertext_bytes"]<=forwarded,"RECIPIENT_BYTES_STOP")
    return {**result,"phase":"R1151","ready_for_owner_call":False,"source_complete":False,"aead_verified":False}


def readiness(profile=None,expected_sha=None,request=None,*,now=None):
    code="SOURCE_IDENTITY_STOP"
    try:
        enrolled=Enrollment(profile,expected_sha)
        validate(enrolled,request,now=int(time.time()) if now is None else now)
        # A real source Trust cannot be reconstructed from untrusted stdin.
        # No independently enrolled immutable remote carrier is approved yet.
        code="INDEPENDENT_SOURCE_RUNTIME_NOT_ENROLLED"
    except Stop as error:code=str(error)
    except Exception:code="PUBLIC_ADMISSION_STOP"
    return dict(phase="R1151",result="READINESS_STOP",code=code,ready_for_owner_call=False,
        source_bytes_transferred=0,source_complete=False,aead_verified=False,activated=False,
        cutover="NO_GO",oci_retirement="STRICT_NO_GO")


def main():
    result=readiness()
    if sys.argv[1:]==["--readiness"]:
        try:
            raw=sys.stdin.buffer
            need(raw.read(8)==PUBLIC_MAGIC,"PUBLIC_INPUT_BOUND_STOP")
            size=struct.unpack(">I",raw.read(4))[0];need(0<size<=MAX_CONTROL,"PUBLIC_INPUT_BOUND_STOP")
            value=decode(raw.read(size));need(raw.read(1)==b"","PUBLIC_INPUT_BOUND_STOP")
            shape(value,"enrollment enrollment_sha256 request")
            result=readiness(value["enrollment"],value["enrollment_sha256"],value["request"])
        except Exception:result=readiness();result["code"]="PUBLIC_ADMISSION_STOP"
    print(canonical(result).decode());return 42


if __name__=="__main__":raise SystemExit(main())
