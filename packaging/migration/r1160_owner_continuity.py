"""Same approval identity, separately signed host custody; offline only.

OLD seals bytes without unsealing the owner key. NEW proves the original key
after authenticated decryption. No rotation, DID provider or network client.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys
import time

from cryptography.hazmat.primitives.asymmetric import ed25519,rsa,padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

ROOT_PINS=dict(public_sha=("bf80a8f60cbb0b15e268602a758f7aaa" "b7b4b9bdcc549f43a4c97e200d2171c7"),
    old_control=("1c9bd366b0bd87e01a542b8da3eb873d" "daa08791c162d67069bbf5f6b55c19c1"),
    oracle_sha=("8dae15bf339e54ece1a23b7c78fdcb43a" "5adb0534b01064fe44d5713c9d96301"))
RECIPIENT_DOMAIN=b"FLOP-R1160-RECIPIENT-POSSESSION-v1\0"
BINDING_DOMAIN=b"FLOP-R1160-SAME-OWNER-HOST-v1\0"
ARTIFACTS=("public.json","approval.pem.enc","oracle-v2.enc","k137.pem")
CAPS=(377,302,672,32768)
CONSENT="PRESERVE_SAME_OWNER_NO_INIT_NO_ROTATION"
ALGORITHM="RSA3072-OAEP-SHA256-AES256GCM"


def need(ok,code="R1160_SCHEMA_STOP"):
    if not ok:raise ValueError(code)
def shape(value,names):need(type(value) is dict and set(value)==set(names.split()))
def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()
def digest(value):need(type(value) is str and re.fullmatch(r"[a-f0-9]{64}",value));return value
def decode(raw):
    need(0<len(raw)<=65536)
    def pairs(items):
        result={}
        for k,v in items:need(k not in result);result[k]=v
        return result
    return json.loads(bytes(raw).decode("utf-8","strict"),object_pairs_hook=pairs,parse_constant=lambda _:need(False))


def machine_identity():
    need(os.name=="nt","R1160_WINDOWS_REQUIRED")
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Cryptography",0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY) as key:
        value,kind=winreg.QueryValueEx(key,"MachineGuid")
    need(kind==winreg.REG_SZ and re.fullmatch(r"[a-fA-F0-9-]{32,36}",value),"R1160_MACHINE_UNVERIFIED")
    return sha(value.lower().encode())


def public_rsa(blob):
    need(type(blob) is bytes and 408<=len(blob)<=412,"R1160_RECIPIENT_INVALID")
    magic,bits,e_len,n_len,p,q=struct.unpack("<6I",blob[:24])
    need((magic,bits,e_len,n_len,p,q)==(0x31415352,3072,3,384,0,0) and len(blob)==24+e_len+n_len,"R1160_RECIPIENT_INVALID")
    e=int.from_bytes(blob[24:27],"big");n=int.from_bytes(blob[27:],"big")
    need(e==65537 and n.bit_length()==3072,"R1160_RECIPIENT_INVALID")
    return rsa.RSAPublicNumbers(e,n).public_key()


def recipient_body(value,now):
    shape(value,"version kind transfer_id new_control new_machine algorithm public_blob created_at expires_at")
    need(type(value["version"]) is int and value["version"]==1 and value["kind"]=="R1160_LOCAL_RECIPIENT" and value["algorithm"]==ALGORITHM)
    need(re.fullmatch(r"[a-f0-9]{32}",value["transfer_id"]))
    for k in ("new_control","new_machine"):digest(value[k])
    need(type(value["created_at"]) is int and type(value["expires_at"]) is int and 0<value["expires_at"]-value["created_at"]<=86400)
    if now is not None:need(value["created_at"]<=now+5 and now<value["expires_at"],"R1160_RECIPIENT_EXPIRED")
    raw=base64.b64decode(value["public_blob"],validate=True);key=public_rsa(raw)
    return key,sha(raw)


def verify_recipient(packet,expected_sha,*,now):
    shape(packet,"body signature");need(sha(canonical(packet))==digest(expected_sha),"R1160_RECIPIENT_MISMATCH")
    key,fingerprint=recipient_body(packet["body"],now)
    signature=base64.b64decode(packet["signature"],validate=True)
    try:key.verify(signature,RECIPIENT_DOMAIN+canonical(packet["body"]),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())
    except Exception:raise ValueError("R1160_RECIPIENT_PROOF_STOP") from None
    return key,fingerprint


def validate_plan(plan,recipient,*,now,pins=ROOT_PINS):
    shape(plan,"version transfer_id recipient_sha256 original_public_sha256 encrypted_approval_sha256 oracle_cipher_sha256 k137_sha256 source_control source_clearance_ref source_clearance_sha256 consent expires_at")
    need(type(plan["version"]) is int and plan["version"]==1 and plan["consent"]==CONSENT)
    for k in ("recipient_sha256","original_public_sha256","encrypted_approval_sha256","oracle_cipher_sha256","k137_sha256","source_control","source_clearance_sha256"):digest(plan[k])
    need(plan["original_public_sha256"]==pins["public_sha"] and plan["source_control"]==pins["old_control"] and
        plan["oracle_cipher_sha256"]==pins["oracle_sha"],"R1160_ORIGINAL_ROOT_MISMATCH")
    need(type(plan["expires_at"]) is int and (now is None or now<plan["expires_at"]<=now+86400),"R1160_PLAN_EXPIRED")
    need(type(plan["source_clearance_ref"]) is str and len(plan["source_clearance_ref"])<=180 and
        re.fullmatch(r"https://github\.com/hanamaru777/technocore-safe-agent/issues/[0-9]+#issuecomment-[0-9]+",plan["source_clearance_ref"]),"R1160_SOURCE_CLEARANCE_REQUIRED")
    key,fingerprint=verify_recipient(recipient,plan["recipient_sha256"],now=now)
    need(plan["expires_at"]<=recipient["body"]["expires_at"],"R1160_PLAN_EXPIRED")
    need(plan["transfer_id"]==recipient["body"]["transfer_id"] and plan["source_control"]!=recipient["body"]["new_control"],"R1160_CONTROL_MISMATCH")
    return key,fingerprint


def verify_files(files,plan,M,*,pins=ROOT_PINS):
    need(type(files) is dict and set(files)==set(ARTIFACTS),"R1160_FILE_SET_STOP")
    expected=(plan["original_public_sha256"],plan["encrypted_approval_sha256"],plan["oracle_cipher_sha256"],plan["k137_sha256"])
    for i,name in enumerate(ARTIFACTS):
        raw=files[name];need(type(raw) is bytearray and 0<len(raw)<=CAPS[i],"R1160_FILE_BOUND_STOP")
        need(sha(raw)==expected[i],"R1160_ORIGINAL_FILE_MISMATCH")
    need(len(files["public.json"])==377 and len(files["approval.pem.enc"])==302 and len(files["oracle-v2.enc"])==672,"R1160_FILE_BOUND_STOP")
    public=decode(files["public.json"]);M.validate_descriptor(public)
    need(public["body"]["role"]=="owner" and public["body"]["control"]==pins["old_control"],"R1160_ORIGINAL_ROOT_MISMATCH")
    return public


def pack_files(files):
    data=bytearray(struct.pack(">I",len(ARTIFACTS)))
    for name in ARTIFACTS:data.extend(struct.pack(">I",len(files[name])));data.extend(files[name])
    return data


def unpack_files(data):
    need(len(data)>=4);count=struct.unpack(">I",data[:4])[0];need(count==4,"R1160_FILE_SET_STOP")
    offset=4;files={}
    try:
        for i,name in enumerate(ARTIFACTS):
            need(offset+4<=len(data));n=struct.unpack(">I",data[offset:offset+4])[0];offset+=4
            need(0<n<=CAPS[i] and offset+n<=len(data),"R1160_PARTIAL_INPUT_STOP")
            files[name]=bytearray(memoryview(data)[offset:offset+n]);offset+=n
        need(offset==len(data),"R1160_FILE_SET_STOP");return files
    except Exception:
        for raw in files.values():raw[:]=b"\0"*len(raw)
        raise


def seal(files,plan,recipient,M,*,now,source_control,pins=ROOT_PINS):
    """No owner passphrase/private-key loader on OLD. Only public RSA here."""
    aes=None;plain=None
    try:
        key,fingerprint=validate_plan(plan,recipient,now=now,pins=pins)
        need(source_control==pins["old_control"],"R1160_SOURCE_ACCOUNT_STOP")
        verify_files(files,plan,M,pins=pins)
        header=dict(version=1,kind="R1160_ENCRYPTED_CREDENTIALS_ONLY",plan_sha=sha(canonical(plan)),recipient_sha=plan["recipient_sha256"],
            recipient_fingerprint=fingerprint,transfer_id=plan["transfer_id"])
        plain=pack_files(files);aes=bytearray(os.urandom(32));nonce=os.urandom(12)
        ciphertext=AESGCM(aes).encrypt(nonce,plain,canonical(header))
        wrapped=key.encrypt(bytes(aes),padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        return dict(header=header,wrapped_key=base64.b64encode(wrapped).decode(),nonce=base64.b64encode(nonce).decode(),ciphertext=base64.b64encode(ciphertext).decode())
    finally:
        for b in (aes,plain,*files.values()):
            if type(b) is bytearray:b[:]=b"\0"*len(b)


def inspect_envelope(envelope,plan,recipient,*,now,pins=ROOT_PINS):
    key,fingerprint=validate_plan(plan,recipient,now=now,pins=pins)
    shape(envelope,"header wrapped_key nonce ciphertext");h=envelope["header"]
    need(h==dict(version=1,kind="R1160_ENCRYPTED_CREDENTIALS_ONLY",plan_sha=sha(canonical(plan)),recipient_sha=plan["recipient_sha256"],
        recipient_fingerprint=fingerprint,transfer_id=plan["transfer_id"]),"R1160_ENVELOPE_BINDING_STOP")
    wrapped=base64.b64decode(envelope["wrapped_key"],validate=True);nonce=base64.b64decode(envelope["nonce"],validate=True)
    cipher=base64.b64decode(envelope["ciphertext"],validate=True)
    need(len(wrapped)==384 and len(nonce)==12 and 16<len(cipher)<=40000,"R1160_ENVELOPE_BOUND_STOP")
    return wrapped,nonce,cipher


def bind_import(envelope,plan,recipient,aes,password,M,*,now,control,machine,pins=ROOT_PINS):
    """NEW only. No plaintext owner serialization, rotation or OLD signing."""
    plain=None;files={};key=None
    try:
        wrapped,nonce,cipher=inspect_envelope(envelope,plan,recipient,now=now,pins=pins)
        need(control==recipient["body"]["new_control"] and machine==recipient["body"]["new_machine"],"R1160_DESTINATION_ACCOUNT_STOP")
        need(type(aes) is bytearray and len(aes)==32 and type(password) is bytearray and 32<=len(password)<=1024)
        try:plain=bytearray(AESGCM(aes).decrypt(nonce,cipher,canonical(envelope["header"])))
        except Exception:raise ValueError("R1160_ENVELOPE_AUTH_STOP") from None
        files=unpack_files(plain);public=verify_files(files,plan,M,pins=pins)
        key=load_pem_private_key(files["approval.pem.enc"],bytes(password))
        need(isinstance(key,ed25519.Ed25519PrivateKey) and key.public_key().public_bytes_raw().hex()==public["body"]["public_hex"],"R1160_SAME_OWNER_KEY_MISMATCH")
        body=dict(version=1,kind="R1160_SAME_OWNER_NEW_HOST",consent=CONSENT,owner_key_id=sha(key.public_key().public_bytes_raw()),
            original_public_sha=plan["original_public_sha256"],encrypted_approval_sha=plan["encrypted_approval_sha256"],old_control=pins["old_control"],
            new_control=control,new_machine=machine,recipient_sha=plan["recipient_sha256"],plan_sha=sha(canonical(plan)),envelope_sha=sha(canonical(envelope)),transfer_id=plan["transfer_id"])
        binding=dict(body=body,signature=key.sign(BINDING_DOMAIN+canonical(body)).hex())
        # Only already-encrypted material may be persisted. K137 plaintext is
        # never written on NEW; its original bytes remain inside this envelope.
        retained={name:bytearray(files[name]) for name in ("public.json","approval.pem.enc","oracle-v2.enc")}
        return binding,retained
    finally:
        key=None
        for b in (aes,password,plain,*files.values()):
            if type(b) is bytearray:b[:]=b"\0"*len(b)


def verify_binding(public_raw,binding,plan,recipient,envelope_sha,M,*,control,machine,pins=ROOT_PINS):
    need(sha(public_raw)==pins["public_sha"],"R1160_ORIGINAL_ROOT_MISMATCH")
    public=decode(public_raw);M.validate_descriptor(public)
    validate_plan(plan,recipient,now=None,pins=pins)
    shape(binding,"body signature");b=binding["body"]
    expected=dict(version=1,kind="R1160_SAME_OWNER_NEW_HOST",consent=CONSENT,owner_key_id=sha(bytes.fromhex(public["body"]["public_hex"])),
        original_public_sha=pins["public_sha"],encrypted_approval_sha=plan["encrypted_approval_sha256"],old_control=pins["old_control"],
        new_control=control,new_machine=machine,recipient_sha=plan["recipient_sha256"],plan_sha=sha(canonical(plan)),envelope_sha=envelope_sha,transfer_id=plan["transfer_id"])
    need(b==expected and public["body"]["control"]==pins["old_control"] and control==recipient["body"]["new_control"] and
        machine==recipient["body"]["new_machine"],"R1160_HOST_BINDING_STOP")
    try:ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public["body"]["public_hex"])).verify(bytes.fromhex(binding["signature"]),BINDING_DOMAIN+canonical(b))
    except Exception:raise ValueError("R1160_OWNER_SIGNATURE_STOP") from None
    return public


def verify_local(folder,public,M,*,control):
    # PUBLIC continuity evidence only. No approval ciphertext/private-key read.
    names=("public.json","host-binding.json","custody-plan.json","custody-recipient.json","custody-receipt.json")
    for n in names:M.secure_path(folder/n)
    raw=(folder/"public.json").read_bytes();need(len(raw)==377,"R1160_ORIGINAL_ROOT_MISMATCH")
    values={n:M.read_public(folder/n) for n in names[1:]}
    receipt=values["custody-receipt.json"];shape(receipt,"phase envelope_sha plan_sha binding_sha")
    need(receipt["phase"]=="IMPORTED_SAME_OWNER_NO_PRODUCTION_AUTHORITY" and receipt["plan_sha"]==sha(canonical(values["custody-plan.json"])) and
        receipt["binding_sha"]==sha(canonical(values["host-binding.json"])),"R1160_IMPORT_NOT_COMMITTED")
    result=verify_binding(raw,values["host-binding.json"],values["custody-plan.json"],values["custody-recipient.json"],digest(receipt["envelope_sha"]),M,
        control=control,machine=machine_identity())
    need(result==public,"R1160_ORIGINAL_ROOT_MISMATCH")
    return values["host-binding.json"]["body"]["encrypted_approval_sha"]


def commit_import(root,binding,retained,plan,recipient,envelope,M,*,control,machine,move=os.rename):
    """All temporary/committed files are encrypted or public. No raw K137.

    Production is Windows: rename to a nonexisting directory is atomic and
    refuses replacement. Partial/unknown state has no automatic retry.
    """
    target=M.store_path();stage=root/"owner-stage"
    M.secure_path(root,directory=True)
    need(not target.exists() and not target.is_symlink() and not stage.exists(),"R1160_DESTINATION_EXISTS")
    stage.mkdir(mode=0o700);M.protect_file(stage);M.secure_path(stage,directory=True)
    try:
        verify_binding(retained["public.json"],binding,plan,recipient,sha(canonical(envelope)),M,control=control,machine=machine)
        M.local_write(stage/"public.json",retained["public.json"])
        M.local_write(stage/"approval.pem.enc",retained["approval.pem.enc"])
        for n,v in (("host-binding.json",binding),("custody-plan.json",plan),("custody-recipient.json",recipient)):
            M.local_write(stage/n,canonical(v))
        receipt=dict(phase="IMPORTED_SAME_OWNER_NO_PRODUCTION_AUTHORITY",envelope_sha=sha(canonical(envelope)),plan_sha=sha(canonical(plan)),binding_sha=sha(canonical(binding)))
        M.local_write(stage/"custody-receipt.json",canonical(receipt))
        M.local_write(root/"credentials.sealed.json",canonical(envelope))
        need(sha((stage/"public.json").read_bytes())==plan["original_public_sha256"] and
            sha((stage/"approval.pem.enc").read_bytes())==plan["encrypted_approval_sha256"],"R1160_PARTIAL_WRITE_STOP")
        for path in stage.iterdir():M.secure_path(path)
        need(not target.exists() and stage.stat().st_dev==target.parent.stat().st_dev,"R1160_DESTINATION_EXISTS")
        move(stage,target)
    except Exception:
        # Keep a private forensic marker; remove ONLY our enumerated new stage
        # files. Never delete/replace the old store or a committed destination.
        if stage.exists():
            try:
                for name in ("public.json","approval.pem.enc","host-binding.json","custody-plan.json","custody-recipient.json","custody-receipt.json"):
                    p=stage/name
                    if p.exists():M.secure_path(p);p.unlink()
                stage.rmdir()
            except Exception:raise ValueError("R1160_CLEANUP_UNVERIFIED") from None
        raise ValueError("R1160_IMPORT_UNKNOWN_NO_RETRY") from None
    finally:
        for b in retained.values():b[:]=b"\0"*len(b)
    return receipt


def private_frame(stream,size):
    need(0<=size<=1048576);value=bytearray(size);offset=0
    try:
        while offset<size:
            n=stream.readinto(memoryview(value)[offset:]);need(n and n<=size-offset,"R1160_PARTIAL_INPUT_STOP");offset+=n
    except Exception:
        value[:]=b"\0"*len(value);raise
    return value


def packet_input(stream):
    need(stream.read(8)==b"FLOPR189")
    n=stream.read(4);need(len(n)==4);raw=private_frame(stream,int.from_bytes(n,"big"))
    try:
        need(len(raw)>=4);length=int.from_bytes(raw[:4],"big");need(0<length<=65536 and length+4<=len(raw))
        return decode(raw[4:4+length]),bytearray(raw[4+length:])
    finally:raw[:]=b"\0"*len(raw)


def main():
    password=bytearray();data=bytearray();retained={}
    try:
        need(sys.argv[1:]==["--pipe"],"R1160_PS51_REQUIRED")
        meta,data=packet_input(sys.stdin.buffer);op=meta["operation"]
        need(op in ("recipient-body","save-recipient","check-source","seal","inspect","import","publish-envelope"))
        if op=="import":
            n=sys.stdin.buffer.read(4);need(len(n)==4);password=private_frame(sys.stdin.buffer,int.from_bytes(n,"big"))
        need(sys.stdin.buffer.read(1)==b"","R1160_PARTIAL_INPUT_STOP")
        sp=importlib.util.spec_from_file_location("r1160_existing_approval",Path(__file__).with_name("r1157_operator.py"))
        M=importlib.util.module_from_spec(sp);sys.modules[sp.name]=M;sp.loader.exec_module(M)
        now=int(time.time());control=M.control_identity()
        if op=="recipient-body":
            shape(meta,"operation transfer_id public_blob");need(not data and control!=ROOT_PINS["old_control"],"R1160_DESTINATION_ACCOUNT_STOP")
            body=dict(version=1,kind="R1160_LOCAL_RECIPIENT",transfer_id=meta["transfer_id"],new_control=control,new_machine=machine_identity(),
                algorithm=ALGORITHM,public_blob=meta["public_blob"],created_at=now,expires_at=now+86400)
            recipient_body(body,now);sys.stdout.buffer.write(canonical(body));return 0
        if op=="save-recipient":
            shape(meta,"operation recipient_b64 output");need(not data)
            recipient=decode(base64.b64decode(meta["recipient_b64"],validate=True));verify_recipient(recipient,sha(canonical(recipient)),now=now)
            need(recipient["body"]["new_control"]==control and recipient["body"]["new_machine"]==machine_identity(),"R1160_DESTINATION_ACCOUNT_STOP")
            M.output(Path(meta["output"]),"recipient.json",recipient)
            result=dict(code="R1160_RECIPIENT_PUBLIC_ONLY",recipient_sha=sha(canonical(recipient)),cutover="NO_GO")
        else:
            names="operation plan_b64 recipient_b64"+(" source_public_b64" if op=="check-source" else "")
            if op in ("inspect","import","publish-envelope"):names+=" envelope_b64 envelope_sha256"
            if op in ("import","publish-envelope"):names+=" output"
            shape(meta,names)
            plan=decode(base64.b64decode(meta["plan_b64"],validate=True));recipient=decode(base64.b64decode(meta["recipient_b64"],validate=True))
            key,fingerprint=validate_plan(plan,recipient,now=now)
            if op=="check-source":
                need(not data and control==ROOT_PINS["old_control"],"R1160_SOURCE_ACCOUNT_STOP")
                raw=base64.b64decode(meta["source_public_b64"],validate=True)
                need(sha(raw)==ROOT_PINS["public_sha"] and len(raw)==377,"R1160_ORIGINAL_ROOT_MISMATCH")
                original=decode(raw);M.validate_descriptor(original)
                need(original["body"]["control"]==control and original["body"]["role"]=="owner","R1160_ORIGINAL_ROOT_MISMATCH")
                result=dict(code="R1160_REVIEWED_SOURCE_PLAN_ONLY",cutover="NO_GO")
            elif op=="seal":
                files=unpack_files(data)
                envelope=seal(files,plan,recipient,M,now=now,source_control=control)
                sys.stdout.buffer.write(canonical(envelope));return 0
            else:
                envelope_raw=base64.b64decode(meta["envelope_b64"],validate=True)
                need(sha(envelope_raw)==digest(meta["envelope_sha256"]),"R1160_ENVELOPE_HASH_STOP")
                envelope=decode(envelope_raw);wrapped,nonce,cipher=inspect_envelope(envelope,plan,recipient,now=now)
                if op=="publish-envelope":
                    need(control==ROOT_PINS["old_control"] and not data,"R1160_SOURCE_ACCOUNT_STOP")
                    M.output(Path(meta["output"]),"credentials.sealed.json",envelope)
                    result=dict(code="R1160_ENCRYPTED_EXPORT_ONLY",envelope_sha=sha(canonical(envelope)),cutover="NO_GO")
                else:
                    machine=machine_identity()
                    need(control==recipient["body"]["new_control"] and machine==recipient["body"]["new_machine"],"R1160_DESTINATION_ACCOUNT_STOP")
                    need(not M.store_path().exists(),"R1160_DESTINATION_EXISTS")
                    if op=="inspect":
                        need(not data);result=dict(code="R1160_RECIPIENT_REQUIRED",wrapped_key=base64.b64encode(wrapped).decode(),
                            recipient_fingerprint=fingerprint,transfer_id=plan["transfer_id"],cutover="NO_GO")
                    else:
                        need(os.name=="nt","R1160_WINDOWS_REQUIRED")
                        binding,retained=bind_import(envelope,plan,recipient,data,password,M,now=now,control=control,machine=machine)
                        commit_import(Path(meta["output"]),binding,retained,plan,recipient,envelope,M,control=control,machine=machine)
                        result=dict(code="R1160_SAME_OWNER_IMPORTED",original_public_sha=ROOT_PINS["public_sha"],
                            credentials="RECIPIENT_ENCRYPTED_CUSTODY",cutover="NO_GO",oracle_retirement="STRICT_NO_GO")
        sys.stdout.buffer.write(canonical(result));return 0
    except Exception as error:
        allowed={"R1160_SOURCE_ACCOUNT_STOP","R1160_DESTINATION_ACCOUNT_STOP","R1160_ORIGINAL_ROOT_MISMATCH","R1160_ORIGINAL_FILE_MISMATCH",
            "R1160_RECIPIENT_MISMATCH","R1160_RECIPIENT_EXPIRED","R1160_ENVELOPE_HASH_STOP","R1160_ENVELOPE_AUTH_STOP",
            "R1160_SAME_OWNER_KEY_MISMATCH","R1160_DESTINATION_EXISTS","R1160_CLEANUP_UNVERIFIED","R1160_IMPORT_UNKNOWN_NO_RETRY",
            "R1160_SOURCE_CLEARANCE_REQUIRED","R1160_PARTIAL_WRITE_STOP"}
        code=str(error) if type(error) is ValueError and str(error) in allowed else "R1160_STOP_NO_RETRY"
        print(json.dumps(dict(code=code,cutover="NO_GO",oracle_retirement="STRICT_NO_GO")));return 42
    finally:
        for b in (data,password,*retained.values()):b[:]=b"\0"*len(b)


if __name__=="__main__":raise SystemExit(main())
