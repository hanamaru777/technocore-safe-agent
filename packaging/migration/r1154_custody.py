"""One original-DID custody envelope. No arbitrary signing or publication API.

Provider entry is Linux technocore-signer only with explicit owner/witness
approval. Only the encrypted envelope can leave that process. Recipient private
key/unattended custody enrollment remains an external owner prerequisite.
"""
from __future__ import annotations
import binascii
import contextlib
import importlib.util
import json
import logging
import os
import stat
from pathlib import Path
import sys
import time

sp=importlib.util.spec_from_file_location("r1154_hold",Path(__file__).with_name("r1154_app_hold.py"))
H=importlib.util.module_from_spec(sp);sys.modules[sp.name]=H;sp.loader.exec_module(H)
C=H.C
S=C.legacy("r1117_signer.py")
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CONFIG=Path("/etc/flop-r1154/custody-public.json")
STATE=Path("/var/lib/flop-r1154-custody")
DOMAIN=b"FLOP-R1154-ORIGINAL-DID-CUSTODY-v1\0"


def approved(authority,binding,owner,witness,*,now):
    H.shape(binding,"continuity recipient_public source_head purpose")
    C.digest(binding["recipient_public"])
    expected=S.request(authority.trust,binding["continuity"]["challenge"],binding["recipient_public"])
    H.need(binding["continuity"]==expected and binding["source_head"]==C.G.SOURCE_HEAD and
           binding["purpose"]=="R1154_ONE_ORIGINAL_DID_ENCRYPTED_CUSTODY","CUSTODY_BINDING_STOP")
    for packet,role in ((owner,"owner"),(witness,"independent")):
        H.need(authority.verify(packet,"custody",role,now)==binding,"CUSTODY_APPROVAL_STOP")


def key_for(shared,ephemeral,binding):
    return HKDF(algorithm=hashes.SHA256(),length=32,salt=bytes.fromhex(C.G.sha(binding)),
                info=DOMAIN+ephemeral).derive(shared)


def encrypt(authority,binding,owner,witness,seed,*,now):
    """Fresh dummy seed in tests; caller retains/wipes mutable secret buffer."""
    try:
        approved(authority,binding,owner,witness,now=now)
        H.need(type(seed) is bytearray and len(seed)==32,"CUSTODY_SEED_FORMAT_STOP")
        official=S.original(); key=official.Ed25519PrivateKey.from_private_bytes(bytes(seed))
        H.need(official.did_of(key)==authority.profile["source_did"],"CUSTODY_DID_STOP")
        texts=S.preimages(binding["continuity"])
        payload=bytearray(C.G.canonical(dict(seed_hex=binascii.hexlify(seed).decode(),
            say_signature=official.signature(key,texts[0]),note_signature=official.signature(key,texts[1]))))
        try:
            sender=X25519PrivateKey.generate(); ephemeral=sender.public_key().public_bytes_raw()
            shared=sender.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(binding["recipient_public"])))
            nonce=os.urandom(12)
            ciphertext=AESGCM(key_for(shared,ephemeral,binding)).encrypt(nonce,bytes(payload),DOMAIN+C.G.canonical(binding))
            return dict(version=1,binding=binding,ephemeral=ephemeral.hex(),nonce=nonce.hex(),ciphertext=ciphertext.hex())
        finally: payload[:]=b"\0"*len(payload)
    finally:
        if type(seed) is bytearray: seed[:]=b"\0"*len(seed)


@contextlib.contextmanager
def _unseal_memory(authority,binding,owner,witness,envelope,recipient,*,now):
    """DISARMED recipient process memory only. No persistence or signer RPC."""
    seed=None;plain=None;data=None
    try:
        approved(authority,binding,owner,witness,now=now)
        H.shape(envelope,"version binding ephemeral nonce ciphertext")
        H.need(type(envelope["version"]) is int and envelope["version"]==1 and envelope["binding"]==binding and
            recipient.public_key().public_bytes_raw().hex()==binding["recipient_public"],"CUSTODY_RECIPIENT_STOP")
        H.need(type(envelope["ciphertext"]) is str and len(envelope["ciphertext"])<=4096 and
            type(envelope["nonce"]) is str and len(envelope["nonce"])==24,"CUSTODY_ENVELOPE_STOP")
        shared=recipient.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(C.digest(envelope["ephemeral"]))))
        plain=bytearray(AESGCM(key_for(shared,bytes.fromhex(envelope["ephemeral"]),binding)).decrypt(
            bytes.fromhex(envelope["nonce"]),bytes.fromhex(envelope["ciphertext"]),DOMAIN+C.G.canonical(binding)))
        data=C.decode(bytes(plain));H.shape(data,"seed_hex say_signature note_signature")
        seed=bytearray(binascii.unhexlify(C.digest(data["seed_hex"])))
        official=S.original(); key=official.Ed25519PrivateKey.from_private_bytes(bytes(seed))
        H.need(official.did_of(key)==authority.profile["source_did"],"CUSTODY_DID_STOP")
        for text,sig in zip(S.preimages(binding["continuity"]),(data["say_signature"],data["note_signature"])):
            C.V.verify_did_signature(authority.profile["source_did"],sig,text)
        yield seed
    finally:
        if type(data) is dict: data["seed_hex"]=""
        if seed is not None: seed[:]=b"\0"*len(seed)
        if plain is not None: plain[:]=b"\0"*len(plain)


@contextlib.contextmanager
def unseal(authority,binding,owner,witness,envelope,recipient,*,now):
    # Production receiver path cannot expose plaintext to Windows/root/observer.
    H.need(sys.platform=="linux","CUSTODY_DEDICATED_RECIPIENT_REQUIRED")
    import pwd
    try:uid=pwd.getpwnam("technocore-signer").pw_uid
    except KeyError:raise H.Stop("CUSTODY_DEDICATED_RECIPIENT_REQUIRED") from None
    H.need(os.geteuid()==uid,"CUSTODY_DEDICATED_RECIPIENT_REQUIRED")
    with Path("/etc/machine-id").open("rb") as f: machine=f.read(129)
    H.need(0<len(machine)<=128 and C.raw_hash(machine.strip())==authority.trust.context["destination"],"CUSTODY_RECIPIENT_HOST_STOP")
    with _unseal_memory(authority,binding,owner,witness,envelope,recipient,now=now) as seed:
        yield seed


def provider_once(authority,binding,owner,witness,journal,provider,*,now):
    approved(authority,binding,owner,witness,now=now)
    H.need(type(journal) is H.J.UndoJournal and journal.latest is None,"CUSTODY_REPLAY_STOP")
    journal.save(dict(phase="CUSTODY_ATTEMPTING",binding_sha=C.G.sha(binding)))
    raw=None;seed=None
    try:
        raw=provider()
        H.need(type(raw) is bytearray and len(raw)==64,"CUSTODY_SEED_FORMAT_STOP")
        seed=bytearray(binascii.unhexlify(raw))
        envelope=encrypt(authority,binding,owner,witness,seed,now=now)
        journal.save(dict(phase="CUSTODY_SEALED_NOT_IMPORTED",binding_sha=C.G.sha(binding),envelope_sha=C.G.sha(envelope)))
        return envelope
    except Exception:
        journal.save(dict(phase="CUSTODY_UNKNOWN_NO_RETRY",binding_sha=C.G.sha(binding)))
        raise H.Stop("CUSTODY_UNKNOWN_NO_RETRY") from None
    finally:
        for value in (raw,seed):
            if type(value) is bytearray: value[:]=b"\0"*len(value)


def source_provider(authority):
    # Existing InstancePrincipals + Vault CURRENT function, unchanged. Never
    # use a CLI secret identifier, root, Windows, generic oci CLI or env dump.
    import pwd
    H.need(sys.platform=="linux" and os.geteuid()==pwd.getpwnam("technocore-signer").pw_uid,"CUSTODY_ISOLATED_USER_REQUIRED")
    with Path("/etc/machine-id").open("rb") as f: machine=f.read(129)
    H.need(0<len(machine)<=128 and C.raw_hash(machine.strip())==authority.trust.context["host"],"CUSTODY_SOURCE_STOP")
    p=H.Linux().command(["/usr/bin/git","-c","safe.directory="+C.ROOTS[0],"-C",C.ROOTS[0],"rev-parse","--verify","HEAD"])
    H.need(p.stdout==(C.G.SOURCE_HEAD+"\n").encode(),"CUSTODY_SOURCE_STOP")
    # Refuse any tracked source change before importing the original provider.
    H.Linux().command(["/usr/bin/git","-c","safe.directory="+C.ROOTS[0],"-c","core.fsmonitor=false","-C",C.ROOTS[0],"diff","--quiet","--no-ext-diff","--exit-code","HEAD","--"])
    sys.path.insert(0,C.ROOTS[0]+"/src")
    from flop_agent.oracle_signer import vault_seed
    old=logging.root.manager.disable;logging.disable(logging.CRITICAL)
    try:return vault_seed()
    finally:logging.disable(old)


def main():
    try:
        H.need(sys.platform=="linux","CUSTODY_ISOLATED_USER_REQUIRED")
        import pwd
        H.need(os.geteuid()==pwd.getpwnam("technocore-signer").pw_uid,"CUSTODY_ISOLATED_USER_REQUIRED")
        C.R.T.private_dir(STATE)
        for parent in CONFIG.parents:
            H.need(not parent.is_symlink() and parent.stat().st_uid==0 and not parent.stat().st_mode&0o022,"CUSTODY_PUBLIC_CUSTODY_STOP")
        meta=CONFIG.lstat()
        H.need(stat.S_ISREG(meta.st_mode) and meta.st_uid==0 and meta.st_nlink==1 and meta.st_size<=1048576 and
               stat.S_IMODE(meta.st_mode)==0o640,"CUSTODY_PUBLIC_CUSTODY_STOP")
        request=C.decode(CONFIG.read_bytes());H.shape(request,"enrollment enrollment_sha binding owner witness")
        authority=H.Authority(request["enrollment"],request["enrollment_sha"])
        journal=H.J.UndoJournal(H.private_dir(STATE/"records"))
        envelope=provider_once(authority,request["binding"],request["owner"],request["witness"],journal,
            lambda:source_provider(authority),now=int(time.time()))
        H.exclusive(STATE/"recipient-envelope.json",C.G.canonical(envelope))
        print('{"phase":"R1154","code":"ENCRYPTED_CUSTODY_NOT_IMPORTED","cutover":"NO_GO"}');return 0
    except Exception:
        print('{"phase":"R1154","code":"CUSTODY_STOP_NO_AUTO_RETRY","cutover":"NO_GO"}');return 42


if __name__=="__main__": raise SystemExit(main())
