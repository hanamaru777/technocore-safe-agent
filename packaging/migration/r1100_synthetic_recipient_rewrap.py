"""R1100: SYNTHETIC encrypted OCI->K137 recipient-binding trial. NO host access.

Never touches OCI Vault, real Ed25519 seed, DNS, SSH, CloudShell, Windows,
TradeBot, or AWS credentials. One-time X25519 encapsulation plus HKDF-SHA256
and AES-256-GCM, with explicit original Ed25519 DID, source/destination host
digests, recipient X25519 public key and simulated approval context. Purpose
domain is hard-coded SYNTHETIC so this is not a real key-export feature.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path(__file__).resolve().parents[2]
R1099 = ROOT / "packaging" / "migration" / "r1099_k137_synthetic_signer_envelope.py"
R1099_GIT_BLOB = "4d9bc0c6df221f1d87fb56a1782068157a6be253"
DOMAIN = b"FLOP-R1100-TEST-ONLY-NO-PRODUCTION-SEED-TRANSFER\x00"
PURPOSE = "SYNTHETIC_NO_LIVE_SEED"
HASH = re.compile(r"[0-9a-f]{64}\Z")


class Stop(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise Stop(code)


def _source():
    raw = R1099.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    need(blob == R1099_GIT_BLOB, "R1099_SOURCE_PIN_STOP")
    spec = importlib.util.spec_from_file_location("r1100_pinned_r1099", R1099)
    need(spec is not None and spec.loader is not None, "R1099_IMPORT_STOP")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._source()


def _json(data):
    return json.dumps(data, sort_keys=True, separators=(",",":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _pairs(items):
    out = {}
    for key, value in items:
        need(key not in out, "DUPLICATE_JSON_FIELD_STOP")
        out[key] = value
    return out


def _host(value):
    need(type(value) is str and HASH.fullmatch(value) is not None,
         "CONTEXT_DIGEST_STOP")
    return value


def _context(did, source_host, dest_host, approval, pub):
    # Strict canonical Ed25519 did:key text, plus the derived-DID comparison
    # against the pinned original signing implementation during seal/open.
    need(type(did) is str and
         re.fullmatch(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}",did) is not None,
         "CONTEXT_DID_STOP")
    need(source_host != dest_host, "SAME_HOST_STOP")
    need(type(pub) is bytes and len(pub) == 32, "RECIPIENT_KEY_STOP")
    return {"version":1,"purpose":PURPOSE,"did":did,
            "source_sha256":_host(source_host),"destination_sha256":_host(dest_host),
            "owner_approval_sha256":_host(approval),
            "recipient_sha256":hashlib.sha256(pub).hexdigest()}


def _derive(shared, salt, context):
    return HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,
                info=DOMAIN + _json(context)).derive(shared)


def _seal_fixture(seed: bytearray, recipient_public: bytes, did: str,
                  source_host: str, dest_host: str, approval: str):
    """Offline synthetic-only helper, NOT a Vault API or transfer CLI."""
    need(type(seed) is bytearray and len(seed) == 32,"TEST_SEED_SHAPE_STOP")
    need(type(recipient_public) is bytes and len(recipient_public) == 32,
         "RECIPIENT_KEY_STOP")
    original=_source()
    key=Ed25519PrivateKey.from_private_bytes(bytes(seed))
    need(original.did_of(key) == did,"ORIGINAL_DID_STOP")
    ctx=_context(did,source_host,dest_host,approval,recipient_public)
    try:
        recipient=X25519PublicKey.from_public_bytes(recipient_public)
        ephemeral=X25519PrivateKey.generate()
        ephemeral_public=ephemeral.public_key().public_bytes_raw()
        salt,nonce=secrets.token_bytes(16),secrets.token_bytes(12)
        shared=ephemeral.exchange(recipient)
        ciphertext=AESGCM(_derive(shared,salt,ctx)).encrypt(
            nonce, bytes(seed), DOMAIN+_json(ctx))
    except ValueError:
        raise Stop("TRANSFER_CRYPTO_STOP") from None
    obj={"context":ctx,"ephemeral":base64.b64encode(ephemeral_public).decode("ascii"),
         "salt":base64.b64encode(salt).decode("ascii"),
         "nonce":base64.b64encode(nonce).decode("ascii"),
         "ciphertext":base64.b64encode(ciphertext).decode("ascii")}
    blob=_json(obj)
    need(200 < len(blob) <= 1536, "ENVELOPE_BOUND_STOP")
    return blob


def _open_fixture(raw: bytes, receiver_identity: X25519PrivateKey, did: str,
                  source_host: str, dest_host: str, approval: str):
    need(type(raw) is bytes and 200 < len(raw) <= 1536,
         "ENVELOPE_BOUND_STOP")
    need(isinstance(receiver_identity,X25519PrivateKey),
         "RECIPIENT_PRIVATE_TYPE_STOP")
    try:
        obj=json.loads(raw,object_pairs_hook=_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(Stop("JSON_STOP")))
    except (ValueError,UnicodeError):
        raise Stop("ENVELOPE_SCHEMA_STOP") from None
    need(type(obj) is dict and set(obj)=={
        "context","ephemeral","salt","nonce","ciphertext"
    }, "ENVELOPE_SCHEMA_STOP")
    pub=receiver_identity.public_key().public_bytes_raw()
    ctx=_context(did,source_host,dest_host,approval,pub)
    need(ctx==obj["context"],"TRANSFER_CONTEXT_STOP")
    need(all(type(obj[k]) is str and len(obj[k]) <= 120 for k in (
        "ephemeral","salt","nonce","ciphertext"
    )), "ENVELOPE_SCHEMA_STOP")
    try:
        ephemeral=base64.b64decode(obj["ephemeral"],validate=True)
        salt=base64.b64decode(obj["salt"],validate=True)
        nonce=base64.b64decode(obj["nonce"],validate=True)
        ciphertext=base64.b64decode(obj["ciphertext"],validate=True)
    except (ValueError,base64.binascii.Error):
        raise Stop("TRANSFER_ENCODING_STOP") from None
    need(len(ephemeral)==32 and len(salt)==16 and len(nonce)==12 and
         len(ciphertext)==48, "TRANSFER_SHAPE_STOP")
    try:
        peer=X25519PublicKey.from_public_bytes(ephemeral)
        shared=receiver_identity.exchange(peer)
        seed=AESGCM(_derive(shared,salt,ctx)).decrypt(nonce,ciphertext,
                                                        DOMAIN+_json(ctx))
        need(len(seed)==32, "TEST_SEED_SHAPE_STOP")
        result=bytearray(seed)
        key=Ed25519PrivateKey.from_private_bytes(bytes(result))
        need(_source().did_of(key)==did,"RECOVERED_DID_STOP")
        return result
    except (InvalidTag,ValueError):
        raise Stop("TRANSFER_AUTH_STOP") from None


def rehearsal():
    original=_source()
    original_key=Ed25519PrivateKey.generate()
    private=bytearray(original_key.private_bytes_raw())
    dest=X25519PrivateKey.generate()
    did=original.did_of(original_key)
    src_hash=hashlib.sha256(b"fixture-oci").hexdigest()
    dst_hash=hashlib.sha256(b"fixture-k137").hexdigest()
    approval=hashlib.sha256(b"fixture-owner-auth-never-live").hexdigest()
    opened=None
    try:
        envelope=_seal_fixture(private,dest.public_key().public_bytes_raw(),
                               did,src_hash,dst_hash,approval)
        need(bytes(private) not in envelope, "PLAINTEXT_DETECTED_STOP")
        opened=_open_fixture(envelope,dest,did,src_hash,dst_hash,approval)
        signer=Ed25519PrivateKey.from_private_bytes(bytes(opened))
        for message in (f"room|1|{'😀'*4096}",f"ns|k|1|{'z'*8192}"):
            sig=signer.sign(message.encode("utf-8"))
            original_key.public_key().verify(sig,message.encode("utf-8"))
        return {"phase":"R1100","result":"SYNTHETIC_RECIPIENT_REWRAP_PASS",
                "original_seed_used":False,"production_hosts_contacted":False,
                "same_synthetic_did":True,"original_full_length_signing":True,
                "encrypted_only_custody":"SYNTHETIC_VERIFIED",
                "live_seed_export":"NOT_IMPLEMENTED",
                "aws_signer_service":"NOT_DEPLOYED",
                "writer_fence":"NOT_PROVEN","post_finality":"NOT_PROVEN",
                "cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}
    finally:
        private[:]=b"\x00"*len(private)
        if opened is not None:
            opened[:]=b"\x00"*len(opened)


if __name__=="__main__":
    try:
        print(_json(rehearsal()).decode("ascii"))
    except (Stop, OSError, ImportError):
        print('{"phase":"R1100","result":"STOP","code":"SYNTHETIC_REWRAP_STOP"}')
        sys.exit(42)
