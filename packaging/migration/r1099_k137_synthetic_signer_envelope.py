"""R1099: disarmed, synthetic-only rehearsal of a future isolated K137 Ed25519 signer.

This is an OFFLINE fixture exercise; no production enrollment, real seed, network,
storage, sockets, IAM, services, or K137/OCI access. It is not an operator
key-import procedure or authority to sign on behalf of the original DID.

Design: independent owner passphrase -> scrypt -> AES-256-GCM at rest; envelope
binds intended original DID, destination machine fingerprint and fixed purpose.
It is unsealed in memory only, with best-effort bytearray wipe. CPython /
cryptography may retain internal copies: NOT an HSM/security enclave.
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

ROOT = Path(__file__).resolve().parents[2]
ORIGINAL_SIGNER = ROOT / "scripts" / "sign.py"
ORIGINAL_SIGNER_BLOB = "81202baa03bff62204fa9ac34ce1f9fd969ddf67"
DOMAIN = b"FLOP-R1099-K137-SYNTHETIC-ENVELOPE-v1\x00"
KDF_N, KDF_R, KDF_P = 1 << 15, 8, 1
VERSION = 1
PURPOSE = "SYNTHETIC_ONLY_NO_PRODUCTION_SIGNING"
DID = re.compile(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")


class Stop(ValueError):
    """Fixed code only: no exceptions, filenames or seed in reports."""


def need(ok: bool, code: str):
    if not ok:
        raise Stop(code)


def _source():
    data = ORIGINAL_SIGNER.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\x00" + data).hexdigest()
    need(blob == ORIGINAL_SIGNER_BLOB, "ORIGINAL_SIGNER_PIN_STOP")
    spec = importlib.util.spec_from_file_location("r1099_synthetic_signer", ORIGINAL_SIGNER)
    need(spec is not None and spec.loader is not None, "SIGNER_IMPORT_STOP")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _json(value) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode("ascii")


def _pairs(items):
    result = {}
    for k,v in items:
        need(k not in result, "DUPLICATE_KEY_STOP")
        result[k] = v
    return result


def _key(passphrase: bytes, salt: bytes) -> bytes:
    need(type(passphrase) is bytes and 24 <= len(passphrase) <= 1024,
         "RECOVERY_INPUT_STOP")
    need(len(salt) == 16, "KDF_SALT_STOP")
    return Scrypt(salt=salt, length=32, n=KDF_N, r=KDF_R, p=KDF_P).derive(passphrase)


def _context(did: str, machine_digest: str) -> dict:
    need(type(did) is str and DID.fullmatch(did) is not None,"DID_SCHEMA_STOP")
    need(type(machine_digest) is str and SHA.fullmatch(machine_digest) is not None,
         "HOST_BINDING_STOP")
    return {"version": VERSION,"purpose": PURPOSE,"did": did,
            "machine_sha256": machine_digest}


def _seal_fixture(seed: bytearray, passphrase: bytes, did: str, host: str) -> bytes:
    """Private function for ONLY synthetic tests; no CLI and no input files."""
    need(type(seed) is bytearray and len(seed) == 32, "SEED_SHAPE_STOP")
    ctx = _context(did,host)
    salt,nonce = secrets.token_bytes(16),secrets.token_bytes(12)
    key = _key(passphrase,salt)
    ct = AESGCM(key).encrypt(nonce,bytes(seed),DOMAIN + _json(ctx))
    envelope = {"context":ctx,"salt":base64.b64encode(salt).decode("ascii"),
                "nonce":base64.b64encode(nonce).decode("ascii"),
                "ciphertext":base64.b64encode(ct).decode("ascii")}
    result=_json(envelope)
    need(len(result) <= 1024, "ENVELOPE_SIZE_STOP")
    return result


def _unseal_fixture(raw: bytes, passphrase: bytes, did: str, host: str) -> bytearray:
    """Private fixture only. Must never wire into a production service."""
    need(type(raw) is bytes and 100 <= len(raw) <= 1024, "ENVELOPE_SIZE_STOP")
    try:
        parsed=json.loads(raw,object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Stop("JSON_STOP")))
    except (ValueError, UnicodeError):
        raise Stop("ENVELOPE_SCHEMA_STOP") from None
    need(type(parsed) is dict and set(parsed)=={"context","salt","nonce","ciphertext"},
         "ENVELOPE_SCHEMA_STOP")
    need(parsed["context"]==_context(did,host),"ENVELOPE_BINDING_STOP")
    need(all(type(parsed[k]) is str and len(parsed[k]) <= 100 for k in
             ("salt","nonce","ciphertext")), "ENVELOPE_SCHEMA_STOP")
    try:
        salt=base64.b64decode(parsed["salt"],validate=True)
        nonce=base64.b64decode(parsed["nonce"],validate=True)
        ciphertext=base64.b64decode(parsed["ciphertext"],validate=True)
    except (ValueError,base64.binascii.Error):
        raise Stop("ENVELOPE_ENCODING_STOP") from None
    need(len(salt)==16 and len(nonce)==12 and len(ciphertext)==48,
         "ENVELOPE_SHAPE_STOP")
    try:
        plain=AESGCM(_key(passphrase,salt)).decrypt(nonce,ciphertext,
             DOMAIN+_json(parsed["context"]))
    except (InvalidTag, ValueError):
        raise Stop("ENVELOPE_AUTH_STOP") from None
    need(len(plain)==32, "SEED_SHAPE_STOP")
    return bytearray(plain)


def rehearsal() -> dict:
    """Uses a new RANDOM NON-PRODUCTION test key; never the original seed."""
    signer = _source()
    key=Ed25519PrivateKey.generate()
    synthetic_seed=bytearray(key.private_bytes_raw())
    host=hashlib.sha256(b"r1099-intentional-offline-fixture-host").hexdigest()
    password=b"r1099-fixture-not-owner-recovery-code"
    derived=signer.did_of(key)
    recovered=None
    try:
        sealed=_seal_fixture(synthetic_seed,password,derived,host)
        need(bytes(synthetic_seed) not in sealed,"PLAINTEXT_LEAK_STOP")
        recovered=_unseal_fixture(sealed,password,derived,host)
        other=Ed25519PrivateKey.from_private_bytes(bytes(recovered))
        need(signer.did_of(other)==derived,"DID_MISMATCH_STOP")
        # Canonical messages use the real source, including Unicode sweep.
        say_text=signer.swept("😀"*signer.MAX_TEXT_CHARS,signer.MAX_TEXT_CHARS)
        note_text=signer.swept("x"*signer.MAX_VALUE_CHARS,signer.MAX_VALUE_CHARS)
        messages=(f"r|1|{say_text}",f"n|k|1|{note_text}")
        for msg in messages:
            signature=other.sign(msg.encode("utf-8"))
            key.public_key().verify(signature,msg.encode("utf-8"))
        return {"phase":"R1099","result":"SYNTHETIC_ROUNDTRIP_ONLY",
                "source_pin":"MATCH","same_synthetic_did":True,
                "full_original_protocol_tested":True,
                "max_say_utf8_bytes":len(messages[0].encode("utf-8")),
                "max_note_utf8_bytes":len(messages[1].encode("utf-8")),
                "aes256gcm_scrypt":"PASS","network_calls":0,
                "original_seed_access":"NONE","real_enrollment":"NOT_STARTED",
                "k137_service":"NOT_DEPLOYED","source_writer_fence":"NOT_PROVEN",
                "post_finality":"NOT_PROVEN","cutover":"NO_GO",
                "oci_retirement":"STRICT_NO_GO"}
    finally:
        synthetic_seed[:]=b"\x00"*len(synthetic_seed)
        if recovered is not None:
            recovered[:]=b"\x00"*len(recovered)


def main() -> int:
    try:
        print(_json(rehearsal()).decode("ascii"))
        return 0
    except (Stop, OSError, ImportError):
        print('{"phase":"R1099","result":"STOP","code":"SYNTHETIC_TEST_STOP"}')
        return 42


if __name__=="__main__":
    sys.exit(main())
