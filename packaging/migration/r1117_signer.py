"""Disarmed, public-proof isolated signer admission; synthetic custody trial only.

No Vault/provider, private-key input, arbitrary signing RPC, network or live
enrollment exists. R1099/R1100 retain their explicit SYNTHETIC purposes.
"""
from __future__ import annotations

import hashlib
import importlib.util
import base64
import os
import stat
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("flop_r1107_contract", Path(__file__).with_name("r1107_contract.py"))
C = sys.modules.get(spec.name)
if C is None:
    C = importlib.util.module_from_spec(spec); sys.modules[spec.name] = C; spec.loader.exec_module(C)

PIN = "81202baa03bff62204fa9ac34ce1f9fd969ddf67"
SIGNER = Path(__file__).resolve().parents[2] / "scripts/sign.py"
SYNTHETIC = "SYNTHETIC_NO_LIVE_CUSTODY"


def original():
    # Same official blob, CRLF/LF transport equivalence ONLY. No new protocol.
    data = SIGNER.read_bytes().replace(b"\r\n", b"\n")
    C.need(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == PIN,
           "G3_SIGNER_PIN_STOP")
    module = type(sys)("r1117_official_public_protocol")
    exec(compile(data, str(SIGNER), "exec"), module.__dict__)
    return module


def fixture_crypto(name, pin):
    """Verify frozen fixture code BEFORE execution, canonical LF only."""
    path = Path(__file__).with_name(name)
    data = path.read_bytes().replace(b"\r\n", b"\n")
    C.need(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == pin,
           "G3_FIXTURE_SOURCE_PIN_STOP")
    module = type(sys)("r1117_private_" + path.stem)
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


def request(enrollment, challenge, recipient_hex):
    C.digest(challenge); C.digest(recipient_hex)
    return {"challenge": challenge, "recipient_hex": recipient_hex,
            "source": enrollment.context["host"], "destination": enrollment.context["destination"],
            "did_digest": enrollment.context["did"], "signer_blob": PIN,
            "purpose": "R1117_DISARMED_CONTINUITY_ONLY"}


def preimages(binding):
    C.shape(binding, "challenge recipient_hex source destination did_digest signer_blob purpose")
    for k in ("challenge", "recipient_hex", "source", "destination", "did_digest"): C.digest(binding[k])
    C.need(binding["source"] != binding["destination"] and binding["signer_blob"] == PIN and
           binding["purpose"] == "R1117_DISARMED_CONTINUITY_ONLY", "G3_BINDING_STOP")
    official = original()
    marker = "R1117-DISARMED-" + C.G.sha(binding)
    say = (marker + "😀" * official.MAX_TEXT_CHARS)[:official.MAX_TEXT_CHARS]
    note = (marker + "😀" * official.MAX_VALUE_CHARS)[:official.MAX_VALUE_CHARS]
    C.need(say == official.swept(say, official.MAX_TEXT_CHARS) and
           note == official.swept(note, official.MAX_VALUE_CHARS), "G3_CANONICAL_STOP")
    # Fixed non-publication proof lane; no caller-supplied room/text/nonce.
    return ("r1117-custody-proof|1|" + say, "r1117|continuity|1|" + note)


def verify_proof(enrollment, expected, owner, recipient, proof, *, now, consume=None):
    """Public-only proof verification. consume must atomically reject replay.

    Verification does NOT establish real key custody or authorize any post.
    It binds exactly one independently enrolled recipient and fresh challenge.
    """
    C.need(expected == request(enrollment, expected["challenge"], expected["recipient_hex"]), "G3_BINDING_STOP")
    for packet, role in ((owner, "owner"), (recipient, "identity")):
        C.need(enrollment.verify(packet, "r1117-custody", role, now) == expected, "G3_RECIPIENT_STOP")
    C.shape(proof, "binding did say_signature note_signature")
    C.need(proof["binding"] == expected and C.raw_hash(proof["did"].encode()) == enrollment.context["did"], "G3_DID_STOP")
    try:
        for text, signature in zip(preimages(expected), (proof["say_signature"], proof["note_signature"])):
            C.need(type(signature) is str and C.V.SIG_RE.fullmatch(signature) and
                   base64.urlsafe_b64encode(base64.urlsafe_b64decode(signature + "==")).rstrip(b"=").decode() == signature,
                   "G3_SIGNATURE_STOP")
            C.V.verify_did_signature(proof["did"], signature, text)
    except ValueError:
        raise C.Stop("G3_SIGNATURE_STOP") from None
    if consume is not None:
        C.need(consume(C.G.sha(expected)) is True, "G3_REPLAY_STOP")
    return {"G3": "PUBLIC_CONTINUITY_VERIFIED_NOT_CUSTODY", "binding_digest": C.G.sha(expected),
            "proof_digest": C.G.sha(proof), "real_custody": "NOT_PROVEN", "post": "DISABLED"}


def synthetic_custody_trial(seed, receiver, password, enrollment, expected, owner, recipient,
                            consume, *, now):
    """Library-only test integration. Never wire fixture crypto to real import.

    Uses the unchanged R1100 recipient wrapper then unchanged R1099 at-rest
    envelope, with the ORIGINAL synthetic domain/purpose on both layers.
    Plaintext is bytearray-wiped best-effort; Python internal copies persist.
    """
    wrap = fixture_crypto("r1100_synthetic_recipient_rewrap.py", "5d7fa0e26381cea7b091201c3a7b1ffba5f34b45")
    vault = fixture_crypto("r1099_k137_synthetic_signer_envelope.py", "4d9bc0c6df221f1d87fb56a1782068157a6be253")
    # Versioned canonical-LF protocol loader only; frozen source files unchanged.
    wrap._source = vault._source = original
    official = original(); opened = recovered = None
    try:
        C.need(type(seed) is bytearray and len(seed) == 32, "G3_TRIAL_INPUT_STOP")
        key = vault.Ed25519PrivateKey.from_private_bytes(bytes(seed))
        did = official.did_of(key)
        C.need(C.raw_hash(did.encode()) == enrollment.context["did"] and
               receiver.public_key().public_bytes_raw().hex() == expected["recipient_hex"], "G3_DID_STOP")
        for packet, role in ((owner, "owner"), (recipient, "identity")):
            C.need(enrollment.verify(packet, "r1117-custody", role, now) == expected, "G3_RECIPIENT_STOP")
        # Burn admission before unseal; crash/failure requires a NEW explicitly
        # approved challenge, never an automatic retry with the same challenge.
        C.need(consume(C.G.sha(expected)) is True, "G3_REPLAY_STOP")
        sealed = wrap._seal_fixture(seed, bytes.fromhex(expected["recipient_hex"]), did,
            expected["source"], expected["destination"], C.G.sha(owner))
        opened = wrap._open_fixture(sealed, receiver, did, expected["source"], expected["destination"], C.G.sha(owner))
        at_rest = vault._seal_fixture(opened, password, did, expected["destination"])
        recovered = vault._unseal_fixture(at_rest, password, did, expected["destination"])
        signer = vault.Ed25519PrivateKey.from_private_bytes(bytes(recovered))
        C.need(official.did_of(signer) == did, "G3_DID_STOP")
        say, note = preimages(expected)
        proof = {"binding": expected, "did": did, "say_signature": official.signature(signer, say),
                 "note_signature": official.signature(signer, note)}
        checked = verify_proof(enrollment, expected, owner, recipient, proof, now=now)
        return proof, {**checked, "mode": SYNTHETIC, "live_import": "NOT_IMPLEMENTED"}
    finally:
        for value in (seed, opened, recovered):
            if type(value) is bytearray: value[:] = b"\0" * len(value)


def read_public_admission(path=Path("/etc/flop-r1117/public-admission.json")):
    """Fixed root-enrolled PUBLIC evidence only, never a key or unlock file."""
    C.need(os.name == "posix", "G3_CUSTODY_STOP")
    for ancestor in (path, *path.parents): C.need(not ancestor.is_symlink(), "G3_CUSTODY_STOP")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(descriptor)
        C.need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and
               stat.S_IMODE(s.st_mode) == 0o640 and s.st_size <= 1024**2, "G3_CUSTODY_STOP")
        with os.fdopen(descriptor, "rb", closefd=False) as stream: return C.decode(stream.read(1024**2 + 1))
    finally:
        os.close(descriptor)


def main():
    """Deploy-reviewable isolated PUBLIC verifier only; never an unseal daemon."""
    try:
        C.need(sys.argv[1:] == ["--disarmed-public-check"], "G3_DISARMED_ONLY")
        control = read_public_admission()
        C.shape(control, "enrollment binding owner recipient proof")
        import time
        verified = verify_proof(C.Enrollment(control["enrollment"]), control["binding"], control["owner"],
            control["recipient"], control["proof"], now=int(time.time()))
        print(C.G.canonical({**verified, "phase": "R1117", "service": "DISARMED_PUBLIC_CHECK_ONLY"}).decode())
        return 0
    except Exception:
        print('{"phase":"R1117","G3":"NO_GO","reason":"G3_ADMISSION_STOP","post":"DISABLED"}')
        return 42


if __name__ == "__main__":
    raise SystemExit(main())
