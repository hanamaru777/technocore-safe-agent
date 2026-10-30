"""Versioned R1107 public evidence contracts. No production trust is bundled."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path


def legacy(name):
    spec = importlib.util.spec_from_file_location("r1107_" + name[:-3], Path(__file__).with_name(name))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


G = legacy("r1063_release_gates.py")
R = legacy("r1089_migration.py")
U = legacy("r1104_g1g4_coverage_consistency.py")
_verification = importlib.util.spec_from_file_location("r1107_public_record", Path(__file__).resolve().parents[2] / "src/flop_agent/public_record.py")
V = importlib.util.module_from_spec(_verification); _verification.loader.exec_module(V)
DOMAIN = b"FLOP-R1107-EVIDENCE-v1\0"
ROOTS = ("/opt/technocore-safe-agent", "/var/lib/technocore-safe-agent")
ROLES = {"owner", "independent", "upstream", "destination", "identity", "restorer"}
MAX_BYTES = 16 * 1024**2


class Stop(ValueError):
    """Fixed codes only. Never interpolate private input or underlying errors."""


def need(value, code="SCHEMA_STOP"):
    if not value:
        raise Stop(code)


def shape(value, keys):
    need(type(value) is dict and set(value) == set(keys.split()))


def integer(value, lo=0, hi=2**63 - 1):
    need(type(value) is int and lo <= value <= hi)
    return value


def digest(value):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value))
    return value


def raw_hash(raw):
    need(type(raw) is bytes and len(raw) <= MAX_BYTES, "INPUT_BOUND_STOP")
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "INPUT_BOUND_STOP")
    try:
        return json.loads(raw, object_pairs_hook=G._pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Stop("JSON_STOP")))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise Stop("JSON_STOP") from None


def fresh(at, now, age=30):
    integer(at, 1); integer(now, 1)
    need(0 <= now - at <= age, "STALE_STOP")


class Enrollment:
    """Must come from independently digest-pinned local enrollment, NOT evidence.

    No private key, key generation, credential discovery or signing interface.
    Each key has ONE role. Source and owner cannot self-attest independent G4.
    """
    def __init__(self, value):
        shape(value, "schema_version context keys source_key_ids source_did")
        need(type(value["schema_version"]) is int and value["schema_version"] == 1)
        G.context_valid(value["context"])
        self.context = value["context"]
        need(type(value["source_did"]) is str and raw_hash(value["source_did"].encode()) == self.context["did"], "SOURCE_DID_BINDING_STOP")
        try:
            V._public_key(value["source_did"])
            own_public = V._b58decode(value["source_did"].removeprefix("did:key:z"))[2:]
        except ValueError:
            raise Stop("SOURCE_DID_BINDING_STOP") from None
        need(type(value["keys"]) is list and 1 <= len(value["keys"]) <= 16, "NO_INDEPENDENT_ISSUER")
        need(type(value["source_key_ids"]) is list)
        self.excluded = {digest(x) for x in value["source_key_ids"]}
        self.excluded.add(hashlib.sha256(own_public).hexdigest())
        self.keys = {}
        for row in value["keys"]:
            shape(row, "public_hex role")
            public = bytes.fromhex(digest(row["public_hex"]))
            kid = hashlib.sha256(public).hexdigest()
            need(row["role"] in ROLES and kid not in self.keys and kid not in self.excluded,
                 "ISSUER_ROLE_STOP")
            self.keys[kid] = (public, row["role"])

    def verify(self, packet, kind, role, now, *, age=30):
        shape(packet, "signer body signature")
        kid = digest(packet["signer"])
        need(kid not in self.excluded and kid in self.keys and self.keys[kid][1] == role,
             "NO_INDEPENDENT_ISSUER")
        body = packet["body"]
        shape(body, "kind context observed_at expires_at data")
        need(body["kind"] == kind and body["context"] == self.context, "BINDING_STOP")
        fresh(body["observed_at"], now, age)
        need(now < integer(body["expires_at"], 1) <= body["observed_at"] + age, "LEASE_EXPIRED")
        need(type(packet["signature"]) is str and re.fullmatch(r"[0-9a-f]{128}", packet["signature"]), "SIGNATURE_STOP")
        try:
            G.Ed25519PublicKey.from_public_bytes(self.keys[kid][0]).verify(
                bytes.fromhex(packet["signature"]), DOMAIN + G.canonical(body))
        except (ValueError, G.InvalidSignature):
            raise Stop("SIGNATURE_STOP") from None
        return body["data"]


def decisions(reason):
    return {"phase": "R1107", "result": "DRY_RUN_ONLY", "reason": reason,
            "source_archive": "NO_GO", "cutover": "NO_GO", "oci_retirement": "STRICT_NO_GO"}
