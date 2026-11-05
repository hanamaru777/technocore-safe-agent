"""R1163 public contracts. No production authority is enrolled by this patch."""
import ast
import base64
import hashlib
import importlib.util
import json
import re
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = "2033ec2159717d473fed2f0031d441ec105b504a"
T1150 = "8a46d43de6e7474941cd241278c00d3352c8a2b6"
DOMAIN = b"FLOP-R1163-ORIGINAL-GUEST-ANCHOR-v1\0"
# A local approver, issue author, AWS key or imported packet cannot enroll an
# Oracle guest-key authority. Independent review must supply a pinned authority
# and its authenticated provenance in source before production import can PASS.
ORIGINAL_AUTHORITIES = {}
MIB = 1024**2


class Stop(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise Stop(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def sha(value):
    return hashlib.sha256(value).hexdigest()


def shape(value, fields):
    need(type(value) is dict and set(value) == set(fields.split()), "PUBLIC_SCHEMA_STOP")


def digest(value):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "PUBLIC_DIGEST_STOP")
    return value


def fresh(at, expiry, now, age=180):
    need(all(type(x) is int for x in (at, expiry, now)) and
         now-age <= at <= now+5 and at < expiry <= at+age and now < expiry,
         "PUBLIC_EXPIRED_STOP")


def source_map():
    manifest = Path(__file__).with_name("r1163_source_pins.json")
    need(not manifest.is_symlink() and not getattr(manifest, "is_junction", lambda: False)() and
         stat.S_ISREG(manifest.lstat().st_mode) and manifest.stat().st_size <= 65536, "SOURCE_MAP_STOP")
    raw = manifest.read_bytes().replace(b"\r\n", b"\n")
    need(sha(raw) == EXPECTED_SHA256, "SOURCE_MAP_STOP")
    value = json.loads(raw)
    need(value["base"] == BASE and value["t1150"] == T1150, "SOURCE_MAP_STOP")
    for name, item in value["files"].items():
        path = ROOT / name
        need(all(not p.is_symlink() and not getattr(p, "is_junction", lambda: False)()
                 for p in (path, *path.parents)) and stat.S_ISREG(path.lstat().st_mode) and
             path.stat().st_size <= 524288, "SOURCE_LINK_STOP")
        data = path.read_bytes().replace(b"\r\n", b"\n")
        blob = hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
        need(blob == item["blob"], "SOURCE_PIN_STOP")
        if name in value["interfaces"]:
            functions = {n.name: ast.dump(n.args, include_attributes=False)
                         for n in ast.parse(data).body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
            for key, signature in value["interfaces"][name].items():
                need(functions.get(key) == signature, "SOURCE_INTERFACE_STOP")
    return value


def legacy(leaf):
    # Public callers must check the entire map before loading an executable
    # dependency. Existing loaders retain their own unchanged immutable pins.
    source_map()
    name = "r1163_"+leaf.replace(".", "_")
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(leaf))
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


def original_anchor(packet, challenge, *, now, authorities=None, trial=False):
    """Import a challenge-bound signed *public* attestation, never TOFU.

    The authority must independently attest the original guest's sshd key,
    machine, current boot and bounded scope. Serial proxy/authorized_keys and
    provider credentials for a different machine are not guest-key evidence.
    Synthetic authorities are library-only and never confer production trust.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    shape(packet, "body signature")
    b = packet["body"]
    shape(b, "version kind authority challenge observed_at expires_at host instance machine_sha256 boot_sha256 scope_sha256 guest_host_key key_sha256 evidence_sha256")
    need(b["version"] == 1 and type(b["version"]) is int and
         b["kind"] == "INDEPENDENT_ORIGINAL_OCI_GUEST_SSHD", "ORACLE_PROVENANCE_STOP")
    need(b["host"] == "140.238.55.171" and b["instance"] == "ORIGINAL_ORACLE",
         "ORACLE_TARGET_STOP")
    need(b["challenge"] == digest(challenge), "ORACLE_CHALLENGE_STOP")
    fresh(b["observed_at"], b["expires_at"], now)
    for k in ("machine_sha256", "boot_sha256", "scope_sha256", "key_sha256", "evidence_sha256"):
        digest(b[k])
    need(trial or authorities is None, "ORACLE_TRUST_OVERRIDE_STOP")
    roots = authorities if trial and authorities is not None else ORIGINAL_AUTHORITIES
    need(type(b["authority"]) is str and b["authority"] in roots, "ORACLE_INDEPENDENT_AUTHORITY_REQUIRED")
    # Use the existing strict SSH wire-format decoder, not a text fingerprint.
    boot = legacy("r1159_m2_bootstrap.py")
    wire = boot.host_key(b["guest_host_key"], "ssh-ed25519")
    need(wire == b["key_sha256"], "ORACLE_KEY_BINDING_STOP")
    original = legacy("r1161_readonly_admission.py")
    need(wire == original.ORIGINAL_ED25519_SHA256, "ORACLE_ORIGINAL_KEY_STOP")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(roots[b["authority"]])).verify(
            bytes.fromhex(packet["signature"]), DOMAIN+canonical(b))
    except Exception:
        raise Stop("ORACLE_AUTH_SIGNATURE_STOP") from None
    return dict(state="PASS" if not trial else "SYNTHETIC_PASS", scope="OFFLINE_TRIAL" if trial else "PUBLIC_ANCHOR_ONLY",
                anchor_sha256=sha(canonical(packet)), challenge=challenge,
                machine_sha256=b["machine_sha256"], boot_sha256=b["boot_sha256"],
                scope_sha256=b["scope_sha256"], expires_at=b["expires_at"], migration="NO_GO")


def k137_receipt(packet, challenge, *, now, expected_boot=None, expected_scope=None):
    """Structural consistency only. The checksum is NOT independent authority."""
    p = legacy("r1162_k137_provider_admission.py")
    p.shape(packet, "body sha256")
    b = packet["body"]
    p.shape(b, "task verdict ssh_login_prebounded challenge observed_at expires_at source_base reference_commit source_blobs provider_operation provider_sha256 provider_witnessed_at credential_expires_at host_key_sha256 head guest_sha256 report_sha256 boot_sha256 scope_sha256 tradebot_sha256 caps m2 cutover oci_retirement")
    need(packet["sha256"] == sha(canonical(b)), "K137_RECEIPT_HASH_STOP")
    need(b["challenge"] == digest(challenge), "K137_CHALLENGE_STOP")
    fresh(b["observed_at"], b["expires_at"], now)
    need(b["task"] == "R1162" and b["verdict"] == "K137_PAYLOAD_BOUNDED" and
         b["ssh_login_prebounded"] is False and b["m2"] == b["cutover"] == "NO_GO" and
         b["oci_retirement"] == "STRICT_NO_GO", "K137_SCOPE_STOP")
    manifest = p.sources()
    pins = {**manifest["frozen"], **manifest["guest"],
            "packaging/migration/r1162_k137_provider_admission.py": p.blob(p.source("packaging/migration/r1162_k137_provider_admission.py"))}
    need(b["source_base"] == p.BASE and b["reference_commit"] == p.REFERENCE and b["source_blobs"] == pins,
         "K137_SOURCE_STOP")
    need(b["provider_operation"] == "Lightsail.GetInstanceAccessDetails" and
         b["head"] == "3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e", "K137_PROVIDER_STOP")
    boot = legacy("r1159_m2_bootstrap.py")
    need(b["host_key_sha256"] == boot.host_key(boot.K137_KEY, "ssh-ed25519"), "K137_HOST_STOP")
    for k in ("provider_sha256", "guest_sha256", "report_sha256", "boot_sha256", "scope_sha256", "tradebot_sha256"):
        digest(b[k])
    need(expected_boot is None or b["boot_sha256"] == digest(expected_boot), "K137_BOOT_STOP")
    need(expected_scope is None or b["scope_sha256"] == digest(expected_scope), "K137_CGROUP_STOP")
    need(type(b["provider_witnessed_at"]) is int and b["observed_at"]-180 <= b["provider_witnessed_at"] <= b["observed_at"] and
         type(b["credential_expires_at"]) is int and b["expires_at"] < b["credential_expires_at"], "K137_PROVIDER_TIME_STOP")
    cg = b["caps"]
    p.shape(cg, "scope_sha256 memory_max pids_max cpu_quota cpu_period swap_max")
    need(cg["scope_sha256"] == b["scope_sha256"], "K137_CGROUP_STOP")
    p.integer(cg["memory_max"], 1, 256*MIB); p.integer(cg["pids_max"], 1, 64)
    p.integer(cg["cpu_period"], 1, 1000000); p.integer(cg["cpu_quota"], 1, cg["cpu_period"]//2)
    p.integer(cg["swap_max"], 0, 0)
    return dict(state="UNKNOWN", consistency="PASS", independent_authority="NOT_PROVEN",
                ssh_login_prebounded=False, migration="NO_GO")


def resource_plan():
    source_map()
    caps = {}
    for role in ("signer", "publisher", "guard-monitor", "resident", "capture"):
        text = (ROOT/f"packaging/oracle/flop-r1156-{role}.service").read_text()
        rows = re.findall(r"^MemoryMax=(\d+)M$", text, re.M)
        need(len(rows) == 1, "UNIT_CAP_STOP")
        caps[role] = int(rows[0])
    required = sum(caps.values())+1200+256
    return dict(state="NO_GO", unit_caps_mib=caps, flop_total_mib=sum(caps.values()),
                tradebot_max_mib=1200, minimum_reserve_mib=256, physical_mib=1906,
                minimum_required_mib=required, overcommit_mib=max(0, required-1906),
                concurrent_rss="NEW_REAL_EVIDENCE_REQUIRED", disk="NEW_REAL_EVIDENCE_REQUIRED",
                policy="PRESERVE_R1158_ACTUAL_CONCURRENT_AND_REMAINING_CAP_GATES")


def production_migration(*args, **kwargs):
    # There is no authenticated global backend, complete five-route finality
    # authority or portable original-DID signer on this evidence. No caller
    # booleans, owner signature or synthetic packet may bypass that absence.
    raise Stop("G3_G4_G5_INDEPENDENT_LIVE_AUTHORITIES_REQUIRED")


# Public integrity hash of the additive source map, not credential material.
EXPECTED_SHA256 = "2b10e2dc916f385fbda2e41e5f0de0aebe18b49ca01a521b3be933f86d60d461"
