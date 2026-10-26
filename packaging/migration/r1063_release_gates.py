"""Offline evidence assessment only. No acquisition, migration or GO capability.

Attestation keys are verifier public keys, never application DID signing keys.
Trust must be supplied OUTSIDE the evidence packet by an independently reviewed
caller. The operator CLI deliberately has no enrolled production trust roots.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _contract(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / "archive" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Reuse audited source contracts; never execute their acquisition/backup code.
ROUTES_CONTRACT = _contract("r1063_routes", "r1052_offline_writer_route_contract.py")
FILES_CONTRACT = _contract("r1063_files", "r1050_offhost_sixfile_audit.py")
SOURCE_HEAD = ROUTES_CONTRACT.ORIGINAL_SOURCE_HEAD
ROUTES = tuple(ROUTES_CONTRACT.SIGN_POST_ROUTES.values())
TEMPLATES = frozenset(ROUTES_CONTRACT.ORIGINAL_TEMPLATE_GIT_BLOBS)
DATABASES = FILES_CONTRACT.SQLITE
LEDGERS = FILES_CONTRACT.LEDGER
MAX_PACKET_BYTES = 1024 * 1024
MAX_ITEMS = 2048
MAX_AGE = 900
GIB = 1024**3
DOMAIN = b"FLOP-R1063-EVIDENCE-v1\0"
HEX = re.compile(r"[0-9a-f]{64}\Z")
GATES = tuple(f"G{i}" for i in range(9))
ROLES = dict(zip(GATES, ("independent", "independent", "destination", "identity",
                        "independent", "independent", "independent", "restorer", "independent")))
ADMISSION = frozenset({"capture", "resident", "discord", "signer", "tclk", "close1",
                       "timers", "cron", "manual", "transient", "boot", "restart", "approval"})
ACTIONS = {
    "G0": "Independent fresh original-host, owner/root scope and exact source identity attestation.",
    "G1": "Resolve absent template, extra-unit effects, SPECIAL cron and proc RACE; complete authority census.",
    "G2": "Measure full-source peak disk and protected TradeBot mixed-load memory/CPU/PSI; prove zero incremental cost.",
    "G3": "Review actual portable authentication, least privilege and disarmed same-DID continuity for all five routes.",
    "G4": "Separately authorize durable admission generation covering Capture/Resident restart and every launcher.",
    "G5": "Independently bind every attempt/leg/DID/nonce to upstream finality across all five POST routes.",
    "G6": "Attest both online SQLite images plus ledgers during one continuously held writer fence.",
    "G7": "Authenticate full census/links/omissions, AES-GCM bytes and independent full inert offhost restore.",
    "G8": "Separate cutover and later retirement approvals, non-overlapping publishers, rollback hold and live safety proof.",
}


class Deny(ValueError):
    """Only fixed reason codes; never format caller-supplied data."""


def need(value, code="SCHEMA_INVALID"):
    if not value:
        raise Deny(code)


def shape(value, names):
    need(type(value) is dict and set(value) == set(names.split()))


def integer(value, low=0, high=2**63 - 1):
    need(type(value) is int and low <= value <= high)
    return value


def digest(value):
    need(type(value) is str and HEX.fullmatch(value) is not None)
    return value


def yes(value):
    need(value is True, "PROOF_MISSING")


def zero(value):
    need(integer(value) == 0, "UNRESOLVED_AUTHORITY")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "DUPLICATE_KEY")
        result[key] = value
    return result


def decode(raw):
    need(type(raw) is bytes and len(raw) <= MAX_PACKET_BYTES, "INPUT_BOUND")
    try:
        return json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Deny("SCHEMA_INVALID")))
    except (ValueError, UnicodeError, RecursionError):
        raise Deny("INVALID_JSON") from None


@dataclass(frozen=True)
class Trust:
    """Trusted caller configuration, NOT fields accepted from evidence/stdin.

    keys maps SHA256(public key) -> (32 public bytes, frozenset authorized roles).
    Context hashes must be independently pinned, not copied from the packet.
    No production keys, host identity or DID are enrolled by this source task.
    """
    context: dict
    keys: dict
    source_key_ids: frozenset


def context_valid(context):
    shape(context, "campaign host destination did source_head generation")
    for name in ("campaign", "host", "destination", "did"):
        digest(context[name])
    need(context["host"] != context["destination"], "HOST_SCOPE")
    need(context["source_head"] == SOURCE_HEAD, "SOURCE_DRIFT")
    integer(context["generation"], 1)


def verify(signed, role, trust):
    shape(signed, "signer body signature")
    key_id = digest(signed["signer"])
    need(key_id not in trust.source_key_ids, "SOURCE_SELF_ATTESTATION")
    need(key_id in trust.keys, "UNTRUSTED_ATTESTER")
    key, roles = trust.keys[key_id]
    need(type(key) is bytes and len(key) == 32 and hashlib.sha256(key).hexdigest() == key_id
         and role in roles, "ATTESTER_ROLE")
    signature = signed["signature"]
    need(type(signature) is str and re.fullmatch(r"[0-9a-f]{128}", signature), "SIGNATURE_INVALID")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(bytes.fromhex(signature), DOMAIN + canonical(signed["body"]))
    except (InvalidSignature, ValueError):
        raise Deny("SIGNATURE_INVALID") from None
    return signed["body"]


def authenticate(packet, gate, trust, now):
    body = verify(packet, ROLES[gate], trust)
    shape(body, "gate context observed_at expires_at evidence")
    need(body["gate"] == gate, "GATE_BINDING")
    context_valid(body["context"])
    need(body["context"] == trust.context, "CONTEXT_OR_EPOCH_MISMATCH")
    observed, expires = integer(body["observed_at"]), integer(body["expires_at"])
    need(observed <= now < expires <= observed + MAX_AGE and now - observed <= MAX_AGE,
         "STALE_OR_FUTURE")
    return body["evidence"]


def authorization(packet, action, binding, trust, now):
    body = verify(packet, "owner", trust)
    shape(body, "action context binding approved_at expires_at")
    need(body["action"] == action and body["context"] == trust.context
         and digest(body["binding"]) == binding, "APPROVAL_BINDING")
    need(integer(body["approved_at"]) <= now < integer(body["expires_at"])
         <= body["approved_at"] + MAX_AGE, "APPROVAL_EXPIRED")


def check_post_route(item, route, inventory_digest, trust, now, all_attempts, all_nonces):
    shape(item, "attempts external")
    records = item["attempts"]
    need(type(records) is list and len(records) <= MAX_ITEMS, "ATTEMPT_BOUND")
    external = verify(item["external"], "upstream", trust)
    shape(external, "context route inventory_digest records observed_at")
    need(external["context"] == trust.context and external["route"] == route
         and external["inventory_digest"] == inventory_digest
         and external["records"] == records, "UPSTREAM_BINDING")
    need(now - MAX_AGE <= integer(external["observed_at"]) <= now, "UPSTREAM_STALE")
    for record in records:
        shape(record, "attempt_id leg room_sha256 nonce_sha256 did text_sha256 local_state verdict acknowledgment")
        for name in ("attempt_id", "room_sha256", "nonce_sha256", "did", "text_sha256", "acknowledgment"):
            digest(record[name])
        integer(record["leg"], 0, MAX_ITEMS)
        need(record["did"] == trust.context["did"], "DID_BINDING")
        need(record["verdict"] in ("ACCEPTED", "DEFINITELY_NOT_ACCEPTED"), "UPSTREAM_UNKNOWN")
        need(record["local_state"] in ("posted", "acknowledged", "ambiguous", "quarantined", "prepared", "attempting"))
        attempt = (record["attempt_id"], record["leg"])
        nonce = (record["did"], record["room_sha256"], record["nonce_sha256"])
        need(attempt not in all_attempts and nonce not in all_nonces, "DUPLICATE_ATTEMPT")
        all_attempts.add(attempt); all_nonces.add(nonce)


def check_gate(gate, e, evidence, packets, trust, now):
    """Strict evidence contracts; booleans only count inside authenticated packets."""
    if gate == "G0":
        shape(e, "scope_complete unrelated_hosts_excluded source_artifact identity_digest roots_digest")
        yes(e["scope_complete"]); yes(e["unrelated_hosts_excluded"])
        for name in ("source_artifact", "identity_digest", "roots_digest"):
            digest(e[name])
    elif gate == "G1":
        shape(e, "templates extras_reviewed census_digest launchers_complete special_cron proc_races unknown_authorities permission_failures")
        need(type(e["templates"]) is dict and set(e["templates"]) == TEMPLATES, "TEMPLATE_COVERAGE")
        need(all(x in ("audited_present", "audited_absent") for x in e["templates"].values()), "TEMPLATE_COVERAGE")
        need(integer(e["extras_reviewed"], 0, MAX_ITEMS) >= len(ROUTES_CONTRACT.UNEXPECTED_INSTALLED_NAMES_FROM_R1034), "EXTRA_UNIT_COVERAGE")
        digest(e["census_digest"]); yes(e["launchers_complete"])
        for name in ("special_cron", "proc_races", "unknown_authorities", "permission_failures"):
            zero(e[name])
    elif gate == "G2":
        shape(e, "source_bytes encrypted_peak_bytes sqlite_bytes rollback_bytes free_bytes memory_bytes tradebot_peak_bytes flop_peak_bytes os_reserve_bytes margin_bytes cpu_psi_safe protected_cycles_safe zero_incremental_cost capacity_digest")
        for name in set(e) - {"cpu_psi_safe", "protected_cycles_safe", "zero_incremental_cost", "capacity_digest"}:
            integer(e[name], 1)
        # Do not budget optimistic compression or discard rollback/original bytes.
        need(e["encrypted_peak_bytes"] >= e["source_bytes"]
             and e["rollback_bytes"] >= e["source_bytes"], "CAPACITY_UNDERCOUNT")
        need(e["free_bytes"] <= 60 * 1000**3, "DESTINATION_CAPACITY_DRIFT")
        need(e["free_bytes"] >= e["source_bytes"] + e["encrypted_peak_bytes"] + e["sqlite_bytes"]
             + e["rollback_bytes"] + 20 * GIB, "INSUFFICIENT_SPACE")
        need(e["memory_bytes"] <= 2 * GIB and e["margin_bytes"] >= 256 * 1024**2
             and e["tradebot_peak_bytes"] + e["flop_peak_bytes"] + e["os_reserve_bytes"]
             + e["margin_bytes"] <= e["memory_bytes"], "INSUFFICIENT_MEMORY")
        for name in ("cpu_psi_safe", "protected_cycles_safe", "zero_incremental_cost"):
            yes(e[name])
        digest(e["capacity_digest"])
    elif gate == "G3":
        shape(e, "portable_credential_proven issuer_subject_audience_expiry_verified permission_and_trust_verified least_privilege revoked_on_rollback no_export same_did_disarmed nonce_receipt_continuity route_coverage custody_review")
        for name in set(e) - {"route_coverage", "custody_review"}:
            yes(e[name])
        need(type(e["route_coverage"]) is list and sorted(e["route_coverage"]) == sorted(ROUTES), "FIVE_ROUTE_COVERAGE")
        digest(e["custody_review"])
    elif gate == "G4":
        shape(e, "coverage fence_start held_until lease_expires_at continuous metadata_guard_preserved no_relaunch active_writers writable_fds unknown_fds barrier_digest approval")
        need(type(e["coverage"]) is list and len(e["coverage"]) == len(ADMISSION)
             and set(e["coverage"]) == ADMISSION, "ADMISSION_COVERAGE")
        need(integer(e["fence_start"]) <= integer(e["held_until"]) <= now
             and now - e["held_until"] <= 30
             and now < integer(e["lease_expires_at"]) <= e["held_until"] + MAX_AGE, "FENCE_NOT_CURRENT")
        need(e["held_until"] <= packets["G4"]["body"]["observed_at"], "FUTURE_FENCE_ASSERTION")
        for name in ("continuous", "metadata_guard_preserved", "no_relaunch"):
            yes(e[name])
        for name in ("active_writers", "writable_fds", "unknown_fds"):
            zero(e[name])
        digest(e["barrier_digest"])
        # Authorize the fixed barrier plan before acquisition, not hindsight facts.
        authorization(e["approval"], "fence", sha({"barrier_digest": e["barrier_digest"],
                                                  "coverage": e["coverage"]}), trust, now)
        need(e["approval"]["body"]["approved_at"] <= e["fence_start"], "APPROVAL_ORDER")
    elif gate == "G5":
        shape(e, "inventory_complete inventory_digest routes")
        yes(e["inventory_complete"]); digest(e["inventory_digest"])
        need(type(e["routes"]) is dict and set(e["routes"]) == set(ROUTES), "FIVE_ROUTE_COVERAGE")
        route_results, all_attempts, all_nonces = [], set(), set()
        for route in ROUTES:
            try:
                check_post_route(e["routes"][route], route, e["inventory_digest"], trust, now, all_attempts, all_nonces)
                status, reason = "PASS", "UPSTREAM_FINALITY_BOUND"
            except (Deny, KeyError, TypeError, ValueError) as error:
                status, reason = "DENY", str(error) if type(error) is Deny else "SCHEMA_INVALID"
            route_results.append({"route": route, "status": status, "reason": reason})
        return route_results
    elif gate == "G6":
        shape(e, "barrier_digest images ledgers full_state_epoch_digest census_digest")
        need(e["barrier_digest"] == evidence["G4"]["barrier_digest"], "EPOCH_BINDING")
        need(type(e["images"]) is dict and set(e["images"]) == set(DATABASES), "TWO_DATABASES_REQUIRED")
        total = 0
        for image in e["images"].values():
            shape(image, "sha256 bytes generation start end online_backup schema_ok integrity_ok wal_accounted")
            digest(image["sha256"]); total += integer(image["bytes"], 100, FILES_CONTRACT.R1005.MAX_SIZE)
            need(integer(image["generation"], 1) == trust.context["generation"], "CROSS_EPOCH")
            need(evidence["G4"]["fence_start"] <= integer(image["start"]) <= integer(image["end"])
                 <= evidence["G4"]["held_until"] <= now, "CROSS_EPOCH")
            for name in ("online_backup", "schema_ok", "integrity_ok", "wal_accounted"):
                yes(image[name])
        need(total <= evidence["G2"]["sqlite_bytes"], "CAPACITY_UNDERCOUNT")
        need(type(e["ledgers"]) is dict and set(e["ledgers"]) == set(LEDGERS), "LEDGER_COVERAGE")
        for value in e["ledgers"].values():
            digest(value)
        digest(e["full_state_epoch_digest"])
        digest(e["census_digest"])
    elif gate == "G7":
        shape(e, "census_digest roots_digest manifest_digest epoch_digest images_digest ledgers_digest source_files restored_files source_bytes restored_bytes unresolved_roots unresolved_links omissions links_accounted full_content_reassembled envelope ciphertext_digest ciphertext_bytes aead_verified offhost_possession independent_key_custody full_inert_restore continuity_verified restore_digest shards max_shard_bytes max_segments max_segment_bytes")
        for name in ("census_digest", "manifest_digest", "ciphertext_digest", "restore_digest"):
            digest(e[name])
        need(e["epoch_digest"] == evidence["G6"]["full_state_epoch_digest"]
             and e["census_digest"] == evidence["G6"]["census_digest"]
             and e["roots_digest"] == evidence["G0"]["roots_digest"]
             and e["images_digest"] == sha(evidence["G6"]["images"])
             and e["ledgers_digest"] == sha(evidence["G6"]["ledgers"]), "RESTORE_BINDING")
        need(integer(e["source_files"], 1, 25000) == integer(e["restored_files"], 1, 25000), "FULL_SET_MISMATCH")
        need(integer(e["source_bytes"], 1) == integer(e["restored_bytes"], 1)
             == evidence["G2"]["source_bytes"], "FULL_BYTES_MISMATCH")
        need(integer(e["ciphertext_bytes"], 1) <= evidence["G2"]["encrypted_peak_bytes"], "CAPACITY_UNDERCOUNT")
        for name in ("unresolved_roots", "unresolved_links", "omissions"):
            zero(e[name])
        for name in ("links_accounted", "full_content_reassembled", "aead_verified", "offhost_possession",
                     "independent_key_custody", "full_inert_restore", "continuity_verified"):
            yes(e[name])
        need(e["envelope"] == "R1001_AES256_GCM", "ARCHIVE_NOT_AUTHENTICATED")
        integer(e["shards"], 1, 64); integer(e["max_shard_bytes"], 1, 6 * GIB)
        integer(e["max_segments"], 1, 512); integer(e["max_segment_bytes"], 1, 3 * GIB)
        # Restorer is independent of the source acquisition verifier.
        need(packets["G7"]["signer"] != packets["G6"]["signer"], "RESTORER_NOT_INDEPENDENT")
    else:
        shape(e, "cutover_approval retirement_approval rollback nonoverlap lease_enforced original_retained latest_posts_reconciled rollback_digest live_stable zero_references exact_retirement_scope hold_complete")
        for name in ("rollback", "nonoverlap", "lease_enforced", "original_retained", "latest_posts_reconciled"):
            yes(e[name])
        digest(e["rollback_digest"])
        binding = sha({g: packets[g] for g in GATES[:-1]})
        authorization(e["cutover_approval"], "cutover", binding, trust, now)
        # Distinguish an assessed cutover approval from later retirement evidence.
        decisions = {"cutover_approval": {"status": "PASS", "reason": "OWNER_BINDING_VALID"}}
        try:
            need(e["retirement_approval"] is not None, "RETIREMENT_APPROVAL_MISSING")
            authorization(e["retirement_approval"], "retirement", sha({"release": binding, "cutover": e["cutover_approval"]}), trust, now)
            need(e["retirement_approval"]["body"]["approved_at"] > e["cutover_approval"]["body"]["approved_at"], "APPROVAL_ORDER")
            for name in ("live_stable", "zero_references", "exact_retirement_scope", "hold_complete"):
                yes(e[name])
            status, reason = "PASS", "LATER_OWNER_BINDING_VALID"
        except (Deny, KeyError, TypeError, ValueError) as error:
            status, reason = "DENY", str(error) if type(error) is Deny else "SCHEMA_INVALID"
        decisions["retirement_approval"] = {"status": status, "reason": reason}
        return decisions


def _report(results, code=None):
    return {"schema_version": 1, "assessment": "EVIDENCE_VALID" if len(results) == 9 and all(x["status"] == "PASS" for x in results) else "DENY",
            "gates": results, "input_error": code,
            "cutover": "NO_GO", "oci_retirement": "STRICT_NO_GO", "all_writers_fenced": "NOT_ASSERTED",
            "authority": "OFFLINE_ASSESSMENT_ONLY", "production_trust_enrolled": False}


def evaluate(bundle, trust=None, *, now):
    """Assess signed metadata only; no caller value or identifier is echoed."""
    results, evidence, packets = [], {}, {}
    try:
        integer(now)
        need(len(canonical(bundle)) <= MAX_PACKET_BYTES, "INPUT_BOUND")
        shape(bundle, "schema_version packets")
        need(type(bundle["schema_version"]) is int and bundle["schema_version"] == 1)
        need(type(bundle["packets"]) is list and len(bundle["packets"]) <= len(GATES))
        for packet in bundle["packets"]:
            shape(packet, "signer body signature")
            gate = packet["body"]["gate"]
            need(type(gate) is str and gate in GATES and gate not in packets, "DUPLICATE_OR_UNKNOWN_GATE")
            packets[gate] = packet
        if trust is not None:
            context_valid(trust.context)
    except (Deny, KeyError, TypeError, ValueError, OverflowError, RecursionError) as error:
        code = str(error) if type(error) is Deny else "SCHEMA_INVALID"
        return _report([{"gate": g, "status": "DENY", "reason": "INVALID_PACKET", "next_evidence": ACTIONS[g]} for g in GATES], code)
    for gate in GATES:
        details = None
        try:
            need(gate in packets, "EVIDENCE_MISSING")
            need(trust is not None, "TRUST_NOT_ENROLLED")
            e = authenticate(packets[gate], gate, trust, now)
            dependencies = {"G4": ("G0", "G1", "G2", "G3"), "G5": ("G4",),
                            "G6": ("G2", "G4", "G5"), "G7": ("G2", "G6"), "G8": GATES[:-1]}
            need(all(x in evidence for x in dependencies.get(gate, ())), "DEPENDENCY_DENIED")
            details = check_gate(gate, e, evidence, packets, trust, now)
            if gate == "G5":
                need(all(x["status"] == "PASS" for x in details), "POST_ROUTE_DENIED")
            elif gate == "G8":
                need(all(x["status"] == "PASS" for x in details.values()), "RETIREMENT_DENIED")
            evidence[gate] = e
            status, reason = "PASS", "AUTHENTICATED_CONTRACT_VALID"
        except (Deny, KeyError, TypeError, ValueError, OverflowError, RecursionError) as error:
            status, reason = "DENY", str(error) if type(error) is Deny else "SCHEMA_INVALID"
        entry = {"gate": gate, "status": status, "reason": reason, "next_evidence": ACTIONS[gate]}
        if gate == "G5":
            entry["post_routes"] = details if details is not None else [
                {"route": route, "status": "DENY", "reason": reason} for route in ROUTES]
        if gate == "G8":
            entry["approvals"] = details if details is not None else {
                kind: {"status": "DENY", "reason": reason} for kind in ("cutover_approval", "retirement_approval")}
        results.append(entry)
    return _report(results)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args not in ([], ["--stdin"]):
        print(json.dumps(_report([], "ARGUMENTS_DENIED")))
        return 2
    try:
        bundle = decode(sys.stdin.buffer.read(MAX_PACKET_BYTES + 1)) if args else {"schema_version": 1, "packets": []}
        report = evaluate(bundle, now=int(time.time()))
    except (Deny, OSError):
        report = _report([], "INPUT_DENIED")
    print(json.dumps(report, sort_keys=True, indent=2))
    return 2  # Evidence review cannot authorize a runtime operation.


if __name__ == "__main__":
    raise SystemExit(main())
