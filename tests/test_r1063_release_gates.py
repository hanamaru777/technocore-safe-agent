"""Executable synthetic E2E harness. Ephemeral verifier keys, no real evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "packaging/migration/r1063_release_gates.py"
spec = importlib.util.spec_from_file_location("r1063", FILE)
r = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = r
spec.loader.exec_module(r)
NOW = 2000000000


def h(label):
    return hashlib.sha256(label.encode()).hexdigest()


class Synthetic:
    def __init__(self):
        self.private, public = {}, {}
        self.ids = {}
        for role in ("independent", "destination", "identity", "restorer", "owner", "upstream", "source"):
            key = Ed25519PrivateKey.generate()  # Ephemeral TEST verifier, never a DID/real credential.
            raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            kid = hashlib.sha256(raw).hexdigest()
            self.private[role], self.ids[role] = key, kid
            public[kid] = (raw, frozenset({role}))
        self.context = {"campaign": h("campaign"), "host": h("original"), "destination": h("K137"),
                        "did": h("synthetic-continuing-identity"), "source_head": r.SOURCE_HEAD, "generation": 7}
        self.trust = r.Trust(self.context, public, frozenset({self.ids["source"]}))
        self.e = self.evidence()

    def sign(self, role, body):
        return {"signer": self.ids[role], "body": copy.deepcopy(body),
                "signature": self.private[role].sign(r.DOMAIN + r.canonical(body)).hex()}

    def approval(self, action, binding, at=NOW - 10):
        return self.sign("owner", {"action": action, "context": self.context, "binding": binding,
                                   "approved_at": at, "expires_at": NOW + 120})

    def evidence(self):
        e = {
            "G0": {"scope_complete": True, "unrelated_hosts_excluded": True,
                   "source_artifact": h("source"), "identity_digest": h("identity"), "roots_digest": h("roots")},
            "G1": {"templates": {n: "audited_present" for n in r.TEMPLATES}, "extras_reviewed": 4,
                   "census_digest": h("unit-census"), "launchers_complete": True, "special_cron": 0,
                   "proc_races": 0, "unknown_authorities": 0, "permission_failures": 0},
            "G2": {"source_bytes": 4 * r.GIB, "encrypted_peak_bytes": 5 * r.GIB,
                   "sqlite_bytes": r.GIB, "rollback_bytes": 4 * r.GIB, "free_bytes": 34 * r.GIB,
                   "memory_bytes": 2 * r.GIB, "tradebot_peak_bytes": r.GIB // 2,
                   "flop_peak_bytes": r.GIB // 2, "os_reserve_bytes": r.GIB // 4,
                   "margin_bytes": r.GIB // 4, "cpu_psi_safe": True, "protected_cycles_safe": True,
                   "zero_incremental_cost": True, "capacity_digest": h("capacity")},
            "G3": {"portable_credential_proven": True, "issuer_subject_audience_expiry_verified": True,
                   "permission_and_trust_verified": True, "least_privilege": True, "revoked_on_rollback": True,
                   "no_export": True, "same_did_disarmed": True, "nonce_receipt_continuity": True,
                   "route_coverage": list(r.ROUTES), "custody_review": h("custody")},
            "G4": {"coverage": sorted(r.ADMISSION), "fence_start": NOW - 60, "held_until": NOW - 1, "lease_expires_at": NOW + 60,
                   "continuous": True, "metadata_guard_preserved": True, "no_relaunch": True,
                   "active_writers": 0, "writable_fds": 0, "unknown_fds": 0, "barrier_digest": h("barrier")},
            "G5": {"inventory_complete": True, "inventory_digest": h("all-attempts"), "routes": {}},
            "G6": {"barrier_digest": h("barrier"), "images": {},
                   "ledgers": {n: h(n) for n in r.LEDGERS}, "full_state_epoch_digest": h("full-epoch"), "census_digest": h("full-census")},
            "G7": {"census_digest": h("full-census"), "roots_digest": h("roots"), "manifest_digest": h("full-manifest"),
                   "epoch_digest": h("full-epoch"), "source_files": 3017, "restored_files": 3017,
                   "source_bytes": 4 * r.GIB, "restored_bytes": 4 * r.GIB, "unresolved_roots": 0,
                   "unresolved_links": 0, "omissions": 0, "links_accounted": True,
                   "full_content_reassembled": True, "envelope": "R1001_AES256_GCM",
                   "ciphertext_digest": h("ciphertext"), "ciphertext_bytes": 4 * r.GIB,
                   "aead_verified": True, "offhost_possession": True, "independent_key_custody": True,
                   "full_inert_restore": True, "continuity_verified": True, "restore_digest": h("restored"),
                   "shards": 4, "max_shard_bytes": 6 * r.GIB, "max_segments": 512, "max_segment_bytes": 3 * r.GIB},
            "G8": {"rollback": True, "nonoverlap": True, "lease_enforced": True, "original_retained": True,
                   "latest_posts_reconciled": True, "rollback_digest": h("rollback"), "live_stable": True,
                   "zero_references": True, "exact_retirement_scope": True, "hold_complete": True},
        }
        for index, route in enumerate(r.ROUTES):
            record = {"attempt_id": h(route), "leg": index, "room_sha256": h("room"),
                      "nonce_sha256": h("nonce-" + route), "did": self.context["did"],
                      "text_sha256": h("payload-" + route), "local_state": "acknowledged",
                      "verdict": "ACCEPTED", "acknowledgment": h("upstream-" + route)}
            e["G5"]["routes"][route] = {"attempts": [record]}
        for name in r.DATABASES:
            e["G6"]["images"][name] = {"sha256": h(name), "bytes": 4096, "generation": 7,
                                       "start": NOW - 40, "end": NOW - 30, "online_backup": True,
                                       "schema_ok": True, "integrity_ok": True, "wal_accounted": True}
        return e

    def bundle(self):
        e = copy.deepcopy(self.e)
        e["G4"]["approval"] = self.approval("fence", r.sha({"barrier_digest": e["G4"]["barrier_digest"],
                                                          "coverage": e["G4"]["coverage"]}), NOW - 65)
        for route, item in e["G5"]["routes"].items():
            item["external"] = self.sign("upstream", {"context": self.context, "route": route,
                "inventory_digest": e["G5"]["inventory_digest"], "records": item["attempts"], "observed_at": NOW - 5})
        e["G7"]["images_digest"] = r.sha(e["G6"]["images"])
        e["G7"]["ledgers_digest"] = r.sha(e["G6"]["ledgers"])
        packets = {}
        for g in r.GATES:
            if g == "G8":
                binding = r.sha(packets)
                e[g]["cutover_approval"] = self.approval("cutover", binding)
                e[g]["retirement_approval"] = self.approval("retirement", r.sha({"release": binding,
                    "cutover": e[g]["cutover_approval"]}), NOW - 5)
            packets[g] = self.sign(r.ROLES[g], {"gate": g, "context": self.context,
                "observed_at": NOW - 1, "expires_at": NOW + 120, "evidence": e[g]})
        return {"schema_version": 1, "packets": list(packets.values())}


@pytest.fixture
def fixture():
    return Synthetic()


def result(f, bundle=None):
    return r.evaluate(f.bundle() if bundle is None else bundle, f.trust, now=NOW)


def denied(report, gate, reason=None):
    found = next(x for x in report["gates"] if x["gate"] == gate)
    assert found["status"] == "DENY"
    if reason:
        assert found["reason"] == reason
    assert report["assessment"] == "DENY"
    assert report["cutover"] == "NO_GO"
    assert report["oci_retirement"] == "STRICT_NO_GO"


def resign(f, bundle, index, role=None):
    body = bundle["packets"][index]["body"]
    bundle["packets"][index] = f.sign(role or r.ROLES[body["gate"]], body)


def test_complete_synthetic_e2e_contract_pass_is_never_live_go(fixture):
    report = result(fixture)
    assert report["assessment"] == "EVIDENCE_VALID"
    assert all(g["status"] == "PASS" for g in report["gates"])
    assert report["cutover"] == "NO_GO"
    assert report["oci_retirement"] == "STRICT_NO_GO"
    assert report["production_trust_enrolled"] is False
    # No caller evidence/nonce/DID/identity or raw paths in the report.
    rendered = json.dumps(report)
    assert fixture.context["did"] not in rendered
    assert "nonce_sha256" not in rendered


@pytest.mark.parametrize("gate", r.GATES)
def test_every_missing_gate_denies(fixture, gate):
    bundle = fixture.bundle()
    bundle["packets"] = [p for p in bundle["packets"] if p["body"]["gate"] != gate]
    denied(result(fixture, bundle), gate, "EVIDENCE_MISSING")


@pytest.mark.parametrize("gate,key,value,reason", [
    ("G0", "scope_complete", False, "PROOF_MISSING"),
    ("G1", "special_cron", 1, "UNRESOLVED_AUTHORITY"),
    ("G1", "proc_races", 1, "UNRESOLVED_AUTHORITY"),
    ("G1", "unknown_authorities", 1, "UNRESOLVED_AUTHORITY"),
    ("G1", "permission_failures", 1, "UNRESOLVED_AUTHORITY"),
    ("G2", "free_bytes", 20 * r.GIB, "INSUFFICIENT_SPACE"),
    ("G2", "free_bytes", 82 * r.GIB, "DESTINATION_CAPACITY_DRIFT"),
    ("G2", "flop_peak_bytes", 2 * r.GIB, "INSUFFICIENT_MEMORY"),
    ("G2", "zero_incremental_cost", False, "PROOF_MISSING"),
    ("G3", "portable_credential_proven", False, "PROOF_MISSING"),
    ("G3", "permission_and_trust_verified", False, "PROOF_MISSING"),
    ("G4", "writable_fds", 4, "UNRESOLVED_AUTHORITY"),
    ("G4", "writable_fds", 5, "UNRESOLVED_AUTHORITY"),
    ("G4", "unknown_fds", 1, "UNRESOLVED_AUTHORITY"),
    ("G4", "continuous", False, "PROOF_MISSING"),
    ("G4", "no_relaunch", False, "PROOF_MISSING"),
    ("G5", "inventory_complete", False, "PROOF_MISSING"),
    ("G7", "unresolved_links", 19, "UNRESOLVED_AUTHORITY"),
    ("G7", "unresolved_roots", 4, "UNRESOLVED_AUTHORITY"),
    ("G7", "omissions", 1, "UNRESOLVED_AUTHORITY"),
    ("G7", "restored_files", 6, "FULL_SET_MISMATCH"),
    ("G7", "aead_verified", False, "PROOF_MISSING"),
    ("G7", "full_inert_restore", False, "PROOF_MISSING"),
    ("G8", "nonoverlap", False, "PROOF_MISSING"),
    ("G8", "original_retained", False, "PROOF_MISSING"),
])
def test_independent_operator_blockers(fixture, gate, key, value, reason):
    fixture.e[gate][key] = value
    denied(result(fixture), gate, reason)


@pytest.mark.parametrize("route", r.ROUTES)
@pytest.mark.parametrize("mode", ["local_only", "unknown", "missing_route", "did_mismatch", "duplicate"])
def test_each_post_route_independently_requires_authoritative_finality(fixture, route, mode):
    if mode == "missing_route":
        del fixture.e["G5"]["routes"][route]
    elif mode in ("unknown", "did_mismatch", "duplicate"):
        rows = fixture.e["G5"]["routes"][route]["attempts"]
        if mode == "unknown":
            rows[0]["verdict"] = "AMBIGUOUS"
        elif mode == "did_mismatch":
            rows[0]["did"] = h("other-did")
        else:
            rows.append(copy.deepcopy(rows[0]))
    bundle = fixture.bundle()
    if mode == "local_only":
        b = bundle["packets"][5]["body"]["evidence"]["routes"][route]["external"]["body"]
        bundle["packets"][5]["body"]["evidence"]["routes"][route]["external"] = fixture.sign("independent", b)
        resign(fixture, bundle, 5)
    denied(result(fixture, bundle), "G5")
    if mode != "missing_route":
        details = result(fixture, bundle)["gates"][5]["post_routes"]
        assert len(details) == 5
        assert sum(x["status"] == "DENY" for x in details) == 1


@pytest.mark.parametrize("mode", ["unsigned", "forged", "self", "stale", "future", "epoch", "source", "duplicate", "unknown_field"])
def test_authenticated_boundary(fixture, mode):
    bundle = fixture.bundle()
    p = bundle["packets"][0]
    if mode == "unsigned":
        p["signature"] = ""
    elif mode == "forged":
        p["body"]["evidence"]["identity_digest"] = h("forged")
    elif mode == "self":
        fixture.trust.keys[fixture.ids["source"]] = (fixture.trust.keys[fixture.ids["source"]][0], frozenset({"independent"}))
        resign(fixture, bundle, 0, "source")
    elif mode == "duplicate":
        bundle["packets"][1] = copy.deepcopy(p)
    else:
        if mode == "stale":
            p["body"]["observed_at"] = NOW - 1000
        elif mode == "future":
            p["body"]["observed_at"] = NOW + 1
        elif mode == "epoch":
            p["body"]["context"]["generation"] += 1
        elif mode == "source":
            p["body"]["context"]["source_head"] = "0" * 40
        else:
            p["body"]["evidence"]["unexpected"] = "UNTRUSTED_SENTINEL"
        resign(fixture, bundle, 0)
    report = result(fixture, bundle)
    denied(report, "G0")
    assert "UNTRUSTED_SENTINEL" not in json.dumps(report)


@pytest.mark.parametrize("field,value", [("generation", 8), ("start", NOW - 100), ("end", NOW + 1),
                                        ("online_backup", False), ("wal_accounted", False), ("integrity_ok", False)])
def test_source_only_or_cross_epoch_database_images_deny(fixture, field, value):
    fixture.e["G6"]["images"][r.DATABASES[1]][field] = value
    denied(result(fixture), "G6")


def test_manifest_restore_binding_cannot_be_swapped(fixture):
    bundle = fixture.bundle()
    bundle["packets"][7]["body"]["evidence"]["images_digest"] = h("other-images")
    resign(fixture, bundle, 7)
    denied(result(fixture, bundle), "G7", "RESTORE_BINDING")


@pytest.mark.parametrize("mode", ["missing", "reuse", "wrong_binding", "not_later"])
def test_owner_approvals_separate_and_bound(fixture, mode):
    bundle = fixture.bundle()
    e = bundle["packets"][8]["body"]["evidence"]
    if mode == "missing":
        e["retirement_approval"] = None
    elif mode == "reuse":
        e["retirement_approval"] = e["cutover_approval"]
    else:
        b = e["retirement_approval"]["body"]
        if mode == "wrong_binding":
            b["binding"] = h("unrelated-release")
        else:
            b["approved_at"] = e["cutover_approval"]["body"]["approved_at"]
        e["retirement_approval"] = fixture.sign("owner", b)
    resign(fixture, bundle, 8)
    denied(result(fixture, bundle), "G8")
    assert result(fixture, bundle)["gates"][8]["approvals"]["cutover_approval"]["status"] == "PASS"


@pytest.mark.parametrize("coverage", ["capture", "resident", "restart", "manual", "cron", "tclk"])
def test_independent_capture_resident_and_launchers_cannot_be_omitted(fixture, coverage):
    fixture.e["G4"]["coverage"].remove(coverage)
    denied(result(fixture), "G4", "ADMISSION_COVERAGE")


@pytest.mark.parametrize("mode", ["future", "stale", "expired", "approval_after_start"])
def test_fence_time_is_not_a_prediction(fixture, mode):
    if mode == "future":
        fixture.e["G4"]["held_until"] = NOW + 1
    elif mode == "stale":
        fixture.e["G4"]["held_until"] = NOW - 31
    elif mode == "expired":
        fixture.e["G4"]["lease_expires_at"] = NOW
    bundle = fixture.bundle()
    if mode == "approval_after_start":
        approval = bundle["packets"][4]["body"]["evidence"]["approval"]["body"]
        approval["approved_at"] = NOW - 10
        bundle["packets"][4]["body"]["evidence"]["approval"] = fixture.sign("owner", approval)
        resign(fixture, bundle, 4)
    denied(result(fixture, bundle), "G4")


def test_current_full_source_budget_cannot_be_assumed_to_fit_k137(fixture):
    fixture.e["G2"].update(source_bytes=20 * r.GIB, encrypted_peak_bytes=21 * r.GIB,
                           rollback_bytes=20 * r.GIB, free_bytes=60 * 1000**3)
    denied(result(fixture), "G2", "INSUFFICIENT_SPACE")


def test_no_self_enrollment_from_input(fixture):
    report = r.evaluate(fixture.bundle(), now=NOW)
    assert all(x["reason"] == "TRUST_NOT_ENROLLED" for x in report["gates"])
    denied(report, "G0")


@pytest.mark.parametrize("raw", [b'{"packets":[],"packets":[]}', b'{"x":NaN}', b'[' * 3000,
                                 b' ' * (r.MAX_PACKET_BYTES + 1), b'\xff'],
                         ids=["duplicate", "nan", "deep", "oversized", "encoding"])
def test_strict_bounded_json(raw):
    with pytest.raises(r.Deny):
        r.decode(raw)


def test_cli_empty_plan_and_untrusted_input_fail_closed_without_echo(fixture):
    for args, raw in (([], None), (["--stdin"], r.canonical(fixture.bundle())), (["--unexpected"], None)):
        p = subprocess.run([sys.executable, str(FILE), *args], input=raw, capture_output=True, timeout=10)
        assert p.returncode == 2 and p.stderr == b""
        report = json.loads(p.stdout)
        assert report["assessment"] == "DENY"
        assert report["oci_retirement"] == "STRICT_NO_GO"
        assert fixture.context["host"].encode() not in p.stdout


def test_reuses_audited_constants_and_protected_source_no_io(fixture, monkeypatch):
    assert r.ROUTES == tuple(r.ROUTES_CONTRACT.SIGN_POST_ROUTES.values())
    assert len(r.TEMPLATES) == 27 and len(r.DATABASES) == 2 and len(r.LEDGERS) == 4
    import builtins
    import socket
    import sqlite3
    def forbidden(*args, **kwargs):
        pytest.fail("offline evaluator attempted an effect")
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    assert result(fixture)["assessment"] == "EVIDENCE_VALID"


def test_r1082_real_oci_cardinality_can_be_attested_without_live_go(fixture):
    """R1081 original counted 30,682, exceeding the old G7 ceiling."""
    assert r.MAX_ARCHIVE_ENTRIES == 100000
    fixture.e["G7"]["source_files"] = 30682
    fixture.e["G7"]["restored_files"] = 30682
    report = result(fixture)
    assert next(x for x in report["gates"] if x["gate"] == "G7")["status"] == "PASS"
    assert report["cutover"] == "NO_GO"
    assert report["oci_retirement"] == "STRICT_NO_GO"
    assert report["production_trust_enrolled"] is False


@pytest.mark.parametrize("source_count,restored_count", [
    (100001, 100001), (30682, 30681), (30682, 100001), (100001, 30682),
])
def test_r1082_g7_cardinality_still_fails_closed(fixture, source_count, restored_count):
    fixture.e["G7"]["source_files"] = source_count
    fixture.e["G7"]["restored_files"] = restored_count
    denied(result(fixture), "G7", "SCHEMA_INVALID" if source_count > 100000 or restored_count > 100000 else "FULL_SET_MISMATCH")


def _r1083_split_budget(fixture):
    """Synthetic signatures model separate pre-existing disk capacity only."""
    e = fixture.e["G2"]
    e.update(source_bytes=26 * r.GIB, encrypted_peak_bytes=27 * r.GIB,
             rollback_bytes=26 * r.GIB, sqlite_bytes=r.GIB, free_bytes=55 * r.GIB)
    offhost = {"context": fixture.context, "observed_at": NOW - 2,
               "filesystem_digest": h("distinct-owner-existing-filesystem"),
               "free_bytes": 35 * r.GIB, "reserve_bytes": r.GIB,
               "location": "EXISTING_OWNER_OFFHOST_NOT_OCI_OR_K137",
               "existing_private_storage": True, "zero_incremental_cost": True}
    e["offhost_receipt"] = fixture.sign("independent", offhost)
    e["offhost_approval"] = fixture.approval("offhost_existing_disk", r.sha({
        "receipt": e["offhost_receipt"], "encrypted_peak_bytes": e["encrypted_peak_bytes"],
        "source_bytes": e["source_bytes"], "destination_free_bytes": e["free_bytes"]}))
    return e


def test_r1083_signed_split_disk_geometry_unblocks_only_g2_not_real_release(fixture):
    _r1083_split_budget(fixture)
    report = result(fixture)
    assert next(x for x in report["gates"] if x["gate"] == "G2")["status"] == "PASS"
    assert report["cutover"] == "NO_GO"
    assert report["oci_retirement"] == "STRICT_NO_GO"
    assert report["production_trust_enrolled"] is False


def test_r1083_legacy_single_disk_remains_strict(fixture):
    e = _r1083_split_budget(fixture)
    del e["offhost_receipt"]
    del e["offhost_approval"]
    denied(result(fixture), "G2", "INSUFFICIENT_SPACE")


@pytest.mark.parametrize("failure", [
    "missing_approval", "unsigned_offhost_bytes", "offhost_exhausted",
    "aws_headroom_exhausted", "untrusted_site", "unapproved_cost",
    "stale_receipt", "no_private_custody",
])
def test_r1083_split_requires_fresh_independent_custody_and_space(fixture, failure):
    e = _r1083_split_budget(fixture)
    if failure == "missing_approval":
        del e["offhost_approval"]
    elif failure == "aws_headroom_exhausted":
        e["free_bytes"] = 40 * r.GIB
    else:
        raw = copy.deepcopy(e["offhost_receipt"]["body"])
        if failure == "unsigned_offhost_bytes":
            e["offhost_receipt"]["body"]["free_bytes"] = 999 * r.GIB
        else:
            if failure == "offhost_exhausted": raw["free_bytes"] = 27 * r.GIB
            if failure == "untrusted_site": raw["location"] = "K137"
            if failure == "unapproved_cost": raw["zero_incremental_cost"] = False
            if failure == "stale_receipt": raw["observed_at"] = NOW - r.MAX_AGE - 1
            if failure == "no_private_custody": raw["existing_private_storage"] = False
            e["offhost_receipt"] = fixture.sign("independent", raw)
            e["offhost_approval"] = fixture.approval("offhost_existing_disk", r.sha({
                "receipt": e["offhost_receipt"],
                "encrypted_peak_bytes": e["encrypted_peak_bytes"],
                "source_bytes": e["source_bytes"],
                "destination_free_bytes": e["free_bytes"]}))
    denied(result(fixture), "G2")
