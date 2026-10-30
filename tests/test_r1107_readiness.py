"""R1107 offline trials only. Fresh dummy keys, no hosts/credentials or writes.

FakeBackend is deliberately NOT a shipped Linux enforcement mechanism.
"""
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "packaging/migration"
spec = importlib.util.spec_from_file_location("r1107_tests", PKG / "r1107_readiness.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
C, B, P = m.C, m.B, m.P
NOW = 2000000000
POSIX = pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="unprivileged readonly SQLite WAL trial")
WIN = pytest.mark.skipif(os.name != "nt", reason="native PS5.1")


def h(label): return hashlib.sha256(label.encode()).hexdigest()
def raw(value): return C.G.canonical(value)


def did(key):
    value = b'\xed\x01' + key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    n = int.from_bytes(value, "big"); out = ""; chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    while n: n, r = divmod(n, 58); out = chars[r] + out
    return "did:key:z" + out


class Reader:
    def __init__(self, fixture):
        self.f = fixture
        self.values = {}
        missing = set(sorted(C.U.EXPECTED)[:8])
        names = set(C.U.EXPECTED) | set(C.U.HISTORICAL_EXTRAS) | {f"technocore-safe-agent-fixture-{i}.service" for i in range(7)}
        for name in sorted(names):
            p = {k: "" for k in B.PROPERTIES}
            p.update(Id=name, Names=name, LoadState="not-found" if name in missing else "loaded",
                     ActiveState="inactive", UnitFileState="disabled", Restart="no", Transient="no")
            if name not in missing:
                p.update(FragmentPath="/synthetic/" + name, ExecStart="/synthetic/wrapper --no-secret")
            self.values[name] = p
        self.unknown = None

    def identity(self): return {"host_digest": self.f.context["host"], "source_head": C.G.SOURCE_HEAD, "uid": 0, "roots_digest": C.G.sha(C.ROOTS)}
    def unit_files(self): return [n for n, p in self.values.items() if p["LoadState"] == "loaded"]
    def loaded(self): return sorted(self.unit_files())[:22]
    def properties(self, name): return copy.deepcopy(self.values[name])
    def surfaces(self):
        return {k: {"complete": k != self.unknown, "unknown": int(k == self.unknown), "digest": h(k)} for k in B.SURFACES}


class Backend:
    def __init__(self):
        self.events = []; self.denied = False; self.bad = False
        self.writable = self.unknown = self.directory = self.deleted_open = self.hardlink = 0
        self.all_namespaces = True
    def identity(self): return h("synthetic-kernel-boundary")
    def enforceable(self): return not self.bad
    def inspect(self, plan):
        C.need(not any((self.writable, self.unknown, self.directory, self.deleted_open, self.hardlink)) and self.all_namespaces, "G4_NOT_PROVABLE")
    def apply(self, plan):
        self.events += ["DENY_LAUNCH_AND_POST", "QUIESCE_WRITERS"]
        self.denied = True
        return {"synthetic_prior_state": h("prior")}
    def restore_exact(self, undo): self.denied = False; self.events.append("RESTORE_EXACT")
    def recover_undo(self, digest): return {"synthetic_prior_state": h("prior")}


class Fixture:
    def __init__(self, now=NOW):
        self.now = now
        self.keys = {r: Ed25519PrivateKey.generate() for r in (*sorted(C.ROLES), "source")}
        self.own = Ed25519PrivateKey.generate(); self.did = did(self.own)
        self.context = {"campaign": h("trial"), "host": h("original"), "destination": h("destination"),
                        "did": h(self.did), "source_head": C.G.SOURCE_HEAD, "generation": 9}
        self.enrolled = {"schema_version": 1, "context": self.context, "source_did": self.did, "keys": [
            {"public_hex": k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(), "role": role}
            for role, k in self.keys.items() if role != "source"], "source_key_ids": [self.kid("source")]}
        self.trust = C.Enrollment(self.enrolled)
        self.reader = Reader(self)
        self.private = B.collect(self.reader, now=self.now)
        self.coverage = self.make_coverage()
        self.review = self.signed("G1", {"census_digest": C.G.sha(self.private), "coverage": self.coverage,
            "scope_uid": 0, "roots_digest": C.G.sha(C.ROOTS)})

    def kid(self, role): return hashlib.sha256(self.keys[role].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()
    def signed(self, kind, data, role="independent", at=None, ttl=30):
        if at is None: at = self.now
        body = {"kind": kind, "context": self.context, "observed_at": at, "expires_at": at + ttl, "data": copy.deepcopy(data)}
        return {"signer": self.kid(role), "body": body, "signature": self.keys[role].sign(C.DOMAIN + raw(body)).hex()}

    def make_coverage(self):
        expected = {n: {"status": "audited_present" if p["LoadState"] == "loaded" else "audited_absent",
                       "config_digest": C.G.sha(p), "effective_aliases_checked": True, "launch_edges_checked": True}
                    for n, p in self.private["units"].items() if n in C.U.EXPECTED}
        return {"schema_version": 1, "observed_at": self.now, "source_head": C.G.SOURCE_HEAD, "host_digest": self.context["host"],
                "baseline": dict(expected=27, installed=19, missing=8, extras=11, loaded=22, active=13, writable_fds=4, unknown_fds=1),
                "units": {"expected": expected, "extras": [{"name_digest": h(n), "config_digest": C.G.sha(p),
                    "effective_aliases_checked": True, "launch_edges_checked": True} for n, p in self.private["units"].items() if n not in expected],
                    "unreadable_units": 0, "unresolved_unit_types": 0},
                "launchers": {k: {"census_digest": C.G.sha({"category": k, "surfaces": self.private["surfaces"]}),
                    "scanned": True, "relaunch_denied": True, "unknown": 0} for k in C.U.CATEGORIES},
                "descriptors": dict(scan_complete=True, active_writers=0, writable_fds=0, directory_fds=0, unknown_fds=0),
                "mounts": dict(namespace_count=2, all_namespaces_enumerated=True, all_aliases_reviewed=True, external_hardlinks=0, unknown_aliases=0)}

    def lease(self, ctl, ledger, *, at=None, previous=None, role="independent"):
        p = ctl.plan
        return self.signed("G4", {"plan_digest": C.G.sha(p), "epoch": p["epoch"], "census_digest": p["census_digest"],
            "backend_digest": p["backend_digest"], "sequence": previous["body"]["data"]["sequence"] + 1 if previous else 1,
            "previous": C.G.sha(previous) if previous else "0" * 64, "ledger_digest": ledger, "global_deny": True}, role, at)

    def controller(self, ledger=h("ledger")):
        backend = Backend(); ctl = B.Controller(self.trust, backend)
        plan = ctl.propose(C.G.sha(self.private), h("epoch"), backend.identity())
        owner = self.signed("apply", {"plan_digest": C.G.sha(plan)}, "owner")
        permit = self.signed("apply", {"plan_digest": C.G.sha(plan)})
        ctl.apply(plan, owner, permit, now=self.now)
        assert ctl.state == "AWAITING_LEASE"
        with pytest.raises(C.Stop): ctl.guard(now=self.now)
        ctl.renew(self.lease(ctl, ledger), now=self.now)
        return ctl


@pytest.fixture
def f(): return Fixture()


def test_private_actual_identity_census_binds_27_11_8_without_logging_names(f):
    assert len(f.private["units"]) == 38
    assert B.bind_review(f.private, f.review, f.trust, now=NOW) == C.G.sha(f.private)
    report = B.report(f.private)
    assert "fixture-0" not in str(report) and report["G4"] == "NO_GO"
    assert not B.LinuxMetadataReader().enforceable()


@pytest.mark.parametrize("case", ["old_four", "absent_unknown", "alias", "exec", "cron", "manual", "transient", "namespace", "four_fds", "unknown_fd", "wrong_source"])
def test_g1_proven_blockers_not_relabelled_as_pass(f, case):
    cov = copy.deepcopy(f.coverage); private = copy.deepcopy(f.private)
    if case == "old_four": cov["units"]["extras"] = cov["units"]["extras"][:4]
    if case == "absent_unknown": next(iter(cov["units"]["expected"].values()))["status"] = "unknown"
    if case == "alias": next(iter(cov["units"]["expected"].values()))["effective_aliases_checked"] = False
    if case == "exec": next(iter(private["units"].values()))["ExecStart"] += " --changed"
    if case in ("cron", "manual", "transient"): cov["launchers"][case]["unknown"] = 1
    if case == "namespace": cov["mounts"]["all_namespaces_enumerated"] = False
    if case == "four_fds": cov["descriptors"]["writable_fds"] = 4
    if case == "unknown_fd": cov["descriptors"]["unknown_fds"] = 1
    if case == "wrong_source": private["identity"]["host_digest"] = h("other")
    p = f.signed("G1", dict(census_digest=C.G.sha(private), coverage=cov, scope_uid=0, roots_digest=C.G.sha(C.ROOTS)))
    with pytest.raises(C.Stop): B.bind_review(private, p, f.trust, now=NOW)


def test_census_detects_effective_property_race_and_indirect_surface(f):
    reader = Reader(f); old = reader.properties; calls = []
    def changed(n):
        calls.append(n); p = old(n)
        if calls.count(n) > 1: p["DropInPaths"] = "/synthetic/replaced"
        return p
    reader.properties = changed
    with pytest.raises(C.Stop, match="CENSUS_RACE_STOP"): B.collect(reader, now=NOW)
    reader = Reader(f); reader.unknown = "interpreters"
    private = B.collect(reader, now=NOW)
    review = f.signed("G1", dict(census_digest=C.G.sha(private), coverage=f.coverage, scope_uid=0, roots_digest=C.G.sha(C.ROOTS)))
    with pytest.raises(C.Stop, match="LAUNCH_CLOSURE_UNPROVEN"): B.bind_review(private, review, f.trust, now=NOW)


def test_systemd_reader_is_fixed_readonly_and_bounded(monkeypatch):
    monkeypatch.setattr(B,"kernel_observation",lambda *a,**k:{"unknown_or_raced":1,"future_denial":"NOT_PROVEN"})
    commands = []
    def runner(argv, **kwargs):
        commands.append(argv); assert kwargs["shell"] is False
        return type("R", (), {"returncode": 0, "stdout": b'[{"unit_file":"x.service","state":"disabled"}]'})()
    assert B.LinuxMetadataReader(runner).unit_files() == ["x.service"]
    with pytest.raises(C.Stop): B.LinuxMetadataReader(runner).properties("x.service;reboot")
    assert len(commands) == 1 and "list-unit-files" in commands[0]
    assert all(not r["complete"] for r in B.LinuxMetadataReader(runner).surfaces().values())


@pytest.mark.parametrize("flag,value", [("writable", 4), ("unknown", 1), ("directory", 1), ("deleted_open", 1), ("hardlink", 1), ("all_namespaces", False)])
def test_no_source_or_mutation_on_unproven_global_boundary(f, flag, value):
    backend = Backend(); setattr(backend, flag, value)
    ctl = B.Controller(f.trust, backend); plan = ctl.propose(h("census"), h("epoch"), backend.identity())
    with pytest.raises(C.Stop): ctl.apply(plan, f.signed("apply", {"plan_digest": C.G.sha(plan)}, "owner"),
        f.signed("apply", {"plan_digest": C.G.sha(plan)}), now=NOW)
    assert backend.events == []


def test_independent_lease_renewal_replay_expiry_and_rollback(f):
    ctl = f.controller(); old = ctl.packet
    ctl.renew(f.lease(ctl, h("ledger"), at=NOW+10, previous=old), now=NOW+10)
    with pytest.raises(C.Stop): ctl.renew(old, now=NOW+11)
    assert ctl.state == "FAULT_CLOSED" and ctl.backend.denied
    binding = dict(plan_digest=C.G.sha(ctl.plan), undo_digest=C.G.sha(ctl.undo), destination_writers_fenced=True, post_finality_reconciled=True)
    with pytest.raises(C.Stop): ctl.rollback(f.signed("rollback", binding, "source"), f.signed("rollback", binding), now=NOW)
    ctl.rollback(f.signed("rollback", binding, "owner"), f.signed("rollback", binding), now=NOW)
    assert ctl.state == "ROLLED_BACK" and not ctl.backend.denied
    expired = f.controller()
    with pytest.raises(C.Stop): expired.guard(now=NOW+31)
    assert expired.backend.denied and expired.state == "FAULT_CLOSED"


@pytest.mark.parametrize("role", ["source", "owner", "upstream"])
def test_source_or_unrelated_role_cannot_issue_g4(f, role):
    ctl = f.controller(); old = ctl.packet
    with pytest.raises(C.Stop): ctl.renew(f.lease(ctl, h("ledger"), previous=old, role=role), now=NOW)
    assert ctl.state == "FAULT_CLOSED"


def test_power_loss_resume_requires_fresh_independent_same_checkpoint(f):
    ctl = f.controller(); saved = ctl.checkpoint()
    replacement = B.Controller(f.trust, ctl.backend)
    replacement.resume(saved, f.signed("resume", {"checkpoint_digest": C.G.sha(saved)}), now=NOW)
    assert replacement.guard(now=NOW)["epoch"] == ctl.plan["epoch"]
    bad = copy.deepcopy(saved); bad["plan"]["epoch"] = h("different")
    with pytest.raises(C.Stop): B.Controller(f.trust, ctl.backend).resume(bad, f.signed("resume", {"checkpoint_digest": C.G.sha(saved)}), now=NOW)


def signed_row(key, room, nonce, text, seq):
    return {"from": did(key), "nonce": str(nonce), "text": text, "seq": seq,
            "ts": "2033-05-18T03:33:20Z", "sig": base64.urlsafe_b64encode(key.sign(f"{room}|{nonce}|{text}".encode())).rstrip(b'=').decode()}


@pytest.fixture
def posts(f):
    P.protocol()
    files = {}; rooms = {}; counters = {}
    def put(name, value): files[name] = raw(value)
    def row(room, nonce, text):
        r = signed_row(f.own, room, nonce, text, len(rooms.setdefault(room, []))+1)
        rooms[room].append(r); counters[f.did+"|"+room] = nonce
        return r
    identity = "c"*20; r = row("lobby", 101, "synthetic fixed public reply")
    put("autopilot/autopilot-outbox.json", {"outbox": {identity: {"room": "lobby", "status": "acknowledged"}}})
    put("signer/oracle-signer-receipts.json", {"schema_version": 1, "receipts": {identity: dict(state="acknowledged", did=f.did,
        nonce="101", text_hash=h(r["text"]), receipt_hash=h(f"{identity}|{f.did}|101|{r['text']}"), prepared_at="synthetic")}})
    r = row("tclk-offers", 102, "tclk1 synthetic accept")
    a = {k: None for k in P.ACCEPT_FIELDS.split()}
    a.update(schema_version=1,state="posted",stage_id="a"*32,did=f.did,nonce="102",sig=r["sig"],accept_line=r["text"],accept_sha256=h(r["text"]),seq=1)
    put("signer/tclk-pilot-accepts/"+"a"*32+".json", a)
    r = row("d-synthetic-deal",103,"tclk1 synthetic reveal")
    a = {k: None for k in P.REVEAL_FIELDS.split()}
    a.update(schema_version=1,state="reveal_ambiguous",stage_id="b"*32,did=f.did,nonce="103",sig=r["sig"],deal_room="d-synthetic-deal",reveal_sha256=h(r["text"]),reveal_seq=None)
    put("signer/tclk-pilot-reveal-publishes/"+"b"*32+".json",a)
    maker = Ed25519PrivateKey.generate()
    def leg(i):
        terms = dict(id="synthetic-"+str(i),maker=did(maker),side="buy",qty="1",px="100",until=12,taker="any")
        sig = base64.urlsafe_b64encode(maker.sign(P.close_call.maker_signature_preimage(terms).encode())).rstrip(b'=').decode()
        taker = base64.urlsafe_b64encode(f.own.sign(P.close_call.taker_signature_preimage(terms,f.did).encode())).rstrip(b'=').decode()
        text = json.dumps(dict(t="trade",season=P.close_call.CONTEST_ID,terms=terms,taker=f.did,maker_sig=sig,taker_sig=taker),separators=(',',':'),sort_keys=True)
        row("close1", 104+i, text)
        return dict(trade_id=terms["id"],maker=terms["maker"],maker_side="buy",qty="1",px="100",until=12,maker_sig=sig)
    single = leg(0); batch = {"legs": [leg(1),leg(2)]}
    put("signer/close1-approved-trade.json",single);put("signer/close1-approved-batch.json",batch)
    for i,x in enumerate([single,*batch["legs"]]):
        approval = "signer/close1-approved-batch.json" if i else "signer/close1-approved-trade.json"
        v = dict(schema_version=1, owner_did=f.did, trade_id=x["trade_id"],approval_sha256=C.raw_hash(files[approval]),offer_room="synthetic-offer",offer_seq=1,room="close1",nonce=str(104+i))
        if i:v["batch"]=True
        name="signer/close1-attempt-"+h(x["trade_id"])+".json"
        put(name,v);put(name.replace("attempt-","receipt-"),{**v,"status":"posted","seq":i+1,"ts":"2033-05-18T03:33:20Z"})
    put("nonces.json",counters)
    ctl = f.controller(P.ledger_digest(files))
    exports = {room:(b''.join(raw(r)+b'\n' for r in rows),"7") for room,rows in rooms.items()}
    witnesses = {room:f.signed("retained-export", dict(room_digest=h(room),export_digest=C.raw_hash(pair[0]),generation=pair[1],
        epoch=h("epoch"),ledger_digest=P.ledger_digest(files),source="https://technocore.chat/r/{room}/export",semantics="RETAINED_POSITIVE_ONLY"),"upstream") for room,pair in exports.items()}
    return files,ctl,exports,witnesses


def test_all_five_original_routes_and_each_close1_leg_match_but_not_fake_finality(f,posts):
    files,ctl,exports,witnesses=posts
    result=P.reconcile(files,f.did,ctl,exports,witnesses,f.trust,now=NOW)
    assert [r["retained_positive_matches"] for r in result["routes"]]==[1,1,1,1,2]
    assert result["G5"]=="NO_GO" and result["source_archive"]=="NO_GO"
    assert all(r["retry_authority"]=="NONE" and not r["history_complete"] for r in result["routes"])
    assert f.did not in str(result) and "synthetic fixed" not in str(result)


@pytest.mark.parametrize("room",["lobby","tclk-offers","d-synthetic-deal","close1"])
@pytest.mark.parametrize("case",["missing","forged","wrong_generation","duplicate_seq","duplicate_nonce","bad_signature","negative"])
def test_g5_fails_closed_per_route_without_retry_or_false_negative(f,posts,room,case):
    files,ctl,exports,witnesses=posts
    if case=="missing":exports[room]=(b'',"7")
    elif case=="forged":witnesses[room]["signature"]="0"*128
    elif case=="wrong_generation":exports[room]=(exports[room][0],"8")
    elif case in ("duplicate_seq","duplicate_nonce","bad_signature"):
        rows=[C.decode(line) for line in exports[room][0].splitlines()]
        if case=="bad_signature":rows[0]["sig"]="A"*86
        else:
            duplicate=copy.deepcopy(rows[0]);duplicate["seq"]=rows[-1]["seq"]+1 if case=="duplicate_nonce" else rows[0]["seq"]
            rows.append(duplicate)
        exports[room]=(b''.join(raw(r)+b'\n' for r in rows),"7")
        proof=witnesses[room]["body"]["data"].copy();proof["export_digest"]=C.raw_hash(exports[room][0])
        witnesses[room]=f.signed("retained-export",proof,"upstream")
    else:
        w=witnesses[room]["body"]["data"].copy();w["semantics"]="DEFINITELY_NOT_ACCEPTED"
        witnesses[room]=f.signed("retained-export",w,"upstream")
    with pytest.raises((C.Stop,ValueError)):
        P.reconcile(files,f.did,ctl,exports,witnesses,f.trust,now=NOW)
    assert ctl.backend.events==["DENY_LAUNCH_AND_POST","QUIESCE_WRITERS"]


def full_plan(f):
    ctl=f.controller()
    pins=dict(original_host_key_digest=h("source-host-key"),destination_host_key_digest=h("destination-host-key"))
    images={name:dict(sha256=h(name),wal_sha256=h(name+"wal"),shm_sha256=h(name+"shm"),count=1,seq=1,epoch=h("epoch")) for name in C.G.DATABASES}
    g6=dict(epoch=h("epoch"),manifest_digest=h("manifest"),ledger_digest=h("ledger"),images=images,source_head=C.G.SOURCE_HEAD,
            barrier_plan_digest=C.G.sha(ctl.plan),whole_state_verified=True,source_bytes=4*m.GIB,evidence_mode="HELD_ORIGINAL_SCOPE")
    cap=dict(observed_at=f.now,free_bytes=64*m.GIB,memory_bytes=2*m.GIB,tradebot_peak_bytes=512*1024**2,
            flop_limit_bytes=256*1024**2,os_reserve_bytes=512*1024**2,margin_bytes=256*1024**2,cpu_psi_safe=True,zero_incremental_cost=True)
    plan=dict(schema_version=1,context=f.context,census=f.private,review=f.review,barrier_plan=ctl.plan,g4=ctl.packet,
        g5=f.signed("G5-retained",dict(epoch=h("epoch"),ledger_digest=h("ledger"),routes={r:dict(known_attempts=1,retained_positive_matches=1) for r in P.ROUTES},semantics="RETAINED_POSITIVE_ONLY"),"upstream"),
        g6=f.signed("G6",g6),destination=f.signed("destination",dict(host_pins=pins,capacity=cap),"destination"),
        source_bytes=4*m.GIB,legacy_plan_digest=h("old-owner-plan"),host_pins=pins)
    plan["owner"]=f.signed("owner-dryrun",dict(plan_digest=C.G.sha(plan),mode="DRY_RUN_ONLY",original_head=C.G.SOURCE_HEAD),"owner")
    return {"enrollment":f.enrolled,"plan":plan}


def reseal_owner(f,control):
    plan=control["plan"]
    plan["owner"]=f.signed("owner-dryrun",dict(plan_digest=C.G.sha({k:v for k,v in plan.items() if k!="owner"}),mode="DRY_RUN_ONLY",original_head=C.G.SOURCE_HEAD),"owner")


def test_even_independently_signed_dryrun_never_starts_transfer_or_source_guard(f,monkeypatch):
    control=full_plan(f)
    monkeypatch.setattr(C.R,"owner",lambda *a,**k:pytest.fail("old unsafe source guard invoked"))
    monkeypatch.setattr(C.R,"child",lambda *a,**k:pytest.fail("external child invoked"))
    result=m.dry_run(control,now=NOW)
    assert result["transfer"]=="DISABLED" and result["G3"]==result["G5"]=="NO_GO"
    assert result["source_archive"]==result["cutover"]=="NO_GO" and not result["r987_custody_accessed"]


@pytest.mark.parametrize("case",["host_pin","short_disk","low_ram","reserve","g6_epoch","source_size","bad_head","fake_negative","missing_g4","expired","forged","missing_issuer"])
def test_final_owner_gate_all_negative_proofs_fail_closed(f,case):
    control=full_plan(f);p=control["plan"]
    if case=="host_pin":p["host_pins"]["destination_host_key_digest"]=h("changed")
    if case in ("short_disk","low_ram","reserve"):
        data=p["destination"]["body"]["data"]
        if case=="short_disk":data["capacity"]["free_bytes"]=m.RESERVE+4*m.GIB
        if case=="low_ram":data["capacity"]["memory_bytes"]=m.GIB
        if case=="reserve":data["capacity"]["margin_bytes"]=0
        p["destination"]=f.signed("destination",data,"destination")
    if case in ("g6_epoch","source_size","bad_head"):
        data=p["g6"]["body"]["data"]
        if case=="g6_epoch":next(iter(data["images"].values()))["epoch"]=h("other")
        if case=="source_size":data["source_bytes"]=1
        if case=="bad_head":data["source_head"]="0"*40
        p["g6"]=f.signed("G6",data)
    if case=="fake_negative":
        data=p["g5"]["body"]["data"];data["semantics"]="DEFINITELY_NOT_ACCEPTED";p["g5"]=f.signed("G5-retained",data,"upstream")
    if case=="missing_g4":p["g4"]={}
    if case=="forged":p["review"]["signature"]="0"*128
    if case=="missing_issuer":control["enrollment"]["keys"]=[]
    reseal_owner(f,control)
    with pytest.raises((C.Stop,ValueError,KeyError)):
        m.dry_run(control,now=NOW+31 if case=="expired" else NOW)


@pytest.fixture
def frozen(f,tmp_path):
    if os.name!="posix" or os.geteuid()==0:pytest.skip("POSIX read-only WAL fixture")
    app=tmp_path/"app";state=tmp_path/"state";origin=tmp_path/"origin"
    app.mkdir(mode=0o700);state.mkdir(mode=0o700);origin.mkdir(mode=0o700)
    (app/"module.py").write_bytes(b"# synthetic source")
    (state/"verified-did.json").write_bytes(raw({"did":f.did}))
    (state/"nonces.json").write_bytes(raw({f.did+"|lobby":200}))
    for name in C.G.DATABASES:
        connection=sqlite3.connect(origin/name)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE messages(seq INTEGER PRIMARY KEY,text TEXT)")
        connection.execute("INSERT INTO messages VALUES(7,'synthetic')");connection.commit()
        for suffix in ("","-wal","-shm"):(state/(name+suffix)).write_bytes((origin/(name+suffix)).read_bytes())
        connection.close()
    for p in state.iterdir():p.chmod(0o400)
    state.chmod(0o500)
    roots={"app":app,"state":state}
    _,manifest,_=C.R.T._census_roots(roots,C.G.SOURCE_HEAD,epoch="FROZEN:"+h("epoch"))
    ctl=f.controller(C.G.sha(m.state_inventory(manifest)))
    try:yield roots,ctl
    finally:
        state.chmod(0o700)
        for p in state.iterdir():p.chmod(0o600)


@POSIX
def test_actual_two_sqlite_wal_full_state_common_epoch(f,frozen):
    roots,ctl=frozen
    result=m.common_epoch(ctl,roots,clock=lambda:NOW,offline_trial=True)
    assert len(result["images"])==2 and all(x["seq"]==7 for x in result["images"].values())
    assert all(x["epoch"]==h("epoch") and x["wal_sha256"] for x in result["images"].values())
    assert result["ledger_digest"]==ctl.packet["body"]["data"]["ledger_digest"]


@POSIX
def test_new_epoch_binding_reuses_frozen_r1089_aead_verifier(f,frozen,tmp_path):
    roots,ctl=frozen
    epoch=m.common_epoch(ctl,roots,clock=lambda:NOW,offline_trial=True)
    def census():return C.R.T._census_roots(roots,C.G.SOURCE_HEAD,epoch="FROZEN:"+h("epoch"))
    _,manifest,ids=census()
    key=os.urandom(48);wire=io.BytesIO()
    C.R.W.seal_manifest_to_stream(roots,manifest,ids,key,wire,recensus=census)
    tmp_path.chmod(0o700);archive=tmp_path/"encrypted"
    C.R.W.receive_offhost_ciphertext(io.BytesIO(wire.getvalue()),archive,quota_bytes=64*1024**2)
    packet=f.signed("G6",epoch)
    result=m.verify_backup_binding(archive,key,packet,f.trust,now=NOW)
    assert result["backup_aead"]=="VERIFIED_AND_G6_BOUND" and result["evidence_mode"]=="OFFLINE_TRIAL"
    assert result["source_archive"]=="NO_GO" and result["G7"]=="DESTINATION_RESTORE_NOT_PROVEN"
    with pytest.raises(C.Stop,match="BACKUP_AUTH_STOP"):
        m.verify_backup_binding(archive,os.urandom(48),packet,f.trust,now=NOW)
    bad=copy.deepcopy(epoch);bad["epoch"]=h("other")
    with pytest.raises(C.Stop,match="BACKUP_EPOCH_BINDING_STOP"):
        m.verify_backup_binding(archive,key,f.signed("G6",bad),f.trust,now=NOW)


@POSIX
def test_inode_based_kernel_reader_finds_aliased_fds_mmap_and_namespace_unknowns(tmp_path):
    root=tmp_path/"source";root.mkdir();item=root/"item";item.write_bytes(b'synthetic')
    alias=tmp_path/"outside-name";os.link(item,alias)
    proc=tmp_path/"proc";pid=proc/"1";(pid/"fd").mkdir(parents=True);(pid/"fdinfo").mkdir();(pid/"ns").mkdir()
    (pid/"ns/mnt").write_bytes(b'fake-namespace')
    (pid/"fd/5").symlink_to(alias);(pid/"fdinfo/5").write_bytes(b'flags:\t0100002\n')
    info=item.stat();dev=f"{os.major(info.st_dev):x}:{os.minor(info.st_dev):x}"
    (pid/"maps").write_text(f"1000-2000 rw-s 00000000 {dev} {info.st_ino} /outside/alias\n")
    (pid/"mountinfo").write_text(f"1 0 {os.major(info.st_dev)}:{os.minor(info.st_dev)} / / ro - ext4 /dev/synthetic ro\n")
    result=B.kernel_observation((root,),proc)
    assert result["writable_fds"]==1 and result["writable_mappings"]==1 and result["external_hardlinks"]==1
    assert result["future_denial"]=="NOT_PROVEN" and str(alias) not in str(result)
    (pid/"fd/6").symlink_to(tmp_path/"missing")
    assert B.kernel_observation((root,),proc)["unknown_or_raced"]>=1


def test_disarmed_smoke_receipts_never_start_runtime(f):
    control=full_plan(f);epoch=control["plan"]["g6"]
    value=dict(manifest_digest=h("manifest"),source_bytes=4*m.GIB,images=epoch["body"]["data"]["images"],
        runtime_started=False,write_root="/var/lib/flop-migration-r1066/disarmed",uid=1000,memory_max=256*1024**2,
        tasks_max=64,cpu_percent=50,original_metadata_reviewed=False)
    report=m.disarmed_smoke(epoch,f.signed("disarmed-restore",value,"restorer"),f.trust,now=NOW)
    assert report["activation"]=="DISABLED" and report["signer"]=="NOT_PROVEN"
    value["runtime_started"]=True
    with pytest.raises(C.Stop):m.disarmed_smoke(epoch,f.signed("disarmed-restore",value,"restorer"),f.trust,now=NOW)


@POSIX
@pytest.mark.parametrize("case",["wal_drift","state_drift","lost_lease","did_change"])
def test_common_epoch_cannot_combine_different_instant_or_custody(f,frozen,monkeypatch,case):
    roots,ctl=frozen
    original=C.R.T._census_roots;calls=[]
    def census(*a,**k):
        result=original(*a,**k);calls.append(True)
        if len(calls)==1:
            if case=="lost_lease":ctl.packet["body"]["expires_at"]=NOW
            else:
                file=roots["state"]/(C.G.DATABASES[0]+"-wal" if case=="wal_drift" else "nonces.json" if case=="state_drift" else "verified-did.json")
                file.chmod(0o600)
                file.write_bytes(file.read_bytes()+b' ' if case!="did_change" else raw({"did":did(Ed25519PrivateKey.generate())}))
                file.chmod(0o400)
        return result
    monkeypatch.setattr(C.R.T,"_census_roots",census)
    with pytest.raises((C.Stop,ValueError,sqlite3.DatabaseError)):
        m.common_epoch(ctl,roots,clock=lambda:NOW,offline_trial=True)


@POSIX
def test_cleanup_review_never_deletes_and_excludes_all_state_and_unknowns(f,frozen):
    roots,ctl=frozen
    cache=roots["app"]/".pytest_cache";cache.mkdir();(cache/"example").write_bytes(b"regenerable")
    _,manifest,_=C.R.T._census_roots(roots,C.G.SOURCE_HEAD,epoch="FROZEN:"+h("epoch"))
    proof=f.signed("restore",dict(manifest_digest=C.G.sha(manifest),backup_aead=True,restored_exact=True,same_did_preserved=True,incomplete=False),"restorer")
    selected={"app/.pytest_cache/example":b"regenerable","state/nonces.json":(roots["state"]/"nonces.json").read_bytes()}
    binding=dict(manifest_digest=C.G.sha(manifest),restore_digest=C.G.sha(proof),review_only=True,
        candidate_snapshot_digest=C.G.sha({k:dict(sha256=C.raw_hash(v),bytes=len(v)) for k,v in selected.items()}))
    result=m.cleanup_review(manifest,selected,proof,f.signed("retirement-review",binding),f.signed("retirement-review",binding,"owner"),f.trust,now=NOW)
    assert len(result["candidates"])==1 and result["deletion_authority"]=="NONE"
    assert (cache/"example").read_bytes()==b"regenerable"
    bad=proof["body"]["data"].copy();bad["incomplete"]=True
    with pytest.raises(C.Stop):m.cleanup_review(manifest,selected,f.signed("restore",bad,"restorer"),{}, {},f.trust,now=NOW)


def test_fixed_get_adapter_has_no_redirect_or_write_and_normalizes_failure(monkeypatch):
    seen=[]
    class Response:
        status=200;headers={"X-Room-Generation":"1"}
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def read(self,n):return b'{"seq":1}\n'
    class Open:
        def open(self,request,timeout):
            seen.append((request.full_url,request.get_method(),timeout));return Response()
    monkeypatch.setattr(P.urllib.request,"build_opener",lambda *a:Open())
    assert P.fetch_retained("lobby")[1]=="1"
    assert seen==[("https://technocore.chat/r/lobby/export","GET",15)]*2
    with pytest.raises(C.Stop):P.fetch_retained("p-private")
    with pytest.raises(C.Stop):P.fetch_retained("lobby?text=write")
    def fail(*a,**k):raise TimeoutError("SYNTHETIC_PRIVATE_ERROR")
    monkeypatch.setattr(Open,"open",fail)
    with pytest.raises(C.Stop,match="^UPSTREAM_READ_STOP$"):P.fetch_retained("lobby")


@WIN
def test_ps51_dryrun_missing_input_no_secret_prompt_no_network():
    p=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-File",str(PKG/"r1107_owner_dryrun.ps1")],capture_output=True,timeout=20)
    assert p.returncode==42 and p.stderr==b""
    result=json.loads(p.stdout)
    assert result["reason"]=="INDEPENDENT_EVIDENCE_REQUIRED" and result["source_archive"]=="NO_GO"


@WIN
def test_ps51_valid_independent_trial_plan_still_cannot_export_or_request_keys(tmp_path):
    f=Fixture(now=int(time.time()));control=full_plan(f)
    paths={"plan":tmp_path/"r1107-plan.json","enrollment":tmp_path/"r1107-enrollment.json"}
    for k,p in paths.items():p.write_bytes(raw(control[k]))
    setup=tmp_path/"dryrun.ps1"
    setup.write_text(r'''
$ErrorActionPreference='Stop'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
foreach($path in @('PLAN','ENROLLMENT')) {
 $acl=New-Object Security.AccessControl.FileSecurity
 $acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
 foreach($who in @($sid,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($who,'FullControl','Allow')))
 }
 [IO.File]::SetAccessControl($path,$acl)
}
& 'SCRIPT' -PlanFile 'PLAN' -PlanSha256 'PLANDIGEST' -EnrollmentFile 'ENROLLMENT' -EnrollmentSha256 'ENROLLDIGEST'
'''.replace("SCRIPT",str(PKG/"r1107_owner_dryrun.ps1")).replace("PLANDIGEST",C.raw_hash(paths["plan"].read_bytes()))
        .replace("ENROLLDIGEST",C.raw_hash(paths["enrollment"].read_bytes())).replace("ENROLLMENT",str(paths["enrollment"]))
        .replace("PLAN",str(paths["plan"])),encoding="utf-8-sig")
    p=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-File",str(setup)],capture_output=True,timeout=50)
    assert p.returncode==0 and p.stderr==b"",(p.stdout,p.stderr)
    result=json.loads(p.stdout)
    assert result["source_archive"]=="NO_GO" and result["transfer"]=="DISABLED" and not result["r987_custody_accessed"]
    assert f.did.encode() not in p.stdout and b'synthetic/wrapper' not in p.stdout


def test_source_did_key_never_acts_as_independent_authority(f):
    bad=copy.deepcopy(f.enrolled)
    bad["keys"][0]["public_hex"]=f.own.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
    bad["keys"][0]["role"]="independent"
    with pytest.raises(C.Stop,match="ISSUER_ROLE_STOP"):C.Enrollment(bad)


def test_private_json_nonfinite_and_duplicate_keys_are_rejected():
    for value in (b'{"x":NaN}',b'{"x":1,"x":2}'):
        with pytest.raises((C.Stop,ValueError)):C.decode(value)


def test_no_legacy_pin_or_protected_runtime_edit_and_no_mutation_primitives():
    expected={"r1089_migration.py":"154e740c94144c942206d3be85310f31471c2d41",
              "r1089_owner_control_pipe.cs":"f8d4d7f586a0cde53d1ffec06816869f47df0b11"}
    for name,pin in expected.items():
        code=(PKG/name).read_bytes().replace(b'\r\n',b'\n')
        assert hashlib.sha1(b'blob '+str(len(code)).encode()+b'\0'+code).hexdigest()==pin
    ps=(PKG/"r1107_owner_dryrun.ps1").read_text()
    for forbidden in ("Read-Host","ssh.exe","Invoke-WebRequest","Remove-Item","-PreserveAndRestore","Unprotect-R1027"):
        assert forbidden not in ps
    source=(PKG/"r1107_readiness.py").read_text()
    assert 'C.R.owner(' not in source and '.unlink(' not in source


def test_versioned_dependency_pins_cover_new_and_frozen_sources():
    def blob(path):
        code=path.read_bytes().replace(b'\r\n',b'\n')
        return hashlib.sha1(b'blob '+str(len(code)).encode()+b'\0'+code).hexdigest()
    table=PKG/"r1107_source_pins.json"
    for name,pin in json.loads(table.read_bytes()).items():assert blob(PKG/name)==pin,name
    assert blob(table) in (PKG/"r1107_owner_dryrun.ps1").read_text()


def test_retained_ring_miss_is_unknown_not_absence_or_retry(f,posts):
    files,ctl,exports,witnesses=posts
    room="lobby";other=signed_row(f.own,room,999,"later retained record",200)
    exports[room]=(raw(other)+b'\n',"7")
    data=witnesses[room]["body"]["data"].copy();data["export_digest"]=C.raw_hash(exports[room][0])
    witnesses[room]=f.signed("retained-export",data,"upstream")
    result=P.reconcile(files,f.did,ctl,exports,witnesses,f.trust,now=NOW)
    assert result["routes"][0]["unresolved_known"]==1 and result["negative_finality"]=="UNSUPPORTED_BY_OFFICIAL_READ_API"


@pytest.mark.parametrize("case",["missing_sidecar","nonce_rollback","wrong_did","approval_changed","epoch_changed"])
def test_original_sidecar_nonce_fence_and_epoch_not_faked(f,posts,case):
    files,ctl,exports,witnesses=posts
    if case=="missing_sidecar":del files["signer/close1-approved-batch.json"]
    if case=="nonce_rollback":files["nonces.json"]=raw({})
    if case=="wrong_did":f.did=did(Ed25519PrivateKey.generate())
    if case=="approval_changed":files["signer/close1-approved-trade.json"]+=b' '
    if case=="epoch_changed":ctl.plan["epoch"]=h("changed")
    with pytest.raises((C.Stop,ValueError)):
        P.reconcile(files,f.did,ctl,exports,witnesses,f.trust,now=NOW)
