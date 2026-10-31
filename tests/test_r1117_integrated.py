"""R1117 offline integration. Fresh dummy keys, no hosts/services/POST/Vault."""
import base64
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import test_r1107_readiness as old

PKG = old.PKG
sp = importlib.util.spec_from_file_location("r1117_test", PKG / "r1117_migration.py")
m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
C, S, M = m.C, m.S, m.M
B = C.legacy("r1117_boundary.py")
f, posts = old.f, old.posts
NOW, h = old.NOW, old.h
POSIX = old.POSIX


class MemoryJournal:
    def __init__(self): self.latest = None; self.values = []
    def save(self, value): self.latest = copy.deepcopy(value); self.values.append(self.latest)


class Consume:
    def __init__(self): self.seen = set()
    def __call__(self, digest):
        if digest in self.seen: return False
        self.seen.add(digest); return True


@pytest.fixture
def frozen(f,tmp_path):
    # Extend the proven fixture without changing its source/pins. Its teardown
    # predates nested route sidecars; repair only synthetic cleanup permissions.
    fixture=old.frozen.__wrapped__(f,tmp_path)
    roots,ctl=next(fixture)
    try:yield roots,ctl
    finally:
        try:next(fixture)
        except StopIteration:pass
        state=roots["state"];state.chmod(0o700)
        def private_dirs(parent):
            for p in parent.iterdir():
                if p.is_dir():p.chmod(0o700);private_dirs(p)
        private_dirs(state)


@pytest.fixture
def custody(f):
    receiver = X25519PrivateKey.generate()
    binding = S.request(f.trust, h("new-approved-challenge"), receiver.public_key().public_bytes_raw().hex())
    owner = f.signed("r1117-custody", binding, "owner")
    recipient = f.signed("r1117-custody", binding, "identity")
    texts = S.preimages(binding)
    proof = dict(binding=binding, did=f.did, say_signature=S.original().signature(f.own, texts[0]),
                 note_signature=S.original().signature(f.own, texts[1]))
    return receiver, binding, owner, recipient, proof


def test_g3_real_full_length_original_format_and_no_arbitrary_payload(f, custody):
    _, binding, owner, recipient, proof = custody
    checked = S.verify_proof(f.trust, binding, owner, recipient, proof, now=NOW, consume=Consume())
    assert checked["post"] == "DISABLED" and checked["real_custody"] == "NOT_PROVEN"
    say, note = S.preimages(binding)
    assert len(say.split("|", 2)[2]) == 4096 and len(note.split("|", 3)[3]) == 8192
    assert len(say.encode()) > 4096 and len(note.encode()) > 8192
    C.V.verify_did_signature(f.did, proof["say_signature"], say)
    assert len(proof["say_signature"]) == 86


@pytest.mark.parametrize("case", ["did", "host", "recipient", "tamper", "expired", "role", "new_fact"])
def test_g3_wrong_did_host_key_tamper_stale_authority_fail_closed(f, custody, case):
    _, binding, owner, recipient, proof = copy.deepcopy(custody)
    if case == "did": proof["did"] = old.did(old.Ed25519PrivateKey.generate())
    if case == "host": binding["destination"] = h("wrong-host")
    if case == "recipient": binding["recipient_hex"] = h("wrong-key")
    if case == "tamper": proof["note_signature"] = "A" * 86
    if case == "role": recipient = f.signed("r1117-custody", binding, "owner")
    if case == "new_fact": proof["text"] = "untrusted arbitrary message"
    with pytest.raises((C.Stop, ValueError)):
        S.verify_proof(f.trust, binding, owner, recipient, proof, now=NOW+31 if case=="expired" else NOW)


def test_g3_synthetic_recipient_and_password_envelopes_reused_no_replay(f, custody):
    receiver, binding, owner, recipient, _ = custody
    take = Consume(); dummy = bytearray(f.own.private_bytes_raw())
    proof, report = S.synthetic_custody_trial(dummy, receiver, b"dummy-only-offline-recovery-bytes", f.trust,
        binding, owner, recipient, take, now=NOW)
    assert dummy == bytearray(32) and report["mode"] == S.SYNTHETIC and report["live_import"] == "NOT_IMPLEMENTED"
    S.verify_proof(f.trust, binding, owner, recipient, proof, now=NOW)
    with pytest.raises(C.Stop, match="G3_REPLAY_STOP"):
        S.synthetic_custody_trial(bytearray(f.own.private_bytes_raw()), receiver,
            b"dummy-only-offline-recovery-bytes", f.trust, binding, owner, recipient, take, now=NOW)


def test_g3_wrong_recipient_and_unpinned_signer_never_unseal(f, custody, monkeypatch, tmp_path):
    receiver, binding, owner, recipient, _ = custody
    with pytest.raises(C.Stop):
        S.synthetic_custody_trial(bytearray(f.own.private_bytes_raw()), X25519PrivateKey.generate(),
            b"dummy-only-offline-recovery-bytes", f.trust, binding, owner, recipient, Consume(), now=NOW)
    wrong = tmp_path / "public-sign.py"; wrong.write_bytes(b"# mutated official source")
    monkeypatch.setattr(S, "SIGNER", wrong)
    with pytest.raises(C.Stop, match="G3_SIGNER_PIN_STOP"): S.preimages(binding)


def test_v249_real_text_lists_mixed_timer_properties_templates_and_missing_not_shown(monkeypatch):
    calls = []
    def runner(argv, **kwargs):
        calls.append(argv)
        if "list-unit-files" in argv: data=b"example.timer enabled enabled\nwriter@.service static -\n"
        elif "list-units" in argv: data=b"example.timer loaded active waiting Timer\n"
        elif "cat" in argv: data=b"# synthetic on-disk template\n[Service]\nExecStart=/synthetic\n"
        else: data=b"Id=example.timer\nNames=example.timer\nLoadState=loaded\nActiveState=active\nTriggers=writer.service\n"
        return type("Result", (), dict(returncode=0, stdout=data))()
    reader=B.MetadataReader(runner)
    assert reader.unit_files()==["example.timer","writer@.service"]
    assert reader.loaded()==["example.timer"]
    timer=reader.observed("example.timer")
    assert "Restart" in timer["unsupported_properties"] and "Restart" not in timer["properties"]
    assert reader.observed("writer@.service")["scope"]=="DISK_ONLY_NOT_LIVE_EQUIVALENCE"
    assert not any("--output=json" in c or "missing" in str(c) for c in calls)
    assert calls[-1][-3:]==["cat","--","writer@.service"]


@pytest.mark.parametrize("raw", [b"bad\n", b"x.service enabled\nx.service enabled\n", b"../../x.service enabled\n", b"x"*(2*1024**2+1),b"x.service imaginary\n"],
                         ids=["malformed", "duplicate", "traversal", "oversized", "invalid-state"])
def test_v249_bad_and_oversized_identity_lists_fail_closed(raw):
    with pytest.raises(C.Stop): B.rows(raw, files=True)


class Reader:
    def __init__(self, f): self.f = f; self.read = []
    def identity(self): return self.f.reader.identity()
    def unit_files(self): return self.f.reader.unit_files()
    def loaded(self): return self.f.reader.loaded()
    def surfaces(self): return self.f.reader.surfaces()
    def observed(self, name):
        self.read.append(name)
        return {"properties": self.f.reader.properties(name), "scope": "MANAGER_OBSERVED_NOT_GLOBAL_CLOSURE"}


def source_review(f, private):
    coverage=copy.deepcopy(f.coverage)
    for n, row in coverage["units"]["expected"].items():
        row["config_digest"]=C.G.sha({"absent_from_unit_files_and_loaded":n} if n in private["missing_expected"] else private["units"][n])
    for n in private["extras"]:
        next(r for r in coverage["units"]["extras"] if r["name_digest"]==h(n))["config_digest"]=C.G.sha(private["units"][n])
    return f.signed("r1117-G1", dict(census_digest=C.G.sha(private), coverage=coverage))


def test_exact_27_8_11_source_identities_no_missing_queries_and_no_false_global_proof(f):
    reader=Reader(f); private=B.plan_source(reader,now=NOW)
    assert len(private["missing_expected"])==8 and len(private["extras"])==11
    assert not set(reader.read)&set(private["missing_expected"])
    assert B.review_source(private,source_review(f,private),f.trust,now=NOW)==C.G.sha(private)
    for surface in ("cron","manual","transient","namespaces","inode_aliases"):
        bad=copy.deepcopy(private);bad["surfaces"][surface]["unknown"]=1
        with pytest.raises(C.Stop):B.review_source(bad,source_review(f,bad),f.trust,now=NOW)
    bad=copy.deepcopy(private);n=next(iter(bad["units"]))
    bad["units"][n]={"disk_digest":h("template"),"scope":"DISK_ONLY_NOT_LIVE_EQUIVALENCE"}
    with pytest.raises(C.Stop):B.review_source(bad,source_review(f,bad),f.trust,now=NOW)


def test_source_plan_race_and_time_budget_stop(f):
    reader=Reader(f); read=reader.observed
    def racing(name):
        value=read(name)
        if len(reader.read)>len(reader.unit_files()):value["properties"]["Restart"]="always"
        return value
    reader.observed=racing
    with pytest.raises(C.Stop,match="G4_CENSUS_RACE"):B.plan_source(reader,now=NOW)
    times=iter([0,36])
    with pytest.raises(C.Stop,match="G4_TIME_BUDGET_STOP"):B.plan_source(Reader(f),now=NOW,clock=lambda:next(times))


class Driver:
    def __init__(self): self.boot=h("boot"); self.events=[]; self.fail=None
    def identity(self):return h("independently-reviewed-test-driver")
    def boot_digest(self):return self.boot
    def enforceable(self):return True
    def inspect(self,plan):return {k:self.fail!=k for k in B.CAPABILITIES}
    def snapshot_undo(self,plan):return {"exact_original_state":h("prior-state")}
    def deny_launch_and_posts(self,plan):
        self.events.append("deny")
        if self.fail=="crash":raise SystemExit()
    def quiesce_exact(self,plan):self.events.append("quiesce")
    def restore_exact(self,undo):
        self.events.append("restore")
        if self.fail=="undo":raise OSError("PRIVATE_SYNTHETIC_FAILURE")
    def verify_restored(self,undo):return True


def admitted(f, journal, driver=None):
    driver=driver or Driver()
    admission=f.signed("r1117-backend",dict(backend_digest=driver.identity(),capabilities=sorted(B.CAPABILITIES),
        boot_digest=driver.boot_digest(),original_context=f.context))
    return B.JournalBackend(driver,journal,f.trust,admission,now=NOW,clock=lambda:NOW)


def authorize_backend(f,backend,plan):
    backend.authorize(plan,f.signed("apply",{"plan_digest":C.G.sha(plan)},"owner"),
        f.signed("apply",{"plan_digest":C.G.sha(plan)}),now=NOW)


@POSIX
def test_durable_undo_precedes_side_effects_crash_reboot_and_explicit_recovery(f,tmp_path):
    root=tmp_path/"undo";root.mkdir(mode=0o700)
    journal=B.UndoJournal(root); driver=Driver();backend=admitted(f,journal,driver)
    ctl=B.B.Controller(f.trust,backend);plan=ctl.propose(h("census"),h("epoch"),backend.identity())
    authorize_backend(f,backend,plan)
    driver.fail="crash"
    with pytest.raises(SystemExit):backend.apply(plan)
    assert driver.events==["deny"] and journal.latest["phase"]=="PREPARED"
    restarted=B.UndoJournal(root)
    assert restarted.latest["undo"]=={"exact_original_state":h("prior-state")}
    again=admitted(f,restarted,driver);authorize_backend(f,again,plan)
    with pytest.raises(C.Stop,match="G4_REPLAY_STOP"):again.apply(plan)
    driver.fail=None;driver.boot=h("new-boot")
    with pytest.raises(C.Stop,match="G4_REBOOT_REVIEW_REQUIRED"):backend.inspect(plan)
    after=admitted(f,restarted,driver)
    binding=dict(journal_digest=restarted.previous,plan_digest=C.G.sha(plan),undo_digest=C.G.sha(restarted.latest["undo"]),
        destination_writers_fenced=True,five_post_finality_verified=True,current_boot_digest=driver.boot)
    with pytest.raises(C.Stop):after.recover_interrupted({}, {},now=NOW)
    after.recover_interrupted(f.signed("r1117-recovery",binding,"owner"),f.signed("r1117-recovery",binding),now=NOW)
    assert B.UndoJournal(root).latest["phase"]=="RESTORED" and driver.events==["deny","restore"]


def test_no_mutation_before_durable_undo_and_restore_failure_stays_closed(f):
    journal=MemoryJournal();backend=admitted(f,journal)
    ctl=B.B.Controller(f.trust,backend);plan=ctl.propose(h("census"),h("epoch"),backend.identity())
    authorize_backend(f,backend,plan)
    def failed(value):raise OSError("SYNTHETIC_DISK_FULL")
    journal.save=failed
    with pytest.raises(OSError):backend.apply(plan)
    assert not backend.driver.events
    journal=MemoryJournal();backend=admitted(f,journal);authorize_backend(f,backend,plan);prior=backend.apply(plan)
    assert [v["phase"] for v in journal.values]==["PREPARED","DENIED","HELD"]
    backend.driver.fail="undo"
    with pytest.raises(C.Stop,match="G4_UNDO_FAILED"):backend.restore_exact(prior)
    assert journal.latest["phase"]=="RESTORE_FAILED_REVIEW_REQUIRED"


@pytest.mark.parametrize("capability",sorted(B.CAPABILITIES))
def test_global_denial_missing_capability_cannot_be_replaced_by_readonly_mount(f,capability):
    backend=admitted(f,MemoryJournal());backend.driver.fail=capability
    with pytest.raises(C.Stop,match="G4_NOT_PROVABLE"):backend.inspect({})
    assert backend.driver.events==[]


def test_g4_old_controller_short_lease_remains_authoritative(f):
    ctl=f.controller()
    with pytest.raises(C.Stop,match="G4_LOST"):ctl.guard(now=NOW+31)
    assert ctl.state=="FAULT_CLOSED" and ctl.backend.events==["DENY_LAUNCH_AND_POST","QUIESCE_WRITERS"]


def test_backend_cannot_apply_without_fresh_exact_owner_and_independent_approval(f):
    backend=admitted(f,MemoryJournal());ctl=B.Controller(f.trust,backend)
    plan=ctl.propose(h("census"),h("epoch"),backend.identity())
    with pytest.raises(C.Stop,match="G4_EXACT_APPROVAL_REQUIRED"):backend.apply(plan)
    owner=f.signed("apply",{"plan_digest":C.G.sha(plan)},"owner")
    permit=f.signed("apply",{"plan_digest":C.G.sha(plan)})
    ctl.apply(plan,owner,permit,now=NOW)
    assert ctl.state=="AWAITING_LEASE" and backend.driver.events==["deny","quiesce"]
    ctl.renew(f.lease(ctl,h("ledger")),now=NOW)
    assert ctl.guard(now=NOW)["global_deny"] is True
    expired=admitted(f,MemoryJournal());authorize_backend(f,expired,plan);expired.clock=lambda:NOW+31
    with pytest.raises(C.Stop):expired.apply(plan)
    assert expired.driver.events==[]
    reboot=admitted(f,MemoryJournal());authorize_backend(f,reboot,plan);reboot.driver.boot=h("later-boot")
    with pytest.raises(C.Stop,match="G4_REBOOT_REVIEW_REQUIRED"):reboot.apply(plan)
    assert reboot.driver.events==[] and reboot.journal.latest is None


@pytest.mark.parametrize("case",["retained","missing","timeout","409","claim_cas","duplicate_nonce"])
def test_five_route_unknown_history_never_becomes_negative_or_export(f,posts,case):
    files,ctl,exports,witnesses=posts
    if case=="missing":exports.pop("lobby")
    if case in ("timeout","409"):exports["lobby"]=(b'',None)
    if case=="duplicate_nonce":
        v=C.decode(files["signer/oracle-signer-receipts.json"])
        v["receipts"]["d"*20]=copy.deepcopy(next(iter(v["receipts"].values())))
        files["signer/oracle-signer-receipts.json"]=old.raw(v)
    result=m.RetainedHistory().reconcile(files,f.did,ctl,exports,witnesses,now=NOW)
    assert result["status"]=="UNKNOWN"
    with pytest.raises(C.Stop):m.verify_complete_authority(m.RetainedHistory(),files,f.did,ctl,exports,witnesses,now=NOW)
    assert not any("POST"==event for event in ctl.backend.events)


class SyntheticArchiveAuthority:
    """Full *synthetic* independent archive/CAS authority, not official API."""
    profile="SYNTHETIC_TEST_ONLY"
    def __init__(self,f):self.f=f
    def complete(self,**k):
        report=M.P.reconcile(k["files"],k["did"],k["controller"],k["exports"],k["witnesses"],self.f.trust,
            now=k["now"],inventory=k["inventory"])
        assert all(r["unresolved_known"]==0 for r in report["routes"])
        result=dict(epoch=report["epoch_digest"],ledger_digest=report["ledger_digest"],
            routes={route:[dict(id=r["id"],leg=r["leg"],nonce=r["nonce"],verdict="AUTHENTICATED_ACCEPTED",
                evidence_digest=h("fixture-full-authority-and-CAS-"+r["id"])) for r in rows] for route,rows in k["attempts"].items()},
            authority_digest=h("independently-authenticated-SYNTHETIC-full-archive"))
        packet=self.f.signed("r1117-SYNTHETIC-complete-index",result,"upstream")
        return self.f.trust.verify(packet,"r1117-SYNTHETIC-complete-index","upstream",k["now"])


def test_synthetic_history_authority_cannot_release_original(f,posts):
    files,ctl,exports,witnesses=posts
    with pytest.raises(C.Stop,match="G5_SYNTHETIC_AUTHORITY_STOP"):
        m.verify_complete_authority(SyntheticArchiveAuthority(f),files,f.did,ctl,exports,witnesses,now=NOW)
    renamed=SyntheticArchiveAuthority(f);renamed.profile="ALLEGED_REAL_AUTHORITY"
    with pytest.raises(C.Stop,match="G5_AUTHORITATIVE_COMPLETE_HISTORY_UNAVAILABLE"):
        m.verify_complete_authority(renamed,files,f.did,ctl,exports,witnesses,now=NOW)
    with pytest.raises(C.Stop):m.OneShot(ctl,trial="false")


def g3_bundle(f,custody):
    _,binding,owner,recipient,proof=custody
    data=dict(proof_digest=C.G.sha(proof),real_custody=False,recipient_binding=C.G.sha(binding),scope="OFFLINE_TRIAL")
    return dict(binding=binding,owner=owner,recipient=recipient,proof=proof,admission=f.signed("r1117-G3-portability",data,"identity"))


def destination(f):
    cap=old.full_plan(f)["plan"]["destination"]["body"]["data"]["capacity"]
    return f.signed("r1117-destination",dict(source_host=f.context["host"],destination_host=f.context["destination"],
        source_host_key=h("src-ssh-key"),destination_host_key=h("dst-ssh-key"),capacity=cap,runtime_started=False),"destination")


def owner_packet(f,ctl,authority,files,inventory,exports,witnesses,g3,dest,cap):
    finality=m.verify_complete_authority(authority,files,f.did,ctl,exports,witnesses,now=NOW,trial=True,inventory=inventory)
    held=ctl.guard(now=NOW)
    return f.signed("r1117-one-shot",dict(operation="R1117_OFFLINE_TRIAL",run_id="c"*32,
        barrier_plan_digest=held["plan_digest"],epoch=held["epoch"],ledger_digest=held["ledger_digest"],g3_digest=C.G.sha(g3),
        finality_digest=C.G.sha(finality),destination_digest=C.G.sha(dest),source_cap=cap),"owner")


class CipherOutput(io.BytesIO):
    host_pins=(h("src-ssh-key"),h("dst-ssh-key"))
    def __init__(self):super().__init__();self.recovery=os.urandom(48)
    def seal_using_existing_r1089(self,roots,manifest,ids,out,census):
        C.R.W.seal_manifest_to_stream(roots,manifest,ids,self.recovery,out,recensus=census)


@POSIX
@pytest.mark.parametrize("failure",[None,"transport_interrupt","host_pin","source_cap","wal_corrupt"])
def test_end_to_end_real_binary_sqlite_wal_ciphertext_independent_inert_restore(f,posts,frozen,custody,tmp_path,monkeypatch,failure):
    roots,_=frozen;files,_,exports,witnesses=posts
    state=roots["state"];state.chmod(0o700)
    for name,data in files.items():
        path=state/name;path.parent.mkdir(parents=True,exist_ok=True)
        if path.exists():path.chmod(0o600)
        path.write_bytes(data)
    (roots["app"]/"binary").write_bytes(bytes(range(256))*32)
    for path in state.rglob("*"):
        if path.is_file():path.chmod(0o400)
    state.chmod(0o500)
    files["verified-did.json"]=(state/"verified-did.json").read_bytes()
    _,manifest,_=C.R.T._census_roots(roots,C.G.SOURCE_HEAD,epoch="FROZEN:"+h("epoch"))
    inventory=M.state_inventory(manifest);ledger=M.P.ledger_digest(files,inventory);ctl=f.controller(ledger)
    for room,witness in list(witnesses.items()):
        data=witness["body"]["data"].copy();data["ledger_digest"]=ledger
        witnesses[room]=f.signed("retained-export",data,"upstream")
    g3=g3_bundle(f,custody);dest=destination(f);cap=4*1024**2;authority=SyntheticArchiveAuthority(f)
    owner=owner_packet(f,ctl,authority,files,inventory,exports,witnesses,g3,dest,cap)
    journal=MemoryJournal();out=CipherOutput();pipe=m.OneShot(ctl,authority,trial=True,clock=lambda:NOW)
    if failure=="transport_interrupt":
        def broken(block):raise OSError("SYNTHETIC_TRANSPORT_FAILURE")
        out.write=broken
        with pytest.raises(C.Stop,match="G6_TRANSFER_INTERRUPTED"):
            pipe.acquire(roots,files,inventory,f.did,exports,witnesses,g3,owner,dest,journal,out,source_cap=cap,run_id="c"*32)
        assert journal.latest["phase"]=="INTERRUPTED_NO_BLIND_RETRY"
        with pytest.raises(C.Stop,match="G6_ONE_SHOT_ALREADY_ATTEMPTED"):
            pipe.acquire(roots,files,inventory,f.did,exports,witnesses,g3,owner,dest,journal,out,source_cap=cap,run_id="c"*32)
        return
    if failure in ("host_pin","source_cap","wal_corrupt"):
        if failure=="host_pin":out.host_pins=(h("other-host"),h("dst-ssh-key"))
        if failure=="source_cap":
            cap=1;owner=owner_packet(f,ctl,authority,files,inventory,exports,witnesses,g3,dest,cap)
        if failure=="wal_corrupt":
            path=state/(C.G.DATABASES[0]+"-wal");path.chmod(0o600);path.write_bytes(b"broken");path.chmod(0o400)
        with pytest.raises(C.Stop):
            pipe.acquire(roots,files,inventory,f.did,exports,witnesses,g3,owner,dest,journal,out,source_cap=cap,run_id="c"*32)
        assert out.getvalue()==b"" and journal.latest is None
        return
    epoch=pipe.acquire(roots,files,inventory,f.did,exports,witnesses,g3,owner,dest,journal,out,source_cap=cap,run_id="c"*32)
    assert epoch["evidence_mode"]=="OFFLINE_TRIAL" and journal.latest["phase"]=="CIPHERTEXT_EMITTED_RESTORE_UNPROVEN"
    with pytest.raises(C.Stop,match="G6_ONE_SHOT_ALREADY_ATTEMPTED"):
        pipe.acquire(roots,files,inventory,f.did,exports,witnesses,g3,owner,dest,journal,out,source_cap=cap,run_id="c"*32)
    tmp_path.chmod(0o700);archive=tmp_path/"offhost";wire=out.getvalue()
    C.R.W.receive_offhost_ciphertext(io.BytesIO(wire),archive,quota_bytes=cap)
    with C.R.LockedArchive(archive) as locked:
        actual,verified=locked.verify(out.recovery);plain=io.BytesIO();locked.stream(out.recovery,plain)
    assert verified["manifest_sha256"]==epoch["manifest_digest"] and actual==manifest
    landing=tmp_path/"quarantine";landing.mkdir(mode=0o700)
    monkeypatch.setattr(C.R.D,"ROOT",landing);monkeypatch.setattr(C.R.D,"machine_digest",lambda:f.context["destination"])
    args=dict(quota_bytes=cap,expected_epoch="FROZEN:"+epoch["epoch"],expected_manifest_sha256=epoch["manifest_digest"],preserve_inert_links=True,resume=True)
    payload=plain.getvalue()
    with pytest.raises(ValueError):C.R.D.restore_stream(io.BytesIO(payload[:len(payload)//2]),"c"*32,f.context["destination"],os.geteuid(),**args)
    result=C.R.D.restore_stream(io.BytesIO(payload),"c"*32,f.context["destination"],os.geteuid(),**args)
    assert result["sqlite_cursors"]==[(1,7),(1,7)] and result["cutover"]=="NO_GO"
    assert (landing/("c"*32)/"state/verified-did.json").read_bytes()==files["verified-did.json"]
    proof=dict(epoch_digest=C.G.sha(epoch),manifest_digest=epoch["manifest_digest"],ledger_digest=epoch["ledger_digest"],
        images=epoch["images"],did_digest=f.context["did"],runtime_started=False,whole_archive_aead=True,scope="OFFLINE_TRIAL")
    rollback=dict(epoch_digest=C.G.sha(epoch),destination_writers_fenced=True,original_preserved=True,no_post_retry=True)
    checked=pipe.verify_restore(epoch,f.signed("r1117-restored",proof,"restorer"),f.signed("r1117-rollback-ready",rollback),now=NOW)
    assert checked["oci_retirement"]=="STRICT_NO_GO" and checked["cutover"]=="NO_GO"


def test_unknown_finality_blocks_before_common_epoch_or_output(f,posts,custody,monkeypatch,tmp_path):
    files,ctl,exports,witnesses=posts
    roots={"app":tmp_path/"app","state":tmp_path/"state"}
    for p in roots.values():p.mkdir(mode=0o700)
    # Root validation itself is mocked only for Windows ACL-independent test.
    monkeypatch.setattr(C.R.T,"offline_source",lambda p:p)
    monkeypatch.setattr(M,"common_epoch",lambda *a,**k:pytest.fail("source images read before G5"))
    out=CipherOutput();pipe=m.OneShot(ctl,trial=True,clock=lambda:NOW)
    with pytest.raises(C.Stop,match="G5_AUTHORITATIVE_COMPLETE_HISTORY_UNAVAILABLE"):
        pipe.acquire(roots,files,None,f.did,exports,witnesses,g3_bundle(f,custody),{},destination(f),MemoryJournal(),out,source_cap=100,run_id="c"*32)
    assert out.getvalue()==b""


@pytest.mark.parametrize("case",["disk","ram","reserve","cpu","cost"])
def test_capacity_protected_20gib_and_tradebot_not_relaxed(f,case):
    data=destination(f)["body"]["data"]["capacity"]
    if case in ("disk","reserve"):data["free_bytes"]=C.R.D.RESERVE
    if case=="ram":data["tradebot_peak_bytes"]=2*1024**3
    if case=="cpu":data["cpu_psi_safe"]=False
    if case=="cost":data["zero_incremental_cost"]=False
    with pytest.raises(C.Stop):M.capacity(data,source_bytes=1,now=NOW)


@pytest.mark.skipif(os.name!="nt",reason="native PS5.1")
def test_windows_ps51_onepass_disarmed_no_credentials_or_cloud():
    file=PKG/"r1117_owner_onepass.ps1"
    p=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-File",str(file),"-DryRun"],capture_output=True,timeout=20)
    assert p.returncode==42 and p.stderr==b""
    value=json.loads(p.stdout)
    assert value["G6"]=="NO_SOURCE_EXPORT" and value["oci_retirement"]=="STRICT_NO_GO"
    assert not any(x in file.read_text() for x in ("Read-Host","ssh.exe","Unprotect-R1027","Invoke-WebRequest"))


@pytest.mark.skipif(os.name!="nt",reason="native PS5.1")
def test_windows_valid_public_proof_checked_but_does_not_authorize_export(tmp_path):
    import time
    fresh=old.Fixture(now=int(time.time()))
    _,binding,owner,recipient,proof=custody.__wrapped__(fresh)
    paths={"proof":tmp_path/"r1117-public-proof.json","enrollment":tmp_path/"r1117-enrollment.json"}
    paths["proof"].write_bytes(old.raw(dict(binding=binding,owner=owner,recipient=recipient,proof=proof)))
    paths["enrollment"].write_bytes(old.raw(fresh.enrolled))
    script=tmp_path/"trial.ps1"
    text=r'''
$ErrorActionPreference='Stop'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
foreach($path in @('PROOFFILE','ENROLLFILE')) {
 $acl=New-Object Security.AccessControl.FileSecurity
 $acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
 foreach($who in @($sid,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($who,'FullControl','Allow')))
 }
 [IO.File]::SetAccessControl($path,$acl)
}
& 'SCRIPTFILE' -DryRun -PublicProofFile 'PROOFFILE' -PublicProofSha256 'PROOFSHA' -EnrollmentFile 'ENROLLFILE' -EnrollmentSha256 'ENROLLSHA'
exit $LASTEXITCODE
'''
    for marker,value in {"SCRIPTFILE":str(PKG/"r1117_owner_onepass.ps1"),"PROOFFILE":str(paths["proof"]),
        "ENROLLFILE":str(paths["enrollment"]),"PROOFSHA":C.raw_hash(paths["proof"].read_bytes()),
        "ENROLLSHA":C.raw_hash(paths["enrollment"].read_bytes())}.items():text=text.replace(marker,value)
    script.write_text(text,encoding="utf-8-sig")
    p=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-File",str(script)],capture_output=True,timeout=55)
    assert p.returncode==42 and p.stderr==b"", (p.stdout,p.stderr)
    result=json.loads(p.stdout)
    assert result["G3"]=="PUBLIC_CONTINUITY_VERIFIED_NOT_CUSTODY" and result["G6"]=="NO_SOURCE_EXPORT"
    assert fresh.did.encode() not in p.stdout and str(paths["proof"]).encode() not in p.stdout


def test_versioned_new_pin_map_preserves_all_legacy_dependency_blobs():
    import hashlib
    def blob(path):
        raw=path.read_bytes().replace(b'\r\n',b'\n')
        return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    pins=PKG/"r1117_source_pins.json"
    for name,value in json.loads(pins.read_bytes()).items():assert blob(PKG/name)==value,name
    assert blob(pins) in (PKG/"r1117_owner_onepass.ps1").read_text()
    assert (PKG/"r1117_owner_onepass.ps1").read_bytes().isascii()


def test_disarmed_service_no_key_provider_network_or_automatic_start():
    text=(PKG/"r1117-k137-signer-disarmed.service").read_text()
    for required in ("User=flop-signer","PrivateNetwork=yes","RestrictAddressFamilies=AF_UNIX","ProtectSystem=strict","LimitCORE=0","--disarmed-public-check"):
        assert required in text
    for forbidden in ("[Install]","Restart=","EnvironmentFile=","SupplementaryGroups=","Vault","KMS"):
        assert forbidden not in text
    p=subprocess.run([old.sys.executable,str(PKG/"r1117_migration.py"),"--execute"],capture_output=True,timeout=20)
    assert p.returncode==42 and json.loads(p.stdout)["G6"]=="NO_SOURCE_EXPORT"
