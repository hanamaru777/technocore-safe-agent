"""Connected real crypto/SQLite integration on disposable offline roots only."""
import copy
import json
import os
from pathlib import Path

import pytest

import test_r1117_integrated as prior
import test_r1160_owner_continuity as custody_prior
from test_r1163_unified import K, U, P, NOW, h

f, posts, frozen, custody = prior.f, prior.posts, prior.frozen, prior.custody
case = custody_prior.case
C = prior.C


@pytest.fixture
def migration(f,posts,frozen,custody,tmp_path):
    roots,_ = frozen; files,_,exports,witnesses = posts
    state = roots["state"]; state.chmod(0o700)
    for name,data in files.items():
        path = state/name; path.parent.mkdir(parents=True,exist_ok=True)
        if path.exists(): path.chmod(0o600)
        path.write_bytes(data)
    (roots["app"]/"binary").write_bytes(bytes(range(256))*32)
    # Include metadata/links in the encrypted manifest; restore keeps symlinks
    # inert rather than enabling a runtime path before activation review.
    (roots["app"]/"inert-link").symlink_to("binary")
    os.link(roots["app"]/"binary", roots["app"]/"hardlink")
    for path in state.rglob("*"):
        if path.is_file(): path.chmod(0o400)
    state.chmod(0o500)
    files["verified-did.json"] = (state/"verified-did.json").read_bytes()
    _,manifest,_ = C.R.T._census_roots(roots,C.G.SOURCE_HEAD,epoch="FROZEN:"+prior.h("epoch"))
    inventory = prior.M.state_inventory(manifest)
    ledger = prior.M.P.ledger_digest(files,inventory); ctl = f.controller(ledger)
    for room,witness in list(witnesses.items()):
        data = witness["body"]["data"].copy(); data["ledger_digest"] = ledger
        witnesses[room] = f.signed("retained-export",data,"upstream")
    g3 = prior.g3_bundle(f,custody); dest = prior.destination(f); cap = 4*1024**2
    authority = prior.SyntheticArchiveAuthority(f)
    owner = prior.owner_packet(f,ctl,authority,files,inventory,exports,witnesses,g3,dest,cap)
    work = tmp_path/"trial"; work.mkdir(mode=0o700)
    trial = P.Trial(ctl,authority,work,mode="OFFLINE_TRIAL",clock=lambda:prior.NOW)
    recovery = bytearray(os.urandom(48))
    args = dict(roots=roots,files=files,inventory=inventory,did=f.did,exports=exports,witnesses=witnesses,
                g3=g3,owner=owner,destination=dest,recovery=recovery,source_cap=cap,run_id="c"*32)
    try:
        yield trial,args,manifest
    finally:
        recovery[:] = b"\0"*len(recovery)


def signed_restore(f, epoch):
    proof = dict(epoch_digest=C.G.sha(epoch),manifest_digest=epoch["manifest_digest"],ledger_digest=epoch["ledger_digest"],
                 images=epoch["images"],did_digest=f.context["did"],runtime_started=False,whole_archive_aead=True,scope="OFFLINE_TRIAL")
    rollback = dict(epoch_digest=C.G.sha(epoch),destination_writers_fenced=True,original_preserved=True,no_post_retry=True)
    return f.signed("r1117-restored",proof,"restorer"), f.signed("r1117-rollback-ready",rollback)


@prior.POSIX
def test_connected_capture_full_readback_restart_restore_and_new_only_baseline(f,migration):
    trial,args,manifest = migration
    before = {p:p.read_bytes() for p in args["roots"]["state"].rglob("*") if p.is_file()}
    captured = trial.capture(**args)
    assert captured["epoch"]["evidence_mode"] == "OFFLINE_TRIAL" and captured["cursors"] == [(1,7),(1,7)]
    assert not (trial.work/"ciphertext.wire").exists()
    with C.R.LockedArchive(trial.work/"offhost") as held:
        actual,_ = held.verify(bytes(args["recovery"]))
        assert actual == manifest
    runtime = P.new_only_plan(args["files"],args["inventory"],args["did"],captured["epoch"],f.trust)
    assert runtime["activation"] == "NO_GO" and set(runtime["baseline"]["old_ids"]) == set(prior.m.M.P.ROUTES)
    assert all(runtime["baseline"]["old_ids"].values())
    restarted = P.Trial(trial.pipe.controller,trial.pipe.authority,trial.work,mode="OFFLINE_TRIAL",clock=lambda:prior.NOW)
    with pytest.raises(P.K.Stop,match="ALREADY_ATTEMPTED"): restarted.capture(**args)
    local = restarted.restore(args["recovery"])
    assert local["state"] == "UNKNOWN" and local["cutover"] == "NO_GO"
    receipt,rollback = signed_restore(f,captured["epoch"])
    value = restarted.restore(args["recovery"],receipt=receipt,rollback=rollback)
    assert value["state"] == "PASS" and value["mode"] == "OFFLINE_TRIAL" and value["cutover"] == "NO_GO"
    assert all(p.read_bytes() == data for p,data in before.items())
    assert restarted.journal.latest["phase"] == "OFFLINE_TRIAL_VERIFIED"
    assert (trial.work/"quarantine"/("c"*32)/"state/verified-did.json").read_bytes() == args["files"]["verified-did.json"]
    assert not (trial.work/"quarantine"/("c"*32)/"app/inert-link").is_symlink()


@prior.POSIX
@pytest.mark.parametrize("fault",["g3","g4","g5","host","disk","wal","interrupt"])
def test_capture_fail_closed_no_retry_or_plaintext(migration,monkeypatch,fault):
    trial,args,_ = migration
    if fault == "g3": args["g3"]["proof"]["did"] = "did:key:synthetic-invalid"
    if fault == "g4": trial.pipe.controller.state = "FAULT_CLOSED"
    if fault == "g5": trial.pipe.authority = None
    if fault == "host": args["destination"]["body"]["data"]["source_host_key"] = h("wrong-host")
    if fault == "disk": args["destination"]["body"]["data"]["capacity"]["free_bytes"] = 20*1024**3
    if fault == "wal":
        path = args["roots"]["state"]/(C.G.DATABASES[0]+"-wal")
        path.chmod(0o600); path.write_bytes(b"corrupt-WAL"); path.chmod(0o400)
    if fault == "interrupt":
        def interrupted(*args,**kwargs): raise KeyboardInterrupt()
        monkeypatch.setattr(P.CaptureOutput,"write",interrupted)
    with pytest.raises(BaseException): trial.capture(**args)
    assert trial.journal.latest["phase"] == "INTERRUPTED_NO_BLIND_RETRY"
    assert not (trial.work/"quarantine").exists()
    with pytest.raises(P.K.Stop,match="ALREADY_ATTEMPTED"): trial.capture(**args)


@prior.POSIX
def test_restore_reauthenticates_archive_and_rejects_forged_independent_receipt(f,migration):
    trial,args,_ = migration; capture = trial.capture(**args)
    receipt,rollback = signed_restore(f,capture["epoch"])
    receipt["body"]["data"]["runtime_started"] = True
    with pytest.raises(ValueError): trial.restore(args["recovery"],receipt=receipt,rollback=rollback)
    assert trial.journal.latest["phase"] == "DISARMED_LOCAL_READBACK"
    # A same-archive resume reauthenticates everything before touching restore.
    part = next((trial.work/"offhost").glob("part-*.bin"))
    data = bytearray(part.read_bytes()); data[-1] ^= 1; part.write_bytes(data)
    with pytest.raises(Exception): trial.restore(args["recovery"])
    assert trial.journal.latest["phase"] == "RESTORE_INTERRUPTED_REVIEW_REQUIRED"


@prior.POSIX
def test_restore_interrupt_requires_explicit_same_archive_resume(migration,monkeypatch):
    trial,args,_ = migration; trial.capture(**args)
    real = P.BlocksIO.read; count = []
    def broken(self,size):
        count.append(1)
        if len(count)>1: raise OSError("SYNTHETIC_STREAM_INTERRUPTION")
        return real(self,size)
    with monkeypatch.context() as patch:
        patch.setattr(P.BlocksIO,"read",broken)
        with pytest.raises(Exception): trial.restore(args["recovery"])
    assert trial.journal.latest["phase"] == "RESTORE_INTERRUPTED_REVIEW_REQUIRED"
    assert trial.restore(args["recovery"])["restore"] == "DISARMED_LOCAL_READBACK"


def test_custody_guard_checks_real_synthetic_same_owner_binding_without_reading_cipher(case,monkeypatch):
    c = case; old = custody_prior; envelope,binding,retained = old.imported(c)
    old.m.commit_import(c["root"],binding,retained,c["plan"],c["packet"],envelope,old.M,control=c["new"],machine=c["machine"])
    monkeypatch.setattr(old.M,"control_identity",lambda:c["new"])
    loader = U.K.legacy
    monkeypatch.setattr(U.K,"legacy",lambda leaf: old.M if leaf=="r1157_operator.py" else old.m if leaf=="r1160_owner_continuity.py" else loader(leaf))
    read = Path.read_bytes
    def public_only(path):
        assert path.name not in ("approval.pem.enc","credentials.sealed.json"), "ciphertext must remain unopened"
        return read(path)
    monkeypatch.setattr(Path,"read_bytes",public_only)
    result = U.custody_metadata(capsule=c["root"]/"credentials.sealed.json")
    assert result["state"] == "PASS" and result["credential_use"] == "NO_GO" and result["private_material"] == "NOT_ACCESSED"
    monkeypatch.setattr(old.M,"control_identity",lambda:c["old"])
    with pytest.raises(ValueError): U.custody_metadata()


def stability(f):
    data = dict(epoch_digest=h("epoch"),manifest_digest=h("manifest"),source_boot=h("source-boot"),destination_boot=h("target-boot"),
                stable_since=prior.NOW-86400,observed_at=prior.NOW,original_did_digest=f.context["did"],
                source_permanent_deny=True,single_publisher=True,backup_full_readback=True,rollback_drill=True,
                destination_writers_fenced=True,ambiguous_posts=0)
    packet = f.signed("r1163-stable",data)
    consent = f.signed("r1163-final-review",dict(action="APP_ROLLBACK_REVIEW",evidence_sha256=P.K.sha(P.K.canonical(packet)),
                       retain_original_vm=True,retain_volumes=True,automatic_restart=False,retain_old_post_deny=True),"owner")
    return packet,consent


@pytest.mark.parametrize("fault",[None,"vm_stop","volume_delete","stale","short","did","deny","publishers","backup","unknown","consent","forged"])
def test_m7_separate_stable_app_review_never_vm_action(f,fault):
    packet,owner = stability(f); data = packet["body"]["data"]
    if fault == "did": data["original_did_digest"] = h("different-DID")
    if fault == "deny": data["source_permanent_deny"] = False
    if fault == "publishers": data["single_publisher"] = False
    if fault == "backup": data["backup_full_readback"] = False
    if fault == "unknown": data["ambiguous_posts"] = 1
    if fault == "short": data["stable_since"] += 1
    if fault == "consent": owner["body"]["data"]["retain_original_vm"] = False
    if fault == "forged": packet["signature"] = "00"*64
    action = "VM_STOP" if fault == "vm_stop" else "VOLUME_DELETE" if fault == "volume_delete" else "APP_ROLLBACK_REVIEW"
    if fault:
        with pytest.raises(ValueError): P.stable_gate(f.trust,packet,owner,now=prior.NOW+31 if fault=="stale" else prior.NOW,action=action)
    else:
        result = P.stable_gate(f.trust,packet,owner,now=prior.NOW)
        assert result["vm_stop"] == result["volume_delete"] == "NO_GO"


def test_app_rollback_uses_existing_exact_controller_and_no_vm_option():
    calls = []
    class Controller:
        def rollback(self,owner,witness,*,now):
            calls.append((owner,witness,now)); return {"phase":"RESTORED_DISARMED_POST_DENY_RETAINED"}
    assert P.app_rollback(Controller(),"owner","witness",now=NOW)["phase"] == "RESTORED_DISARMED_POST_DENY_RETAINED"
    assert calls == [("owner","witness",NOW)]
