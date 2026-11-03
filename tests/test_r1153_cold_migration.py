"""New cold admission only. Synthetic keys/cold files, zero cloud/SSH/POST."""
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
from types import SimpleNamespace

import pytest
import test_r1107_readiness as old

ROOT = Path(__file__).resolve().parents[1]
sp = importlib.util.spec_from_file_location("r1153_test", ROOT/"packaging/migration/r1153_cold_migration.py")
m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
POSIX = pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="unprivileged cold filesystem fixtures")
WIN = pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1")


def raw(v): return m.G.canonical(v)
def h(v): return hashlib.sha256(v.encode()).hexdigest()


def sign(f, kind, data, role="independent", at=None):
    return f.signed("r1153-"+kind, data, role, at=at)


def owner(a):
    a.bundle["owner"] = sign(a.f, "owner", dict(
        bundle_sha=m.G.sha({k: v for k, v in a.bundle.items() if k != "owner"}),
        enrollment_sha=a.authority.pin, downtime=True, cold_capture=True, rollback=True,
        cost_cap="ZERO_NEW_BILLING", operation="PRESERVE_DISARMED_ONLY", operation_expires_at=a.f.now+3600), "owner")


def update(a, field, mutate, role="independent", kind=None):
    data = copy.deepcopy(a.bundle[field]["body"]["data"]); mutate(data)
    a.bundle[field] = sign(a.f, kind or field, data, role)
    owner(a)


@pytest.fixture
def case(tmp_path):
    f = old.Fixture(now=int(time.time())); f.context["destination"] = m.B.K137
    profile = dict(version=1, authority=f.enrolled, source_instance=h("instance"), boot_volume=h("boot"),
        attached_volumes=[h("boot"), h("state volume")], mounts=dict(app=h("boot"), state=h("state volume")), source_host_key=h("source host key"))
    authority = m.Authority(profile, m.G.sha(profile))
    roots = dict(app=tmp_path/"app", state=tmp_path/"state")
    for path in roots.values(): path.mkdir(mode=0o700)
    files, _, _, _ = old.posts.__wrapped__(f)
    files["verified-did.json"] = raw(dict(did=f.did))
    (roots["app"]/"example.py").write_bytes(b"# synthetic only\n")
    for name, data in files.items():
        path = roots["state"]/name; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700); path.write_bytes(data)
    origin = tmp_path/"db-origin"; origin.mkdir(mode=0o700)
    for name in sorted(m.G.DATABASES):
        connection = sqlite3.connect(origin/name)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE messages(seq INTEGER PRIMARY KEY,text TEXT)")
        connection.execute("INSERT INTO messages VALUES(7,'synthetic')"); connection.commit()
        for suffix in ("", "-wal", "-shm"):
            (roots["state"]/(name+suffix)).write_bytes(Path(str(origin/name)+suffix).read_bytes())
        connection.close()
    if os.name == "posix":
        # A fake RO kernel flag alone would still let SQLite alter the copied
        # SHM on CI. Match the existing immutable-copy test's actual permissions.
        for root in roots.values():
            for path in root.rglob("*"): path.chmod(0o500 if path.is_dir() else 0o400)
            root.chmod(0o500)
    # Exact census grammar also on Windows (old O_NOFOLLOW is POSIX only).
    entries = []
    def visit(path, name):
        st = path.lstat(); directory = path.is_dir()
        entries.append(dict(path=name, mode=st.st_mode & 0o7777, uid=st.st_uid, gid=st.st_gid,
            mtime_ns=st.st_mtime_ns, kind="directory" if directory else "file",
            size=0 if directory else st.st_size, sha256=None if directory else hashlib.sha256(path.read_bytes()).hexdigest(), target=None))
        if directory:
            for child in sorted(path.iterdir(), key=lambda p: os.fsencode(p.name)): visit(child, name+"/"+child.name)
    for key, path in roots.items(): visit(path, key)
    epoch = h("cold epoch")
    manifest = dict(version=1, source_head=m.G.SOURCE_HEAD, epoch="FROZEN:"+epoch, entries=entries)
    bundle = dict(version=1, run_id="c"*32, epoch=epoch, manifest=manifest)
    inventory = {row["path"][6:]: row["sha256"] for row in entries if row["kind"] == "file" and row["path"].startswith("state/")}
    bundle["inventory"] = m.normalized_attempts(files, f.did, inventory)
    _, _, images = m.check_manifest(bundle)
    images = [dict(image, count=1, seq=7) for image in images]
    acquisitions = dict(mount_table_sha=h("synthetic mounts"), bindings={key: dict(path_sha=m.G.sha(str(path)),
        # Synthetic Linux attestation: NTFS unsigned device IDs are not Linux IDs.
        device=path.stat().st_dev & (2**63-1), inode=path.stat().st_ino & (2**63-1), capture=h("capture "+key)) for key, path in roots.items()})
    cold = dict(instance=profile["source_instance"], boot_volume=profile["boot_volume"],
        volume_copies=[dict(volume=profile["mounts"][key], capture=h("capture "+key), epoch=epoch, read_only=True) for key in roots],
        roots=dict(zip(("app", "state"), m.C.ROOTS)), source_head=m.G.SOURCE_HEAD, did=f.context["did"], epoch=epoch,
        state="STOPPED", restart_denied=True, external_writers_absent=True, manifest_sha=m.G.sha(manifest), sqlite=images,
        ledger_files_sha=m.P.ledger_digest(files, inventory), inventory_sha=m.G.sha(bundle["inventory"]),
        backup_ids=[h("preserved backup 1"), h("preserved backup 2")], acquisition=acquisitions)
    bundle["cold"] = sign(f, "stopped", cold)
    policy = m.policy_for(authority, bundle); policy_sha = m.G.sha(policy)
    bundle["disposition"] = sign(f, "quarantine", dict(policy_sha=policy_sha, inventory_sha=m.G.sha(bundle["inventory"]),
        ledger_files_sha=cold["ledger_files_sha"], epoch=epoch, disposition="PERMANENT_NO_REPLAY_UNKNOWN", loss_tradeoff_accepted=True), "owner")
    bundle["policies"] = {side: sign(f, "policy-installed", dict(host=host, epoch=epoch, policy_sha=policy_sha,
        survives_reboot=True, missing_policy_denies=True, all_five_routes=True), role)
        for side, role, host in (("source", "independent", f.context["host"]), ("destination", "destination", m.B.K137))}
    bundle["destination"] = sign(f, "destination", dict(machine=m.B.K137, uid=1000, root=str(m.D.ROOT),
        source_host_key=profile["source_host_key"], destination_host_key=m.B.K137_KEY, free_bytes=64*m.R.GIB,
        memory_available_bytes=m.R.GIB, memory_psi_milli=0, io_psi_milli=0, caps=m.CAPS,
        runtime_started=False, tradebot_unchanged=True), "destination")
    bundle["rollback"] = sign(f, "rollback", dict(epoch=epoch, manifest_sha=m.G.sha(manifest), original_backups_preserved=True,
        source_remains_stopped=True, destination_disarmed=True, no_post_retry=True, recovery_accepted=True))
    binding = m.S.request(authority.trust, m.G.sha([bundle["run_id"], epoch]), h("synthetic independent recipient"))
    texts = m.S.preimages(binding); official = m.S.original()
    proof = dict(binding=binding, did=f.did, say_signature=official.signature(f.own, texts[0]), note_signature=official.signature(f.own, texts[1]))
    bundle["g3"] = dict(binding=binding, owner=f.signed("r1117-custody", binding, "owner"),
        recipient=f.signed("r1117-custody", binding, "identity"), proof=proof,
        custody=sign(f, "real-custody", dict(proof_sha=m.G.sha(proof), epoch=epoch, real_custody=True,
                    scope="K137_DISARMED_SAME_DID", recipient_hex=binding["recipient_hex"]), "identity"))
    a = SimpleNamespace(f=f, authority=authority, profile=profile, bundle=bundle, roots=roots,
                        files=files, inventory=inventory, tmp=tmp_path, policy=policy)
    owner(a)
    try:
        yield a
    finally:
        if os.name == "posix":
            for root in roots.values():
                root.chmod(0o700)
                for path in root.rglob("*"): path.chmod(0o700 if path.is_dir() else 0o600)


def test_pure_cold_admission_unknown_is_not_negative_finality(case):
    before = raw(case.bundle)
    result = m.admit(case.authority, case.bundle, now=case.f.now)
    assert raw(case.bundle) == before
    assert result["g5"] == "UNKNOWN_PERMANENTLY_NO_REPLAY"
    assert len(result["images"]) == 2
    assert all(len(case.bundle["inventory"][route]) for route in m.P.ROUTES)
    assert m.status("CHECKED")["cutover"] == "NO_GO"


@pytest.mark.parametrize("field,value", [("state", "RUNNING"), ("restart_denied", False), ("external_writers_absent", False),
    ("volume_copies", []), ("source_head", "f"*40), ("backup_ids", []), ("instance", "f"*64)])
def test_authenticated_but_incomplete_cold_evidence_stops(case, field, value):
    update(case, "cold", lambda data: data.update({field: value}), kind="stopped")
    with pytest.raises(ValueError): m.admit(case.authority, case.bundle, now=case.f.now)


def test_unsigned_or_spoofed_stopped_and_enrollment_rejected(case):
    bundle = copy.deepcopy(case.bundle); bundle["cold"]["signature"] = "0"*128
    with pytest.raises(ValueError): m.admit(case.authority, bundle, now=case.f.now)
    bundle["cold"] = sign(case.f, "stopped", case.bundle["cold"]["body"]["data"], "owner")
    with pytest.raises(ValueError): m.admit(case.authority, bundle, now=case.f.now)
    with pytest.raises(ValueError): m.Authority(case.profile, "0"*64)
    profile = copy.deepcopy(case.profile); profile["authority"]["keys"][0]["public_hex"] = "0"*64
    with pytest.raises(ValueError): m.Authority(profile, case.authority.pin)


@pytest.mark.parametrize("change", ["epoch", "wal", "shm", "capture", "cursor"])
def test_two_sqlite_volume_or_wal_epoch_mismatch_stops(case, change):
    def mutate(data):
        if change == "epoch": data["sqlite"][0]["epoch"] = h("wrong epoch")
        if change == "wal": data["sqlite"][0]["wal_sha"] = h("wrong WAL")
        if change == "capture": data["acquisition"]["bindings"]["state"]["capture"] = h("wrong copy")
        if change == "cursor": data["sqlite"][0]["count"] = -1
        if change == "shm": data["sqlite"][0].pop("shm_sha")
    update(case, "cold", mutate, kind="stopped")
    with pytest.raises(ValueError): m.admit(case.authority, case.bundle, now=case.f.now)


@pytest.mark.parametrize("change", ["missing_route", "duplicate_attempt", "duplicate_nonce", "wrong_did", "missing_nonce"])
def test_g5_inventory_incomplete_or_nonunique_fails_closed(case, change):
    inventory = case.bundle["inventory"]; first, second = m.P.ROUTES[:2]
    if change == "missing_route": inventory.pop(first)
    if change == "duplicate_attempt": inventory[first].append(copy.deepcopy(inventory[first][0]))
    if change == "duplicate_nonce": inventory[second][0].update(nonce=inventory[first][0]["nonce"], room_sha=inventory[first][0]["room_sha"])
    if change == "wrong_did": inventory[first][0]["did"] = h("other did")
    if change == "missing_nonce": inventory[first][0].pop("nonce")
    owner(case)
    with pytest.raises(ValueError): m.admit(case.authority, case.bundle, now=case.f.now)


@pytest.mark.parametrize("field,value", [("free_bytes", 20*1024**3), ("memory_available_bytes", 0),
    ("machine", "f"*64), ("runtime_started", True), ("tradebot_unchanged", False), ("memory_psi_milli", 9000)])
def test_destination_identity_capacity_and_tradebot_fail_close(case, field, value):
    update(case, "destination", lambda data: data.update({field: value}), role="destination")
    with pytest.raises(ValueError): m.admit(case.authority, case.bundle, now=case.f.now)


@pytest.mark.parametrize("field", ["downtime", "cold_capture", "rollback", "cost_cap"])
def test_explicit_independent_owner_downtime_capture_rollback_zero_cost(case, field):
    data = copy.deepcopy(case.bundle["owner"]["body"]["data"]); data[field] = False
    case.bundle["owner"] = sign(case.f, "owner", data, "owner")
    with pytest.raises(ValueError): m.admit(case.authority, case.bundle, now=case.f.now)


def test_g3_demo_signature_without_real_custody_attestation_is_not_enough(case):
    case.bundle["g3"]["custody"] = sign(case.f, "real-custody", dict(real_custody=False), "identity"); owner(case)
    with pytest.raises(m.Stop, match="COLD_REAL_G3_REQUIRED"): m.admit(case.authority, case.bundle, now=case.f.now)


@pytest.mark.parametrize("side", ["source", "destination"])
def test_both_planned_hosts_require_reboot_safe_policy_installation(case, side):
    case.bundle["policies"].pop(side); owner(case)
    with pytest.raises(ValueError): m.admit(case.authority, case.bundle, now=case.f.now)


def test_failed_rollback_and_expired_lease_stop(case):
    update(case, "rollback", lambda data: data.update(recovery_accepted=False))
    with pytest.raises(m.Stop, match="COLD_ROLLBACK_STOP"): m.admit(case.authority, case.bundle, now=case.f.now)
    with pytest.raises(ValueError): m.admit(case.authority, case.bundle, now=case.f.now+31)


@POSIX
def test_permanent_journal_reboot_missing_corrupt_and_wrong_policy_deny(case):
    root = case.tmp/"policy"; root.mkdir(mode=0o700)
    digest = m.G.sha(case.policy)
    policy = m.PermanentPolicy(root, digest)
    assert policy.can_send("any", boot="anything") is False
    with pytest.raises(m.Stop): policy.check()
    policy.install(case.authority, case.policy, case.bundle["disposition"], now=case.f.now)
    assert policy.check() == digest
    reloaded = m.PermanentPolicy(root, digest)
    assert reloaded.check() == digest and not reloaded.can_send("known", boot="next reboot")
    with pytest.raises(m.Stop): reloaded.install(case.authority, case.policy, case.bundle["disposition"], now=case.f.now)
    row = root/"000001.json"; old_bytes = row.read_bytes(); row.write_bytes(b"broken")
    with pytest.raises(ValueError): reloaded.check()
    assert not reloaded.can_send("any")
    row.write_bytes(old_bytes); row.unlink()
    with pytest.raises(m.Stop): reloaded.check()
    assert not reloaded.can_send("any", boot="reboot")


def journal(case, name="source-journal"):
    root = case.tmp/name; root.mkdir(mode=0o700)
    return m.J.UndoJournal(root)


def policy(case):
    root = case.tmp/"policy"; root.mkdir(mode=0o700)
    p = m.PermanentPolicy(root, m.G.sha(case.policy))
    p.install(case.authority, case.policy, case.bundle["disposition"], now=case.f.now)
    return p


def synthetic_kernel(monkeypatch):
    # ONLY synthetic temp roots get fake kernel RO. Production has no trial flag.
    monkeypatch.setattr(m, "readonly_roots", lambda *args: None)
    original = m.os.statvfs
    def readonly(path):
        value = original(path)
        result = SimpleNamespace(**{name: getattr(value, name) for name in dir(value) if name.startswith("f_")})
        result.f_flag |= m.os.ST_RDONLY
        return result
    monkeypatch.setattr(m.os, "statvfs", readonly)


@POSIX
def test_full_cold_source_real_aead_and_disarmed_restore_with_both_sqlite(case, monkeypatch):
    a = case; p = policy(a); attempt = journal(a); synthetic_kernel(monkeypatch)
    wire = io.BytesIO(); recovery = os.urandom(48)
    m.source_peer(a.authority, a.bundle, a.roots, a.files, a.inventory, lambda: a.bundle["cold"], p, attempt, recovery, wire, clock=lambda: a.f.now)
    assert attempt.latest["phase"] == "CIPHERTEXT_EMITTED_NOT_RESTORED"
    assert wire.getvalue().startswith(b"FLOPST01") and a.f.did.encode() not in wire.getvalue()
    archive = a.tmp/"archive"
    m.W.receive_offhost_ciphertext(io.BytesIO(wire.getvalue()), archive, quota_bytes=64*1024**2)
    landing = a.tmp/"disarmed"; landing.mkdir(mode=0o700)
    monkeypatch.setattr(m.D, "ROOT", landing)
    monkeypatch.setattr(m.D.shutil, "disk_usage", lambda _: SimpleNamespace(free=64*m.R.GIB))
    monkeypatch.setattr(m.D, "machine_digest", lambda: m.B.K137)
    # Fixed production UID remains 1000; only synthetic host identity is mocked.
    monkeypatch.setattr(m.D, "evidence_gate", lambda root, machine, uid: (
        m.need(root == landing and machine == m.B.K137 and uid == 1000, "SYNTHETIC_HOST_STOP"), m.D.private_parent(root)))
    restore_journal = journal(a, "restore-journal")
    result = m.restore_peer(a.authority, a.bundle, archive, recovery, p, restore_journal, now=a.f.now)
    assert result["restore"]["sqlite_integrity"] == "PASS" and result["activated"] is False
    assert result["oci_retirement"] == "STRICT_NO_GO"
    assert (landing/a.bundle["run_id"]/"state/verified-did.json").read_bytes() == a.files["verified-did.json"]
    with pytest.raises(m.Stop): m.restore_peer(a.authority, a.bundle, archive, recovery, p, restore_journal, now=a.f.now)
    with pytest.raises(m.Stop): m.source_peer(a.authority, a.bundle, a.roots, a.files, a.inventory,
        lambda: a.bundle["cold"], p, attempt, recovery, io.BytesIO(), clock=lambda: a.f.now)


@POSIX
def test_live_rw_copy_stops_before_ciphertext(case):
    update(case, "cold", lambda data: data["acquisition"].update(mount_table_sha=hashlib.sha256(Path("/proc/self/mountinfo").read_bytes()).hexdigest()), kind="stopped")
    p = policy(case); wire = io.BytesIO(); attempt = journal(case)
    with pytest.raises(m.Stop):
        m.source_peer(case.authority, case.bundle, case.roots, case.files, case.inventory,
                      lambda: case.bundle["cold"], p, attempt, os.urandom(48), wire, clock=lambda: case.f.now)
    assert not wire.getvalue() and attempt.latest is None


@POSIX
def test_transfer_break_is_durable_unknown_never_retried(case, monkeypatch):
    synthetic_kernel(monkeypatch); p = policy(case); attempt = journal(case)
    class Broken:
        def write(self, _): raise RuntimeError("synthetic disconnect")
    with pytest.raises(m.Stop, match="COLD_TRANSFER_UNKNOWN_NO_RETRY"):
        m.source_peer(case.authority, case.bundle, case.roots, case.files, case.inventory,
                      lambda: case.bundle["cold"], p, attempt, os.urandom(48), Broken(), clock=lambda: case.f.now)
    assert attempt.latest["phase"] == "UNKNOWN_NO_RETRY"
    # A fresh process sees the persisted interrupted attempt, not an empty queue.
    reloaded = m.J.UndoJournal(attempt.root)
    with pytest.raises(m.Stop, match="COLD_DURABLE_JOURNAL_REQUIRED"):
        m.source_peer(case.authority, case.bundle, case.roots, case.files, case.inventory,
                      lambda: case.bundle["cold"], p, reloaded, os.urandom(48), io.BytesIO(), clock=lambda: case.f.now)


@POSIX
def test_altered_ciphertext_and_manifest_rejected_before_restore_write(case, monkeypatch):
    synthetic_kernel(monkeypatch); p = policy(case); wire = io.BytesIO(); recovery = os.urandom(48)
    m.source_peer(case.authority, case.bundle, case.roots, case.files, case.inventory,
                  lambda: case.bundle["cold"], p, journal(case), recovery, wire, clock=lambda: case.f.now)
    archive = case.tmp/"archive"
    m.W.receive_offhost_ciphertext(io.BytesIO(wire.getvalue()), archive, quota_bytes=64*1024**2)
    shard = next(archive.glob("part-*.bin")); data = bytearray(shard.read_bytes()); data[len(data)//2] ^= 1; shard.write_bytes(data)
    monkeypatch.setattr(m.D, "restore_stream", lambda *a, **k: pytest.fail("no plaintext restore after auth failure"))
    attempt = journal(case, "restore-journal")
    with pytest.raises(m.Stop, match="COLD_ARCHIVE_AUTHENTICATION_STOP"):
        m.restore_peer(case.authority, case.bundle, archive, recovery, p, attempt, now=case.f.now)
    assert attempt.latest is None


def test_default_cli_no_secret_no_ssh_and_safe_redacted_output():
    result = subprocess.run([sys.executable, "-I", "-B", str(Path(m.__file__))], capture_output=True, timeout=15)
    assert result.returncode == 42 and result.stderr == b""
    assert json.loads(result.stdout)["code"] == "COLD_AUTHORITY_REQUIRED"
    source = Path(m.__file__).read_text()
    assert "subprocess" not in source and "socket" not in source


@WIN
def test_windows_ps51_preflight_syntax_default_stop():
    script = ROOT/"packaging/windows/r1153_cold_owner_preflight.ps1"
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(script)], capture_output=True, timeout=15)
    assert result.returncode == 42 and result.stderr == b""
    assert json.loads(result.stdout)["source_archive"] == "NO_GO"


@WIN
def test_native_ps51_signed_contract_never_becomes_execution(case):
    enrollment = case.tmp/"enrollment.json"; bundle = case.tmp/"bundle.json"
    enrollment.write_bytes(raw(case.profile)); bundle.write_bytes(raw(case.bundle))
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File",
        str(ROOT/"tests/windows/r1153_cold_preflight.ps1"), "-EnrollmentFile", str(enrollment),
        "-EnrollmentSha256", case.authority.pin, "-BundleFile", str(bundle), "-BundleSha256", m.G.sha(case.bundle)],
        capture_output=True, timeout=30, cwd=ROOT)
    assert result.returncode == 0, result.stdout.decode(errors="replace")+result.stderr.decode(errors="replace")
    assert result.stdout.strip() == b"R1153_PS51_PREFLIGHT=PASS"


@pytest.mark.parametrize("field", ["loss_tradeoff_accepted", "disposition"])
def test_permanent_business_disposition_never_inferred(case, field):
    update(case, "disposition", lambda data: data.update({field: False}), role="owner", kind="quarantine")
    with pytest.raises(m.Stop, match="COLD_QUARANTINE_APPROVAL_STOP"):
        m.admit(case.authority, case.bundle, now=case.f.now)


def test_wrong_or_missing_sidecar_and_non_durable_journal_stop_before_read(case):
    class InMemory:
        latest = None
        def save(self, row): pytest.fail("a memory journal is not durable")
    with pytest.raises(m.Stop, match="COLD_LOCAL_POLICY_REQUIRED"):
        m.source_peer(case.authority, case.bundle, case.roots, {}, {}, lambda: None, None, InMemory(),
                      os.urandom(48), io.BytesIO(), clock=lambda: case.f.now)


@POSIX
def test_memory_attempt_journal_cannot_replace_fsynced_journal(case):
    class InMemory:
        latest = None
    p = policy(case)
    with pytest.raises(m.Stop, match="COLD_DURABLE_JOURNAL_REQUIRED"):
        m.source_peer(case.authority, case.bundle, case.roots, case.files, case.inventory,
                      lambda: None, p, InMemory(), os.urandom(48), io.BytesIO(), clock=lambda: case.f.now)


@POSIX
def test_different_lease_or_missing_original_attempt_stops_without_export(case):
    p = policy(case); attempt = journal(case); wire = io.BytesIO()
    data = copy.deepcopy(case.bundle["cold"]["body"]["data"]); data["state"] = "RUNNING"
    bad = sign(case.f, "stopped", data)
    with pytest.raises(m.Stop, match="COLD_LEASE_CHANGED_STOP"):
        m.source_peer(case.authority, case.bundle, case.roots, case.files, case.inventory, lambda: bad,
                      p, attempt, os.urandom(48), wire, clock=lambda: case.f.now)
    missing = dict(case.files); missing.pop("signer/oracle-signer-receipts.json")
    with pytest.raises(ValueError):
        m.source_peer(case.authority, case.bundle, case.roots, missing, case.inventory, lambda: case.bundle["cold"],
                      p, attempt, os.urandom(48), wire, clock=lambda: case.f.now)
    assert not wire.getvalue() and attempt.latest is None


@POSIX
def test_fresh_same_epoch_lease_can_renew_without_extending_owner_scope(case, monkeypatch):
    synthetic_kernel(monkeypatch); p = policy(case); attempt = journal(case); wire = io.BytesIO()
    calls = [case.f.now]
    def clock():
        return calls.pop() if calls else case.f.now+31
    renewed = sign(case.f, "stopped", case.bundle["cold"]["body"]["data"], at=case.f.now+31)
    m.source_peer(case.authority, case.bundle, case.roots, case.files, case.inventory, lambda: renewed,
                  p, attempt, os.urandom(48), wire, clock=clock)
    assert attempt.latest["phase"] == "CIPHERTEXT_EMITTED_NOT_RESTORED"


def test_malicious_control_is_not_printed():
    control = b"SYNTHETIC-NOT-TO-BE-REFLECTED"
    result = subprocess.run([sys.executable, "-I", "-B", str(Path(m.__file__)), "--preflight"],
        input=control, capture_output=True, timeout=15)
    assert result.returncode == 42 and result.stderr == b"" and control not in result.stdout
    assert json.loads(result.stdout)["code"] == "COLD_ADMISSION_STOP"


def test_verified_did_symlink_is_rejected_before_any_follow(case):
    row = next(row for row in case.bundle["manifest"]["entries"] if row["path"] == "state/verified-did.json")
    row.update(kind="symlink", target="/SYNTHETIC-DO-NOT-FOLLOW", size=0, sha256=None)
    with pytest.raises(m.Stop, match="COLD_DID_STOP"):
        m.admit(case.authority, case.bundle, now=case.f.now)
