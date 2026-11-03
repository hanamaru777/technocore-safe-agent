"""Cold-source admission + permanent no-replay. No cloud/sign/send capability.

This is NOT a substitute for R1117 live G4/G5. Independently authenticated
STOPPED + restart denial and cold immutable volume copies are a separate lane.
CLI is public offline preflight only; archive peers are explicit library APIs.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import re
import sqlite3
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def dependencies():
    import json
    pins = json.loads(Path(__file__).with_name("r1153_source_pins.json").read_bytes())
    for name, expected in pins.items():
        raw = (ROOT/name).read_bytes().replace(b"\r\n", b"\n")
        if hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest() != expected:
            raise ValueError("R1153_SOURCE_PIN_STOP")
    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, ROOT/path)
        module = importlib.util.module_from_spec(spec); sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    s = load("r1153_continuity", "packaging/migration/r1117_signer.py")
    b = load("r1153_preseed_contract", "packaging/migration/r1151_preseed_owner_bridge.py")
    return s, b


try:
    S, B = dependencies()
except Exception:
    if __name__ == "__main__":
        print('{"phase":"R1153","result":"PREFLIGHT_ONLY","code":"COLD_DEPENDENCY_STOP","source_archive":"NO_GO","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO","activated":false}')
        raise SystemExit(42)
    raise
C, R = S.C, S.C.R
G, T, W, D = C.G, R.T, R.W, R.D
DISARMED_ROOT = str(D.ROOT)
P = C.legacy("r1107_g5_reconciliation.py")
J = C.legacy("r1117_boundary.py")
FIELDS = "version run_id epoch cold manifest inventory disposition destination rollback g3 owner policies"
CAPS = {"memory_max_bytes": 256*1024**2, "cpu_quota_percent": 25, "io_bytes_per_second": 4*1024**2}
PROTECTED = (*T.BLOCKED_ROOTS, "/var/lib/tradebot-k137-public", "/home/ubuntu/k137-canonical-source",
             "/home/ubuntu/k137q-public-only", "/home/ubuntu/k137-public-state")


class Stop(ValueError): pass


def need(value, code):
    if not value: raise Stop(code)


def shape(value, keys):
    need(type(value) is dict and set(value) == set(keys.split()), "COLD_SCHEMA_STOP")


def bounded(value):
    need(len(G.canonical(value)) <= C.MAX_BYTES, "COLD_BOUND_STOP")


class Authority:
    """Independent digest pin is a caller input OUTSIDE the evidence bundle.

    No production authority is enrolled by this module. C.Enrollment excludes
    the continuing DID key and source keys and enforces distinct role keys.
    """
    def __init__(self, public, expected_sha):
        bounded(public)
        need(G.sha(public) == C.digest(expected_sha), "COLD_ENROLLMENT_PIN_STOP")
        shape(public, "version authority source_instance boot_volume attached_volumes mounts source_host_key")
        need(type(public["version"]) is int and public["version"] == 1, "COLD_SCHEMA_STOP")
        self.public = C.decode(G.canonical(public)); self.pin = expected_sha
        self.trust = C.Enrollment(self.public["authority"])
        self.context = self.trust.context
        need(self.context["destination"] == B.K137, "COLD_DESTINATION_STOP")
        for name in ("source_instance", "boot_volume", "source_host_key"): C.digest(public[name])
        volumes = public["attached_volumes"]
        need(type(volumes) is list and 1 <= len(volumes) <= 32 and
             len(volumes) == len(set(volumes)) and public["boot_volume"] in volumes, "COLD_VOLUME_STOP")
        for volume in volumes: C.digest(volume)
        shape(public["mounts"], "app state")
        need(all(public["mounts"][key] in volumes for key in ("app", "state")), "COLD_VOLUME_STOP")

    def verify(self, packet, kind, role, now):
        need(G.sha(self.public) == self.pin, "COLD_ENROLLMENT_PIN_STOP")
        return self.trust.verify(packet, "r1153-"+kind, role, now, age=30)


def normalized_attempts(files, did, inventory):
    """Reuse actual five original parsers, never trust hand-written outcomes."""
    P.ledger_digest(files, inventory)
    original = P.original_attempts(files, did)
    return {route: [dict(id=G.sha(row["id"]), leg=row["leg"], did=C.raw_hash(row["did"].encode()),
                        nonce=row["nonce"], room_sha=G.sha(row["room"]),
                        record_sha=G.sha(row)) for row in rows] for route, rows in original.items()}


def inventory_check(authority, inventory):
    shape(inventory, " ".join(P.ROUTES))
    ids, nonces = set(), set()
    for route, rows in inventory.items():
        need(type(rows) is list and len(rows) <= 2048, "COLD_ATTEMPT_BOUND_STOP")
        for row in rows:
            shape(row, "id leg did nonce room_sha record_sha")
            for key in ("id", "did", "room_sha", "record_sha"): C.digest(row[key])
            need(row["did"] == authority.context["did"] and type(row["leg"]) is int and
                 0 <= row["leg"] <= 256 and type(row["nonce"]) is str and
                 C.V.NONCE_RE.fullmatch(row["nonce"]), "COLD_ATTEMPT_STOP")
            identity = (route, row["id"], row["leg"])
            nonce = (row["did"], row["room_sha"], row["nonce"])
            need(identity not in ids and nonce not in nonces, "COLD_DUPLICATE_ATTEMPT_OR_NONCE_STOP")
            ids.add(identity); nonces.add(nonce)


def policy_for(authority, bundle):
    return dict(version=1, context_sha=G.sha(authority.context), epoch=bundle["epoch"],
                ledger_sha=R.state_ledger_digest(bundle["manifest"]),
                ledger_files_sha=bundle["cold"]["body"]["data"]["ledger_files_sha"], inventory=bundle["inventory"],
                default_deny=True, permanent=True, no_prune=True, unknown_remains_unknown=True,
                scope="ALL_FIVE_ROUTES_ALL_BOOTS_DISARMED")


def state_hashes(manifest):
    rows = {row["path"]: row for row in manifest["entries"]}
    return {name[6:]: (row["sha256"] if row["kind"] == "file" else rows[row["target"]]["sha256"])
            for name, row in rows.items() if name.startswith("state/") and row["kind"] in ("file", "hardlink")}


def check_manifest(bundle):
    manifest = bundle["manifest"]
    shape(manifest, "version source_head epoch entries")
    need(type(manifest["version"]) is int and manifest["version"] == 1 and
         manifest["source_head"] == G.SOURCE_HEAD and manifest["epoch"] == "FROZEN:"+bundle["epoch"], "COLD_EPOCH_STOP")
    rows, size, _ = D.validate_manifest(manifest, preserve_inert_links=True)
    need(rows.get("app", {}).get("kind") == "directory" and rows.get("state", {}).get("kind") == "directory" and
         all(name == "app" or name == "state" or name.startswith(("app/", "state/")) for name in rows), "COLD_ROOT_SCOPE_STOP")
    need(size <= T.C.MAX_SOURCE_BYTES, "COLD_SIZE_STOP")
    did = rows.get("state/verified-did.json")
    need(did is not None and did["kind"] == "file" and 0 < did["size"] <= 16384, "COLD_DID_STOP")
    images = []
    for name in sorted(G.DATABASES):
        found = [path for path in rows if path.rsplit("/", 1)[-1] == name]
        need(len(found) == 1, "COLD_TWO_SQLITE_STOP")
        path = found[0]
        need(path.startswith("state/"), "COLD_TWO_SQLITE_STOP")
        hashes = {}
        for suffix, key in (("", "db_sha"), ("-wal", "wal_sha"), ("-shm", "shm_sha")):
            row = rows.get(path+suffix)
            need(row is not None and row["kind"] == "file", "COLD_SQLITE_SIDECAR_STOP")
            hashes[key] = row["sha256"]
        images.append(dict(path=path, epoch=bundle["epoch"], **hashes))
    images.sort(key=lambda image: list(rows).index(image["path"]))
    return rows, size, images


def admit(authority, bundle, *, now):
    """Pure preflight. A checked plan is NOT a transfer/cutover/retirement GO."""
    need(isinstance(authority, Authority), "COLD_AUTHORITY_REQUIRED")
    bounded(bundle); shape(bundle, FIELDS)
    need(type(bundle["version"]) is int and bundle["version"] == 1 and type(bundle["run_id"]) is str and
         re.fullmatch(r"[0-9a-f]{32}", bundle["run_id"]), "COLD_RUN_STOP")
    C.digest(bundle["epoch"])
    rows, size, images = check_manifest(bundle)
    cold = authority.verify(bundle["cold"], "stopped", "independent", now)
    shape(cold, "instance boot_volume volume_copies roots source_head did epoch state restart_denied external_writers_absent manifest_sha sqlite ledger_files_sha inventory_sha backup_ids acquisition")
    need(cold["instance"] == authority.public["source_instance"] and cold["boot_volume"] == authority.public["boot_volume"] and
         cold["roots"] == dict(zip(("app", "state"), C.ROOTS)) and cold["source_head"] == G.SOURCE_HEAD and
         cold["did"] == authority.context["did"] and cold["epoch"] == bundle["epoch"] and
         cold["state"] == "STOPPED" and cold["restart_denied"] is True and cold["external_writers_absent"] is True and
         cold["manifest_sha"] == G.sha(bundle["manifest"]), "COLD_STOPPED_OR_EPOCH_STOP")
    need(type(cold["sqlite"]) is list and len(cold["sqlite"]) == 2, "COLD_TWO_SQLITE_STOP")
    for actual, expected in zip(cold["sqlite"], images):
        shape(actual, "path epoch db_sha wal_sha shm_sha count seq")
        C.integer(actual["count"]); C.integer(actual["seq"])
        need({k: v for k, v in actual.items() if k not in ("count", "seq")} == expected, "COLD_SQLITE_EPOCH_STOP")
    need(type(cold["backup_ids"]) is list and len(cold["backup_ids"]) >= 2 and len(cold["backup_ids"]) <= 32 and
         len(cold["backup_ids"]) == len(set(cold["backup_ids"])), "COLD_BACKUP_STOP")
    for backup in cold["backup_ids"]: C.digest(backup)
    copies = cold["volume_copies"]
    need(type(copies) is list and len(copies) == len(authority.public["attached_volumes"]), "COLD_VOLUME_STOP")
    seen = set()
    for copy in copies:
        shape(copy, "volume capture epoch read_only")
        C.digest(copy["capture"])
        need(copy["volume"] in authority.public["attached_volumes"] and copy["volume"] not in seen and
             copy["epoch"] == bundle["epoch"] and copy["read_only"] is True, "COLD_VOLUME_STOP")
        seen.add(copy["volume"])
    shape(cold["acquisition"], "mount_table_sha bindings")
    C.digest(cold["acquisition"]["mount_table_sha"])
    shape(cold["acquisition"]["bindings"], "app state")
    for key, binding in cold["acquisition"]["bindings"].items():
        shape(binding, "path_sha device inode capture")
        C.digest(binding["path_sha"]); C.integer(binding["device"]); C.integer(binding["inode"], 1)
        expected_volume = authority.public["mounts"][key]
        need(binding["capture"] == next(x["capture"] for x in copies if x["volume"] == expected_volume), "COLD_VOLUME_STOP")
    inventory_check(authority, bundle["inventory"])
    C.digest(cold["ledger_files_sha"])
    need(cold["ledger_files_sha"] == G.sha(state_hashes(bundle["manifest"])), "COLD_LEDGER_MANIFEST_STOP")
    need(cold["inventory_sha"] == G.sha(bundle["inventory"]), "COLD_INVENTORY_STOP")
    policy = policy_for(authority, bundle); policy_sha = G.sha(policy)
    decision = authority.verify(bundle["disposition"], "quarantine", "owner", now)
    need(decision == dict(policy_sha=policy_sha, inventory_sha=cold["inventory_sha"], ledger_files_sha=cold["ledger_files_sha"],
        epoch=bundle["epoch"], disposition="PERMANENT_NO_REPLAY_UNKNOWN", loss_tradeoff_accepted=True), "COLD_QUARANTINE_APPROVAL_STOP")
    for side, role, host in (("source", "independent", authority.context["host"]),
                             ("destination", "destination", authority.context["destination"])):
        shape(bundle["policies"], "source destination")
        installed = authority.verify(bundle["policies"][side], "policy-installed", role, now)
        need(installed == dict(host=host, epoch=bundle["epoch"], policy_sha=policy_sha,
            survives_reboot=True, missing_policy_denies=True, all_five_routes=True), "COLD_POLICY_NOT_INSTALLED_STOP")
    destination = authority.verify(bundle["destination"], "destination", "destination", now)
    shape(destination, "machine uid root source_host_key destination_host_key free_bytes memory_available_bytes memory_psi_milli io_psi_milli caps runtime_started tradebot_unchanged")
    need(destination["machine"] == B.K137 and destination["uid"] == 1000 and type(destination["uid"]) is int and
         destination["root"] == DISARMED_ROOT and destination["source_host_key"] == authority.public["source_host_key"] and
         destination["destination_host_key"] == B.K137_KEY and destination["runtime_started"] is False and
         destination["tradebot_unchanged"] is True and destination["caps"] == CAPS, "COLD_DESTINATION_STOP")
    for key in ("free_bytes", "memory_available_bytes", "memory_psi_milli", "io_psi_milli"): C.integer(destination[key])
    # Archive + independent inert copy + allowance. Never assume compression.
    need(destination["free_bytes"] >= 20*R.GIB + 2*size + 2*R.GIB and
         destination["memory_available_bytes"] >= 512*1024**2 and destination["memory_psi_milli"] <= 5000 and
         destination["io_psi_milli"] <= 10000, "COLD_CAPACITY_STOP")
    rollback = authority.verify(bundle["rollback"], "rollback", "independent", now)
    need(rollback == dict(epoch=bundle["epoch"], manifest_sha=G.sha(bundle["manifest"]),
         original_backups_preserved=True, source_remains_stopped=True, destination_disarmed=True,
         no_post_retry=True, recovery_accepted=True), "COLD_ROLLBACK_STOP")
    g3 = bundle["g3"]; shape(g3, "binding owner recipient proof custody")
    need(g3["binding"]["challenge"] == G.sha([bundle["run_id"], bundle["epoch"]]), "COLD_G3_CHALLENGE_STOP")
    S.verify_proof(authority.trust, g3["binding"], g3["owner"], g3["recipient"], g3["proof"], now=now)
    custody = authority.verify(g3["custody"], "real-custody", "identity", now)
    need(custody == dict(proof_sha=G.sha(g3["proof"]), epoch=bundle["epoch"], real_custody=True,
         scope="K137_DISARMED_SAME_DID", recipient_hex=g3["binding"]["recipient_hex"]), "COLD_REAL_G3_REQUIRED")
    approval = authority.verify(bundle["owner"], "owner", "owner", now)
    shape(approval, "bundle_sha enrollment_sha downtime cold_capture rollback cost_cap operation operation_expires_at")
    C.integer(approval.get("operation_expires_at"))
    need(now < approval["operation_expires_at"] <= bundle["owner"]["body"]["observed_at"]+14400, "COLD_OWNER_DEADLINE_STOP")
    need(approval == dict(bundle_sha=G.sha({k: v for k, v in bundle.items() if k != "owner"}),
        enrollment_sha=authority.pin, downtime=True, cold_capture=True, rollback=True,
        cost_cap="ZERO_NEW_BILLING", operation="PRESERVE_DISARMED_ONLY",
        operation_expires_at=approval["operation_expires_at"]), "COLD_OWNER_APPROVAL_STOP")
    return dict(policy=policy, policy_sha=policy_sha, size=size, images=cold["sqlite"], manifest_sha=G.sha(bundle["manifest"]),
                ledger_files_sha=cold["ledger_files_sha"], binding_sha=G.sha(bundle), g5="UNKNOWN_PERMANENTLY_NO_REPLAY")


class PermanentPolicy:
    """One-time private POSIX journal. Never grants any posting authority.

    The independently retained expected policy digest is mandatory on reload.
    Missing/corrupt/truncated journals cannot turn into an empty allow policy.
    """
    def __init__(self, root, expected_sha):
        need(not any(Path(root) == Path(p) or Path(p) in Path(root).parents for p in PROTECTED), "COLD_PROTECTED_ROOT_STOP")
        self.expected = C.digest(expected_sha); self.journal = J.UndoJournal(root)

    def install(self, authority, policy, approval, *, now):
        need(G.sha(policy) == self.expected and self.journal.latest is None, "COLD_POLICY_REPLAY_STOP")
        shape(policy, "version context_sha epoch ledger_sha ledger_files_sha inventory default_deny permanent no_prune unknown_remains_unknown scope")
        inventory_check(authority, policy["inventory"])
        need(policy["context_sha"] == G.sha(authority.context) and policy["default_deny"] is True and
             policy["permanent"] is True and policy["no_prune"] is True and policy["unknown_remains_unknown"] is True and
             policy["scope"] == "ALL_FIVE_ROUTES_ALL_BOOTS_DISARMED", "COLD_POLICY_STOP")
        decision = authority.verify(approval, "quarantine", "owner", now)
        need(decision == dict(policy_sha=self.expected, inventory_sha=G.sha(policy["inventory"]),
            ledger_files_sha=policy["ledger_files_sha"], epoch=policy["epoch"],
            disposition="PERMANENT_NO_REPLAY_UNKNOWN", loss_tradeoff_accepted=True), "COLD_QUARANTINE_APPROVAL_STOP")
        self.journal.save(dict(phase="PERMANENT_NO_REPLAY", policy=policy))

    def check(self):
        self.journal = J.UndoJournal(self.journal.root)
        row = self.journal.latest
        need(type(row) is dict and row.get("phase") == "PERMANENT_NO_REPLAY" and
             G.sha(row["policy"]) == self.expected and row["policy"]["default_deny"] is True, "COLD_POLICY_LOST_STOP")
        return self.expected

    def can_send(self, *args, **kwargs):
        # Closed even when journal disappeared, boot changed, or caller lies.
        return False


def readonly_roots(roots, acquisition):
    """Acquisition-host RO check, NOT a claim of global live G4 denial."""
    need(sys.platform == "linux", "COLD_LINUX_ACQUISITION_REQUIRED")
    with Path("/proc/self/mountinfo").open("rb") as source:
        raw = source.read(1024**2+1)
    need(len(raw) <= 1024**2 and hashlib.sha256(raw).hexdigest() == acquisition["mount_table_sha"], "COLD_MOUNT_CHANGED_STOP")
    for key, root in roots.items():
        need(not any(root == Path(p) or Path(p) in root.parents for p in PROTECTED), "COLD_LIVE_ROOT_STOP")
        s = root.stat(); binding = acquisition["bindings"][key]
        need(binding["path_sha"] == G.sha(str(root)) and binding["device"] == s.st_dev and
             binding["inode"] == s.st_ino and os.statvfs(root).f_flag & os.ST_RDONLY, "COLD_READONLY_COPY_REQUIRED")


def source_peer(authority, bundle, roots, files, inventory, guard, policy, journal, recovery, output, *, clock=time.time):
    """Only independently admitted COLD copies; never original live roots.

    guard returns a fresh independently signed complete cold bundle, rather
    than a self-reported bool. Caller owns the separate source runtime access.
    """
    checked = admit(authority, bundle, now=int(clock()))
    need(type(policy) is PermanentPolicy, "COLD_LOCAL_POLICY_REQUIRED")
    need(isinstance(journal, J.UndoJournal) and not any(journal.root == Path(p) or Path(p) in journal.root.parents for p in PROTECTED), "COLD_DURABLE_JOURNAL_REQUIRED")
    need(isinstance(journal, J.UndoJournal) and J.UndoJournal(journal.root).latest is None, "COLD_DURABLE_JOURNAL_REQUIRED")
    need(policy.check() == checked["policy_sha"] and journal.latest is None, "COLD_ATTEMPT_OR_POLICY_STOP")
    need(type(recovery) is bytes and 32 <= len(recovery) <= 1024, "COLD_RECOVERY_STOP")
    shape(roots, "app state")
    # Existing offline roots disallow all protected live/TradeBot paths.
    roots = {k: T.offline_source(Path(v)) for k, v in roots.items()}
    def refresh():
        now = int(clock())
        need(now < bundle["owner"]["body"]["data"]["operation_expires_at"], "COLD_OWNER_DEADLINE_STOP")
        fresh = authority.verify(guard(), "stopped", "independent", now)
        need(fresh == bundle["cold"]["body"]["data"], "COLD_LEASE_CHANGED_STOP")
        policy.check()
    refresh()
    need(P.ledger_digest(files, inventory) == checked["ledger_files_sha"] and
         normalized_attempts(files, authority.public["authority"]["source_did"], inventory) == bundle["inventory"],
         "COLD_ORIGINAL_LEDGER_STOP")
    def census():
        refresh()
        readonly_roots(roots, bundle["cold"]["body"]["data"]["acquisition"])
        current = T._census_roots(roots, G.SOURCE_HEAD, epoch="FROZEN:"+bundle["epoch"])
        need(current[1] == bundle["manifest"], "COLD_SOURCE_MANIFEST_STOP")
        # ALL state file hashes, plus all required sidecar bytes, are bound.
        actual = state_hashes(current[1])
        need(actual == inventory, "COLD_ORIGINAL_LEDGER_STOP")
        return current
    _, manifest, ids = census()
    verified_path = roots["state"]/"verified-did.json"
    verified = b"".join(T.read_blocks(verified_path, ids["state/verified-did.json"]))
    need(C.decode(verified).get("did") ==
         authority.public["authority"]["source_did"], "COLD_DID_STOP")
    for image in checked["images"]:
        db = T.resolve_source(roots, image["path"])
        # Must be truly read-only on the acquisition host. This is NOT G4.
        need(os.name == "posix" and os.statvfs(db).f_flag & os.ST_RDONLY, "COLD_READONLY_COPY_REQUIRED")
        con = sqlite3.connect(db.as_uri()+"?mode=ro", uri=True)
        try:
            con.execute("PRAGMA trusted_schema=OFF"); con.execute("PRAGMA query_only=ON")
            need(con.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "COLD_SQLITE_INTEGRITY_STOP")
            need(list(con.execute("SELECT count(*),coalesce(max(seq),0) FROM messages").fetchone()) ==
                 [image["count"], image["seq"]], "COLD_SQLITE_CURSOR_STOP")
        finally: con.close()
    _, manifest, ids = census()
    journal.save(dict(phase="ATTEMPTING", binding_sha=checked["binding_sha"]))
    class Output:
        def isatty(self): return False
        def write(self, data): refresh(); return output.write(data)
    try:
        W.seal_manifest_to_stream(roots, manifest, ids, recovery, Output(), recensus=census)
        refresh(); output.flush()
    except Exception:
        journal.save(dict(phase="UNKNOWN_NO_RETRY", binding_sha=checked["binding_sha"]))
        raise Stop("COLD_TRANSFER_UNKNOWN_NO_RETRY") from None
    journal.save(dict(phase="CIPHERTEXT_EMITTED_NOT_RESTORED", binding_sha=checked["binding_sha"]))
    return status("CIPHERTEXT_EMITTED_NOT_RESTORED")


def restore_peer(authority, bundle, archive, recovery, policy, journal, *, now, windows_validator=None):
    """R1089 locked two-pass AEAD + R1086 fixed K137 DISARMED child only."""
    checked = admit(authority, bundle, now=now)
    need(type(policy) is PermanentPolicy, "COLD_LOCAL_POLICY_REQUIRED")
    need(isinstance(journal, J.UndoJournal) and not any(journal.root == Path(p) or Path(p) in journal.root.parents for p in PROTECTED), "COLD_DURABLE_JOURNAL_REQUIRED")
    need(isinstance(journal, J.UndoJournal) and J.UndoJournal(journal.root).latest is None, "COLD_DURABLE_JOURNAL_REQUIRED")
    need(policy.check() == checked["policy_sha"] and journal.latest is None, "COLD_ATTEMPT_OR_POLICY_STOP")
    need(not any(Path(archive) == Path(p) or Path(p) in Path(archive).parents for p in PROTECTED), "COLD_PROTECTED_ROOT_STOP")
    with R.LockedArchive(archive, windows_validator=windows_validator) as locked:
        manifest, meta = locked.verify(recovery)
        need(manifest == bundle["manifest"] and meta["manifest_sha256"] == checked["manifest_sha"], "COLD_ARCHIVE_MANIFEST_STOP")
        journal.save(dict(phase="RESTORE_ATTEMPTING", binding_sha=checked["binding_sha"]))
        try:
            # Existing reader streams only AFTER complete AEAD pass; no full RAM buffer.
            class PlainInput:
                def __init__(self): self.blocks = iter(locked.blocks(recovery)); self.buffer = bytearray(); self.eof = False
                def read(self, size):
                    need(type(size) is int and 0 <= size <= T.CHUNK, "COLD_RESTORE_READ_BOUND_STOP")
                    need(int(time.time()) < bundle["owner"]["body"]["data"]["operation_expires_at"], "COLD_OWNER_DEADLINE_STOP")
                    policy.check()
                    while len(self.buffer) < size and not self.eof:
                        block = next(self.blocks, None)
                        if block is None: self.eof = True
                        else: self.buffer.extend(block)
                    value = bytes(self.buffer[:size]); del self.buffer[:size]; return value
            reader = PlainInput()
            result = D.restore_stream(reader, bundle["run_id"], B.K137, 1000,
                quota_bytes=checked["size"], expected_epoch=manifest["epoch"],
                expected_manifest_sha256=checked["manifest_sha"], preserve_inert_links=True,
                expected_cursors=[[image["count"], image["seq"]] for image in checked["images"]])
            did = D.ROOT/bundle["run_id"]/"state/verified-did.json"
            need(not did.is_symlink() and did.stat().st_size <= 16384 and C.decode(did.read_bytes()).get("did") ==
                 authority.public["authority"]["source_did"], "COLD_RESTORED_DID_STOP")
            locked.check(); policy.check()
        except Exception:
            journal.save(dict(phase="RESTORE_UNKNOWN_NO_RETRY", binding_sha=checked["binding_sha"]))
            raise Stop("COLD_RESTORE_UNKNOWN_NO_RETRY") from None
    journal.save(dict(phase="DISARMED_RESTORE_ONLY", binding_sha=checked["binding_sha"]))
    return {**status("DISARMED_RESTORE_ONLY"), "restore": result}


def status(code):
    return dict(phase="R1153", result="PREFLIGHT_ONLY", code=code, source_archive="NO_GO",
        cutover="NO_GO", oci_retirement="STRICT_NO_GO", activated=False)


def main():
    result = status("COLD_AUTHORITY_REQUIRED")
    if sys.argv[1:] == ["--preflight"]:
        try:
            request = R.frame_read(sys.stdin.buffer, R.MAGIC)
            need(sys.stdin.buffer.read(1) == b"", "COLD_INPUT_STOP")
            shape(request, "enrollment enrollment_sha bundle")
            authority = Authority(request["enrollment"], request["enrollment_sha"])
            # The input must come from the independently hash/ACL-pinned owner
            # PS carrier. This CLI is a verifier, NEVER an archive/send CLI.
            admit(authority, request["bundle"], now=int(time.time()))
            result = status("COLD_CONTRACT_CHECKED_NOT_EXECUTION_AUTHORITY")
        except Exception:
            result = status("COLD_ADMISSION_STOP")
    print(G.canonical(result).decode()); return 42


if __name__ == "__main__": raise SystemExit(main())
