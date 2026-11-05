"""Connected, owner-gated G3-G7 laboratory path; no production adapter.

This is executable integration of the existing full-state capture/AEAD/readback/
DISARMED restore, not a second archive format. The only exposed mode is an
explicit offline trial. Original Vault custody, global fencing and complete
five-route finality remain unavailable for real migration.
"""
import importlib.util
import os
from pathlib import Path
import sys
import time

spec = importlib.util.spec_from_file_location("r1163_contract", Path(__file__).with_name("r1163_contract.py"))
K = importlib.util.module_from_spec(spec); spec.loader.exec_module(K)


class BlocksIO:
    """Bounded streaming view; no plaintext temporary file or whole-archive RAM."""
    def __init__(self, blocks):
        self.blocks = iter(blocks)
        self.buffer = bytearray()
        self.eof = False

    def read(self, size):
        K.need(type(size) is int and 0 <= size <= 8*1024**2, "STREAM_READ_BOUND_STOP")
        while len(self.buffer) < size and not self.eof:
            block = next(self.blocks, None)
            if block is None:
                self.eof = True
            else:
                K.need(type(block) is bytes and len(block) <= 8*1024**2, "STREAM_BLOCK_BOUND_STOP")
                self.buffer.extend(block)
        out = bytes(self.buffer[:size]); del self.buffer[:size]
        return out


class CaptureOutput:
    def __init__(self, file, host_pins, recovery, wal, stage, guard, limit):
        self.file, self.host_pins, self.recovery = file, host_pins, recovery
        self.wal, self.stage, self.guard, self.limit = wal, stage, guard, limit
        self.count = 0
        self.cursors = None

    def write(self, block):
        K.need(self.count+len(block) <= self.limit, "CIPHERTEXT_QUOTA_STOP")
        written = self.file.write(block)
        self.count += written
        return written

    def flush(self):
        self.file.flush(); os.fsync(self.file.fileno())

    def seal_using_existing_r1089(self, roots, manifest, identities, out, census):
        # Strict checksum validation of the *original* WAL bytes and a private
        # WAL-aware SQLite copy. Original files never opened writable here.
        self.cursors = self.wal.validate(roots, manifest, identities,
            lambda *args: self.guard(), parent=self.stage)
        self.wal.C.R.W.seal_manifest_to_stream(roots, manifest, identities,
            bytes(self.recovery), out, recensus=census)


class Trial:
    def __init__(self, controller, authority, workspace, *, mode, clock=time.time):
        K.source_map()
        K.need(mode == "OFFLINE_TRIAL", "PRODUCTION_MIGRATION_NOT_ADMITTED")
        K.need(os.name == "posix" and sys.platform == "linux", "POSIX_TRIAL_REQUIRED")
        K.need(getattr(authority, "profile", None) == "SYNTHETIC_TEST_ONLY", "TRIAL_AUTHORITY_STOP")
        self.m = K.legacy("r1117_migration.py")
        self.wal = K.legacy("r1155_wal.py")
        self.boundary = K.legacy("r1117_boundary.py")
        self.work = self.m.C.R.T.offline_source(Path(workspace))
        self.m.C.R.T.private_dir(self.work)
        self.clock = clock
        self.pipe = self.m.OneShot(controller, authority, trial=True, clock=clock)
        journal_root = self.work/"session"
        if not journal_root.exists(): journal_root.mkdir(mode=0o700)
        self.journal = self.boundary.UndoJournal(journal_root)

    def capture(self, *, roots, files, inventory, did, exports, witnesses, g3,
                owner, destination, recovery, source_cap, run_id):
        """One durable attempt; no automatic retry after any interrupted output.

        Recovery material is library-only memory supplied via an approved path
        by a future owner transport. No CLI/env/file/secret prompt is offered.
        Tests supply fresh random dummy bytes. This library never retrieves it.
        """
        K.need(self.journal.latest is None, "SESSION_ALREADY_ATTEMPTED")
        K.need(type(recovery) is bytearray and 32 <= len(recovery) <= 1024, "RECOVERY_MEMORY_REQUIRED")
        K.need(type(run_id) is str and len(run_id) == 32 and all(c in "0123456789abcdef" for c in run_id), "RUN_ID_STOP")
        for path in roots.values():
            p = self.m.C.R.T.offline_source(path)
            K.need(p != self.work and p not in self.work.parents and self.work not in p.parents, "TRIAL_SCOPE_STOP")
        # Journal before any output creation; duplicate/orphan entries stop.
        self.journal.save(dict(phase="TRIAL_PREPARED", run_id=run_id, mode="OFFLINE_TRIAL"))
        cap = source_cap+4*1024**2
        stage = self.work/"wal-stage"; stage.mkdir(mode=0o700)
        step = self.work/"capture"; step.mkdir(mode=0o700)
        acquire_journal = self.boundary.UndoJournal(step)
        wire = self.work/"ciphertext.wire"
        try:
            d = destination["body"]["data"]
            fd = os.open(wire, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as file:
                out = CaptureOutput(file, (d["source_host_key"], d["destination_host_key"]), recovery,
                    self.wal, stage, lambda: self.pipe.controller.guard(now=int(self.clock())), cap)
                epoch = self.pipe.acquire(roots, files, inventory, did, exports, witnesses,
                    g3, owner, destination, acquire_journal, out, source_cap=source_cap, run_id=run_id)
                out.flush()
            archive = self.work/"offhost"
            with wire.open("rb") as stream:
                self.m.C.R.W.receive_offhost_ciphertext(stream, archive, quota_bytes=cap)
            # An independent complete read of every AEAD part and every file.
            with self.m.C.R.LockedArchive(archive) as locked:
                manifest, proof = locked.verify(bytes(recovery))
            K.need(proof["manifest_sha256"] == epoch["manifest_digest"] and
                   self.m.C.G.sha(self.m.M.state_inventory(manifest)) == epoch["ledger_digest"] and
                   proof["bytes"] == epoch["source_bytes"] and
                   proof["epoch"] == "FROZEN:"+epoch["epoch"], "FULL_READBACK_BINDING_STOP")
            binding = dict(epoch=epoch, run_id=run_id, cursors=out.cursors,
                           archive_proof=proof, mode="OFFLINE_TRIAL")
            self.journal.save(dict(phase="FULL_READBACK_RESTORE_UNPROVEN", **binding))
            # Only this attempt's redundant ciphertext wire, after verified
            # offhost shards; never remove user backups or interrupted evidence.
            wire.unlink()
            return binding
        except BaseException:
            self.journal.save(dict(phase="INTERRUPTED_NO_BLIND_RETRY", run_id=run_id, mode="OFFLINE_TRIAL"))
            raise

    def restore(self, recovery, *, receipt=None, rollback=None):
        """Resume only the same fully verified archive; never recapture.

        A local DISARMED result is not an independent receipt. Final validation
        needs the existing restorer and rollback-role signed packets separately.
        """
        current = self.journal.latest
        K.need(current is not None and current["phase"] in (
            "FULL_READBACK_RESTORE_UNPROVEN", "RESTORE_INTERRUPTED_REVIEW_REQUIRED", "DISARMED_LOCAL_READBACK"),
            "RESTORE_EVIDENCE_REQUIRED")
        bind = {k: current[k] for k in ("epoch", "run_id", "cursors", "archive_proof", "mode")}
        epoch = bind["epoch"]
        # Isolated instance: changing a laboratory landing must never redirect
        # any existing production module or shared transport's global ROOT.
        path = Path(__file__).with_name("r1086_k137_disarmed_stream_restore.py")
        spec = importlib.util.spec_from_file_location("r1163_trial_restore", path)
        restorer = importlib.util.module_from_spec(spec); spec.loader.exec_module(restorer)
        landing = self.work/"quarantine"
        if not landing.exists(): landing.mkdir(mode=0o700)
        self.m.C.R.T.private_dir(landing)
        restorer.ROOT = landing
        dest = self.pipe.controller.enrollment.context["destination"]
        restorer.machine_digest = lambda: dest  # synthetic enrollment ONLY
        self.journal.save(dict(phase="RESTORE_INTERRUPTED_REVIEW_REQUIRED", **bind))
        try:
            with self.m.C.R.LockedArchive(self.work/"offhost") as locked:
                _, proof = locked.verify(bytes(recovery))
                K.need(proof == bind["archive_proof"], "RESTORE_ARCHIVE_CHANGED_STOP")
                result = restorer.restore_stream(BlocksIO(locked.blocks(bytes(recovery))), bind["run_id"], dest, os.geteuid(),
                    quota_bytes=max(1, proof["bytes"]), expected_epoch="FROZEN:"+epoch["epoch"],
                    expected_manifest_sha256=epoch["manifest_digest"],
                    preserve_inert_links=True, resume=True, expected_cursors=bind["cursors"])
                locked.check()
            local_receipt = self.m.C.decode((landing/bind["run_id"]/"DISARMED-STREAM-RECEIPT.json").read_bytes())
            K.need(local_receipt["runtime_started"] is False and result["cutover"] == "NO_GO" and
                   result["manifest_sha256"] == epoch["manifest_digest"], "DISARMED_RESTORE_STOP")
            self.journal.save(dict(phase="DISARMED_LOCAL_READBACK", **bind))
            if receipt is None or rollback is None:
                return dict(state="UNKNOWN", mode="OFFLINE_TRIAL", restore="DISARMED_LOCAL_READBACK",
                            independent_receipt="REQUIRED", cutover="NO_GO")
            checked = self.pipe.verify_restore(epoch, receipt, rollback, now=int(self.clock()))
            self.journal.save(dict(phase="OFFLINE_TRIAL_VERIFIED", **bind))
            return dict(state="PASS", mode="OFFLINE_TRIAL", **checked)
        except BaseException:
            # This phase deliberately allows only same-archive restore review,
            # not new export or automatic replay of any POST/owner operation.
            raise


def app_rollback(controller, owner, witness, *, now):
    """Existing exact APP undo, old global POST denial permanently retained.

    No VM/volume operation is represented by this API. Production controller
    admission remains the existing independent host/backend/owner contract.
    """
    return controller.rollback(owner, witness, now=now)


def new_only_plan(files, inventory, did, epoch, enrollment):
    """Derive the existing runtime quarantine from original epoch bytes only.

    This does not activate a publisher or authorize signing. R1155 activation,
    R1156 fresh-origin checks and R1158 machine/boot/single-writer/capacity gates
    are still mandatory. Old/UNKNOWN IDs, nonces and rate history are retained.
    """
    S = K.legacy("r1155_signer.py")
    K.need(K.sha(did.encode()) == enrollment.context["did"], "ORIGINAL_DID_REQUIRED")
    K.need(epoch["source_head"] == S.C.G.SOURCE_HEAD and epoch["whole_state_verified"] is True,
           "RUNTIME_ORIGINAL_EPOCH_REQUIRED")
    baseline = S.baseline(files, inventory, did, epoch["epoch"])
    K.need(baseline["ledger_sha"] == epoch["ledger_digest"], "RUNTIME_LEDGER_EPOCH_STOP")
    return dict(baseline=baseline, baseline_sha=K.sha(K.canonical(baseline)),
                activation="NO_GO", publisher="SINGLE_ISOLATED_PUBLISHER_ONLY",
                replay="ALL_OLD_FIVE_ROUTE_IDS_DENIED_UNKNOWN_REMAINS_UNKNOWN",
                required_gates=["r1155_signer.activation", "r1155_signer.approved", "r1156_runtime.origin",
                                "r1156_runtime.publish_cycle", "r1158_machine.target_activation"])


def stable_gate(enrollment, packet, owner, *, now, action="APP_ROLLBACK_REVIEW"):
    K.need(action == "APP_ROLLBACK_REVIEW", "VM_STOP_OR_DELETE_NOT_IMPLEMENTED")
    data = enrollment.verify(packet, "r1163-stable", "independent", now)
    K.shape(data, "epoch_digest manifest_digest source_boot destination_boot stable_since observed_at original_did_digest source_permanent_deny single_publisher backup_full_readback rollback_drill destination_writers_fenced ambiguous_posts")
    for name in ("epoch_digest", "manifest_digest", "source_boot", "destination_boot", "original_did_digest"):
        K.digest(data[name])
    K.need(data["original_did_digest"] == enrollment.context["did"], "STABLE_DID_STOP")
    K.need(type(data["stable_since"]) is int and type(data["observed_at"]) is int and
           data["stable_since"]+86400 <= data["observed_at"] <= now and now-data["observed_at"] <= 30,
           "STABILITY_WINDOW_UNPROVEN")
    K.need(all(data[x] is True for x in ("source_permanent_deny", "single_publisher", "backup_full_readback",
           "rollback_drill", "destination_writers_fenced")) and type(data["ambiguous_posts"]) is int and
           data["ambiguous_posts"] == 0, "ROLLBACK_NOT_SAFE")
    expected = dict(action=action, evidence_sha256=K.sha(K.canonical(packet)), retain_original_vm=True,
                    retain_volumes=True, automatic_restart=False, retain_old_post_deny=True)
    K.need(enrollment.verify(owner, "r1163-final-review", "owner", now) == expected, "SEPARATE_FINAL_CONSENT_REQUIRED")
    return dict(state="PASS", permission="APP_ROLLBACK_REVIEW_ONLY", vm_stop="NO_GO", volume_delete="NO_GO")
