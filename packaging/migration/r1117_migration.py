"""One-shot acquisition/restore integration. CLI stays DISARMED.

No built-in complete-history authority or global-denial driver exists. Those
missing real capabilities cannot be replaced with a JSON GO flag. Production
transport/custody remains the unchanged audited R1089 owner's responsibility.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import time

spec = importlib.util.spec_from_file_location("flop_r1107_contract", Path(__file__).with_name("r1107_contract.py"))
C = sys.modules.get(spec.name)
if C is None:
    C = importlib.util.module_from_spec(spec); sys.modules[spec.name] = C; spec.loader.exec_module(C)
M = C.legacy("r1107_readiness.py")
S = C.legacy("r1117_signer.py")
ROUTES = M.P.ROUTES


def outcome(reason):
    return {"phase": "R1117", "mode": "DISARMED", "reason": reason,
            "G3": "REAL_CUSTODY_NOT_PROVEN", "G4": "G4_NOT_PROVABLE",
            "G5": "AUTHORITATIVE_HISTORY_UNAVAILABLE", "G6": "NO_SOURCE_EXPORT",
            "G7": "NOT_PERFORMED", "cutover": "NO_GO", "oci_retirement": "STRICT_NO_GO"}


class RetainedHistory:
    """Existing actual GET-only verifier. Retention never implies completeness."""
    profile = "OFFICIAL_RETAINED_ONLY"

    def reconcile(self, files, did, controller, exports, witnesses, *, now, inventory=None):
        try:
            report = M.P.reconcile(files, did, controller, exports, witnesses, controller.enrollment,
                                   now=now, inventory=inventory)
            return {"status": "UNKNOWN", "routes": report["routes"], "ledger_digest": report["ledger_digest"],
                    "reason": "G5_COMPLETE_HISTORICAL_INDEX_AND_CLAIM_CAS_MISSING"}
        except Exception:
            return {"status": "UNKNOWN", "reason": "G5_ORIGINAL_OR_UPSTREAM_EVIDENCE_UNVERIFIED"}

    def complete(self, *args, **kwargs):
        raise C.Stop("G5_AUTHORITATIVE_COMPLETE_HISTORY_UNAVAILABLE")


def verify_complete_authority(authority, files, did, controller, exports, witnesses, *, now, trial=False, inventory=None):
    """A reviewed read-only authenticated upstream adapter is REQUIRED.

    There is deliberately no parser accepting caller-supplied ACCEPTED /
    DEFINITELY_NOT_ACCEPTED alone. The existing API cannot provide negative
    finality, so its concrete RetainedHistory adapter always rejects release.
    Test adapters are explicitly confined to blocked-root offline trials.
    """
    C.need(type(trial) is bool, "G5_TRIAL_MODE_STOP")
    C.need(trial or authority.profile != "SYNTHETIC_TEST_ONLY", "G5_SYNTHETIC_AUTHORITY_STOP")
    # No official complete-history/negative-finality protocol is enrolled.
    # Renaming a test adapter or supplying a signed boolean cannot enable a
    # production release. A future real adapter requires a separate code audit.
    C.need(trial and authority.profile == "SYNTHETIC_TEST_ONLY", "G5_AUTHORITATIVE_COMPLETE_HISTORY_UNAVAILABLE")
    held = controller.guard(now=now)
    digest = M.P.ledger_digest(files, inventory)
    C.need(digest == held["ledger_digest"], "G5_LEDGER_EPOCH_STOP")
    attempts = M.P.original_attempts(files, did)
    result = authority.complete(attempts=attempts, files=files, did=did, exports=exports,
        witnesses=witnesses, controller=controller, now=now, inventory=inventory)
    C.shape(result, "epoch ledger_digest routes authority_digest")
    C.digest(result["authority_digest"])
    C.need(result["epoch"] == held["epoch"] and result["ledger_digest"] == digest and
           set(result["routes"]) == set(ROUTES), "G5_COMPLETE_BINDING_STOP")
    for route, rows in attempts.items():
        # The adapter MUST authenticate full authority/completeness, not only
        # this structural check. Exact identities/legs prevent shared receipts.
        verdicts = result["routes"][route]
        C.need(type(verdicts) is list and len(verdicts) == len(rows), "G5_INCOMPLETE_STOP")
        wanted = {(r["id"], r["leg"], r["nonce"]) for r in rows}
        found = set()
        for v in verdicts:
            C.shape(v, "id leg nonce verdict evidence_digest")
            identity = v["id"], v["leg"], v["nonce"]
            C.need(identity in wanted and identity not in found, "G5_DUPLICATE_OR_MISSING_STOP")
            # No pending, attempted, ambiguous, timeout, negative-from-ring etc.
            C.need(v["verdict"] in ("AUTHENTICATED_ACCEPTED", "AUTHORITATIVE_NEVER_ACCEPTED"), "G5_UNKNOWN_STOP")
            C.digest(v["evidence_digest"]); found.add(identity)
        C.need(found == wanted, "G5_INCOMPLETE_STOP")
    C.need(controller.guard(now=now) == held, "G5_EPOCH_CHANGED")
    return result


def source_sidecars(controller, provider, *, now):
    """Only after G4 admission: provider owns exact private immutable custody.

    Source metadata/index must cover all original signer/outbox/nonces/history;
    unknown archive/retention is NEVER filled with an empty dictionary.
    """
    held = controller.guard(now=now)
    files, inventory = provider.read_private_sidecars()
    C.need(M.P.ledger_digest(files, inventory) == held["ledger_digest"], "G5_LEDGER_EPOCH_STOP")
    C.need(controller.guard(now=now) == held, "G5_EPOCH_CHANGED")
    return files, inventory


class OneShot:
    def __init__(self, controller, authority=None, *, trial=False, clock=time.time):
        C.need(type(trial) is bool, "G6_TRIAL_MODE_STOP")
        self.controller, self.authority = controller, authority or RetainedHistory()
        self.trial, self.clock = trial, clock

    def acquire(self, roots, files, inventory, did, exports, witnesses, g3, owner, destination,
                journal, output, *, source_cap, run_id):
        """Library execution contract, NOT an owner activation CLI.

        Accepts authenticated adapters only. Default public RetainedHistory
        prevents any SQLite/full-state read or ciphertext on current evidence.
        Output is R1089 ciphertext-only; no plaintext staging or second crypto.
        """
        now = int(self.clock()); ctl = self.controller; trust = ctl.enrollment
        if self.trial:
            for p in roots.values(): C.R.T.offline_source(p)
        else:
            C.need(tuple(str(roots[k]) for k in ("app", "state")) == C.ROOTS, "G6_ROOT_SCOPE_STOP")
        held = ctl.guard(now=now)
        C.need(type(run_id) is str and C.R.re.fullmatch(r"[0-9a-f]{32}", run_id), "G6_RUN_STOP")
        S.verify_proof(trust, g3["binding"], g3["owner"], g3["recipient"], g3["proof"], now=now)
        identity = trust.verify(g3["admission"], "r1117-G3-portability", "identity", now)
        C.need(identity == {"proof_digest": C.G.sha(g3["proof"]), "real_custody": not self.trial,
               "recipient_binding": C.G.sha(g3["binding"]), "scope": "OFFLINE_TRIAL" if self.trial else "REVIEWED_ORIGINAL_K137"},
               "G3_REAL_PORTABILITY_NOT_PROVEN")
        finality = verify_complete_authority(self.authority, files, did, ctl, exports, witnesses,
            now=now, trial=self.trial, inventory=inventory)
        dest = trust.verify(destination, "r1117-destination", "destination", now)
        C.shape(dest, "source_host destination_host source_host_key destination_host_key capacity runtime_started")
        C.need(dest["source_host"] == trust.context["host"] and dest["destination_host"] == trust.context["destination"] and
               dest["runtime_started"] is False and dest["source_host_key"] != dest["destination_host_key"], "G7_HOST_PIN_STOP")
        C.digest(dest["source_host_key"]); C.digest(dest["destination_host_key"])
        M.capacity(dest["capacity"], source_bytes=source_cap, now=now)
        binding = {"operation": "R1117_OFFLINE_TRIAL" if self.trial else "R1117_ACQUIRE_DISARMED_RESTORE",
                   "run_id": run_id, "barrier_plan_digest": held["plan_digest"], "epoch": held["epoch"],
                   "ledger_digest": held["ledger_digest"], "g3_digest": C.G.sha(g3), "finality_digest": C.G.sha(finality),
                   "destination_digest": C.G.sha(destination), "source_cap": source_cap}
        C.need(trust.verify(owner, "r1117-one-shot", "owner", now) == binding, "G6_EXACT_OWNER_APPROVAL_REQUIRED")
        C.need(journal.latest is None, "G6_ONE_SHOT_ALREADY_ATTEMPTED")
        C.need(output.host_pins == (dest["source_host_key"], dest["destination_host_key"]), "G7_TRANSPORT_PIN_STOP")
        # Source image reads occur ONLY after G4/G5, G3, host/capacity, approval.
        try:
            epoch = M.common_epoch(ctl, roots, clock=self.clock, offline_trial=self.trial)
        except Exception:
            raise C.Stop("G6_COMMON_EPOCH_UNPROVEN") from None
        C.need(epoch["source_bytes"] <= source_cap, "G6_SOURCE_CAP_STOP")
        _, manifest, ids = C.R.T._census_roots(roots, C.G.SOURCE_HEAD, epoch="FROZEN:" + held["epoch"])
        C.need(C.G.sha(manifest) == epoch["manifest_digest"], "G6_EPOCH_CHANGED")
        # output is an independently admitted fixed-host transport capability.
        C.need(output.host_pins == (dest["source_host_key"], dest["destination_host_key"]), "G7_TRANSPORT_PIN_STOP")
        journal.save({"phase": "EXPORT_ATTEMPTING", "binding": binding, "epoch": epoch})
        def census():
            ctl.guard(now=int(self.clock()))
            current = C.R.T._census_roots(roots, C.G.SOURCE_HEAD, epoch="FROZEN:" + held["epoch"])
            C.need(C.G.sha(current[1]) == epoch["manifest_digest"], "G6_EPOCH_CHANGED")
            return current
        class GuardedOutput:
            def write(_, block):
                ctl.guard(now=int(self.clock()))
                return output.write(block)
            def flush(_):
                ctl.guard(now=int(self.clock())); output.flush()
        try:
            # The old owner transport supplies recovery through its approved
            # secure path; no secret CLI/env/file path is added by R1117.
            output.seal_using_existing_r1089(roots, manifest, ids, GuardedOutput(), census)
            ctl.guard(now=int(self.clock()))
        except Exception:
            journal.save({"phase": "INTERRUPTED_NO_BLIND_RETRY", "binding": binding, "epoch": epoch})
            raise C.Stop("G6_TRANSFER_INTERRUPTED") from None
        journal.save({"phase": "CIPHERTEXT_EMITTED_RESTORE_UNPROVEN", "binding": binding, "epoch": epoch})
        return epoch

    def verify_restore(self, epoch, receipt, rollback, *, now):
        trust = self.controller.enrollment
        data = trust.verify(receipt, "r1117-restored", "restorer", now)
        expected = {"epoch_digest": C.G.sha(epoch), "manifest_digest": epoch["manifest_digest"],
                    "ledger_digest": epoch["ledger_digest"], "images": epoch["images"],
                    "did_digest": trust.context["did"], "runtime_started": False,
                    "whole_archive_aead": True, "scope": "OFFLINE_TRIAL" if self.trial else "K137_DISARMED"}
        C.need(data == expected, "G7_INDEPENDENT_RESTORE_STOP")
        C.need(trust.verify(rollback, "r1117-rollback-ready", "independent", now) ==
               {"epoch_digest": C.G.sha(epoch), "destination_writers_fenced": True,
                "original_preserved": True, "no_post_retry": True}, "G7_ROLLBACK_STOP")
        return {**outcome("DISARMED_RESTORE_RECEIPT_CONSISTENT"), "G6": "OFFLINE_TRIAL_VERIFIED" if self.trial else "SIGNED_EPOCH_CHECKED",
                "G7": "INDEPENDENT_RECEIPT_CHECKED_NOT_ACTIVATED"}


def main():
    # New future one-owner invocation contract. No fallback to old R1112 or
    # old SourceGuard. Runtime authority/key import is deliberately unavailable.
    result = outcome("R1117_DISARMED_ONLY")
    if sys.argv[1:] == ["--dry-run"]:
        try:
            control = C.R.frame_read(sys.stdin.buffer, C.R.MAGIC)
            C.need(sys.stdin.buffer.read(1) == b"", "PUBLIC_INPUT_STOP")
            C.shape(control, "enrollment g3")
            C.shape(control["g3"], "binding owner recipient proof")
            g3 = control["g3"]
            checked = S.verify_proof(C.Enrollment(control["enrollment"]), g3["binding"], g3["owner"],
                                     g3["recipient"], g3["proof"], now=int(time.time()))
            result = {**outcome("G4_GLOBAL_DENIAL_AND_G5_HISTORY_AUTHORITY_REQUIRED"), "G3": checked["G3"],
                      "public_proof_digest": checked["proof_digest"]}
        except Exception:
            result = outcome("PUBLIC_CONTINUITY_EVIDENCE_INVALID_OR_UNAVAILABLE")
    print(C.G.canonical(result).decode())
    return 42


if __name__ == "__main__":
    raise SystemExit(main())
