"""R1107 consolidation, common-epoch verifier and dry-run-only owner gate.

No production controller, migration activation, signing, secret/key input,
deletion or network CLI exists. Legacy R1089/pins remain byte-for-byte frozen.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
from pathlib import Path
import sqlite3
import sys
import time

spec = importlib.util.spec_from_file_location("flop_r1107_contract", Path(__file__).with_name("r1107_contract.py"))
C = sys.modules.get(spec.name)
if C is None:
    C = importlib.util.module_from_spec(spec); sys.modules[spec.name] = C; spec.loader.exec_module(C)
B = C.legacy("r1107_g1g4_boundary.py")
P = C.legacy("r1107_g5_reconciliation.py")
GIB = 1024**3
RESERVE = C.R.D.RESERVE


def state_inventory(manifest):
    C.R.D.validate_manifest(manifest, preserve_inert_links=True)
    return {r["path"][6:]: r["sha256"] for r in manifest["entries"] if r["kind"] == "file" and
            r["path"].startswith("state/") and
            r["path"] not in {"state/" + db + suffix for db in C.G.DATABASES for suffix in ("", "-wal", "-shm")}}


def common_epoch(controller, roots, *, clock=time.time, offline_trial=False):
    """Actual SQLite+WAL and full-state verification under an external fence.

    No freeze/copy/stop/checkpoint mutation. Production roots can be used ONLY
    by an independently admitted backend. This API has no CLI route. Source
    mode=ro requires an actually readonly view; SHM/metadata drift fails closed.
    """
    held = controller.guard(now=int(clock()))
    epoch = held["epoch"]
    C.need(set(roots) == {"app", "state"}, "ROOT_SCOPE_STOP")
    C.need(all(type(p) is type(Path()) and p.is_absolute() and not p.is_symlink() for p in roots.values()), "ROOT_SCOPE_STOP")
    if offline_trial:
        for p in roots.values(): C.R.T.offline_source(p)
    else:
        C.need(tuple(str(roots[k]) for k in ("app", "state")) == C.ROOTS, "ROOT_SCOPE_STOP")
    def census():
        controller.guard(now=int(clock()))
        result = C.R.T._census_roots(roots, C.G.SOURCE_HEAD, epoch="FROZEN:" + epoch)
        controller.guard(now=int(clock()))
        return result
    _, before, before_ids = census()
    verified = roots["state"] / "verified-did.json"
    C.need(verified.is_file() and not verified.is_symlink() and verified.stat().st_size <= 16384, "DID_BINDING_STOP")
    did = C.decode(verified.read_bytes()).get("did")
    C.need(type(did) is str and C.raw_hash(did.encode()) == controller.enrollment.context["did"], "DID_BINDING_STOP")
    C.V._public_key(did)
    inventory = state_inventory(before)
    C.need(C.G.sha(inventory) == held["ledger_digest"], "COMMON_LEDGER_EPOCH_STOP")
    images = {}
    with contextlib.ExitStack() as stack:
        for name in C.G.DATABASES:
            db = roots["state"] / name
            connection = stack.enter_context(contextlib.closing(sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)))
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            C.need(connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "SQLITE_INTEGRITY_STOP")
            count, seq = connection.execute("SELECT count(*),coalesce(max(seq),0) FROM messages").fetchone()
            rows = {r["path"]: r for r in before["entries"]}
            expected = "state/" + name
            C.need(expected in rows and expected + "-wal" in rows, "SQLITE_WAL_MISSING")
            images[name] = {"sha256": rows[expected]["sha256"], "wal_sha256": rows[expected + "-wal"]["sha256"],
                            "shm_sha256": rows.get(expected + "-shm", {}).get("sha256"),
                            "count": count, "seq": seq, "epoch": epoch}
        _, during, during_ids = census()
        C.need(during == before and during_ids == before_ids, "COMMON_EPOCH_DRIFT")
    _, after, after_ids = census()
    C.need(after == before and after_ids == before_ids, "COMMON_EPOCH_DRIFT")
    current = controller.guard(now=int(clock()))
    C.need(all(current[k] == held[k] for k in ("epoch", "census_digest", "ledger_digest", "plan_digest")), "COMMON_EPOCH_DRIFT")
    C.need(len(images) == 2 and len({(before_ids["state/" + n][0], before_ids["state/" + n][1]) for n in images}) == 2,
           "DISTINCT_SQLITE_STOP")
    return {"epoch": epoch, "manifest_digest": C.G.sha(before), "ledger_digest": C.G.sha(inventory),
            "source_bytes": sum(r["size"] for r in before["entries"]),
            "evidence_mode": "OFFLINE_TRIAL" if offline_trial else "HELD_ORIGINAL_SCOPE",
            "images": images, "source_head": C.G.SOURCE_HEAD,
            "barrier_plan_digest": held["plan_digest"], "whole_state_verified": True}


def capacity(data, *, source_bytes, now):
    C.shape(data, "observed_at free_bytes memory_bytes tradebot_peak_bytes flop_limit_bytes os_reserve_bytes margin_bytes cpu_psi_safe zero_incremental_cost")
    C.fresh(data["observed_at"], now)
    C.integer(source_bytes, 1, C.R.C.MAX_SOURCE_BYTES)
    for k in ("free_bytes", "memory_bytes", "tradebot_peak_bytes", "flop_limit_bytes", "os_reserve_bytes", "margin_bytes"):
        C.integer(data[k])
    C.need(data["free_bytes"] >= source_bytes + C.R.D.SQLITE_ALLOWANCE + RESERVE, "K137_CAPACITY_NO_GO")
    C.need(data["memory_bytes"] <= 2 * GIB and 0 < data["flop_limit_bytes"] <= 256 * 1024**2 and
           data["margin_bytes"] >= 256 * 1024**2 and data["tradebot_peak_bytes"] + data["flop_limit_bytes"] +
           data["os_reserve_bytes"] + data["margin_bytes"] <= data["memory_bytes"], "K137_MEMORY_NO_GO")
    C.need(data["cpu_psi_safe"] is True and data["zero_incremental_cost"] is True, "RESOURCE_NO_GO")
    return {"capacity": "EVIDENCE_CONSISTENT", "protected_reserve_bytes": RESERVE,
            "required_bytes": source_bytes + C.R.D.SQLITE_ALLOWANCE + RESERVE}


def verify_backup_binding(archive, recovery, epoch_packet, enrollment, *, now, windows_validator=None):
    """Reuse the unchanged R1089 full AES-GCM verifier; no second crypto path.

    Library-only offhost custody operation, never a source acquire or CLI secret
    input. A matching archive does not prove actual destination restoration.
    """
    epoch = enrollment.verify(epoch_packet, "G6", "independent", now)
    C.need(epoch["source_head"] == C.G.SOURCE_HEAD and epoch["whole_state_verified"] is True and
           epoch["evidence_mode"] in ("OFFLINE_TRIAL", "HELD_ORIGINAL_SCOPE"), "BACKUP_EPOCH_BINDING_STOP")
    try:
        with C.R.LockedArchive(archive, windows_validator=windows_validator) as held:
            manifest, verified = held.verify(recovery)
    except Exception:
        raise C.Stop("BACKUP_AUTH_STOP") from None
    C.need(verified["epoch"] == "FROZEN:" + epoch["epoch"] and verified["manifest_sha256"] == epoch["manifest_digest"] and
           verified["bytes"] == epoch["source_bytes"] and C.G.sha(state_inventory(manifest)) == epoch["ledger_digest"],
           "BACKUP_EPOCH_BINDING_STOP")
    rows = {r["path"]: r for r in manifest["entries"]}
    C.need(set(epoch["images"]) == set(C.G.DATABASES), "BACKUP_EPOCH_BINDING_STOP")
    for name, image in epoch["images"].items():
        C.need(image["epoch"] == epoch["epoch"] and rows["state/" + name]["sha256"] == image["sha256"] and
               rows["state/" + name + "-wal"]["sha256"] == image["wal_sha256"] and
               rows.get("state/" + name + "-shm", {}).get("sha256") == image["shm_sha256"], "BACKUP_EPOCH_BINDING_STOP")
    return {**C.decisions("BACKUP_BOUND_DESTINATION_NOT_PROVEN"), "backup_aead": "VERIFIED_AND_G6_BOUND",
            "G7": "DESTINATION_RESTORE_NOT_PROVEN", "manifest_digest": verified["manifest_sha256"],
            "evidence_mode": epoch["evidence_mode"]}


def disarmed_smoke(epoch_packet, receipt_packet, enrollment, *, now):
    """Independent receipt consistency only, not a live host/start operation."""
    epoch = enrollment.verify(epoch_packet, "G6", "independent", now)
    receipt = enrollment.verify(receipt_packet, "disarmed-restore", "restorer", now)
    C.shape(receipt, "manifest_digest source_bytes images runtime_started write_root uid memory_max tasks_max cpu_percent original_metadata_reviewed")
    C.need(receipt["manifest_digest"] == epoch["manifest_digest"] and receipt["source_bytes"] == epoch["source_bytes"] and
           receipt["images"] == epoch["images"] and receipt["runtime_started"] is False and
           receipt["write_root"] == str(C.R.D.ROOT).replace("\\", "/") and
           type(receipt["uid"]) is int and receipt["uid"] == 1000 and
           type(receipt["memory_max"]) is int and receipt["memory_max"] == 256 * 1024**2 and
           type(receipt["tasks_max"]) is int and receipt["tasks_max"] == 64 and
           type(receipt["cpu_percent"]) is int and receipt["cpu_percent"] == 50, "DISARMED_SMOKE_STOP")
    return {**C.decisions("INDEPENDENT_RECEIPT_CONSISTENT_NOT_LIVE_ACCEPTANCE"), "runtime_started": False,
            "signer": "NOT_PROVEN", "activation": "DISABLED",
            "metadata_activation_review": "STILL_REQUIRED" if receipt["original_metadata_reviewed"] is not True else "REVIEW_RECORDED_NOT_APPLIED"}


def cleanup_review(manifest, fresh_files, restore, retirement, owner, enrollment, *, now):
    """Review ONLY regenerated app caches; no deletion method or authority.

    Entire state, unknown objects, symlinks, hardlinks, .git/.venv and TradeBot
    remain excluded. Historical R1095 atomic-state cleanup is NEVER repeated.
    """
    proof = enrollment.verify(restore, "restore", "restorer", now)
    expected = {"manifest_digest": C.G.sha(manifest), "backup_aead": True, "restored_exact": True,
                "same_did_preserved": True, "incomplete": False}
    C.need(proof == expected, "RESTORE_REQUIRED")
    binding = {"manifest_digest": C.G.sha(manifest), "restore_digest": C.G.sha(restore), "review_only": True,
               "candidate_snapshot_digest": C.G.sha({k: {"sha256": C.raw_hash(v), "bytes": len(v)} for k, v in fresh_files.items()})}
    C.need(enrollment.verify(retirement, "retirement-review", "independent", now) == binding and
           enrollment.verify(owner, "retirement-review", "owner", now) == binding, "RETIREMENT_GATE_REQUIRED")
    rows, _, _ = C.R.D.validate_manifest(manifest, preserve_inert_links=True)
    candidates = []
    for name, raw in fresh_files.items():
        row = rows.get(name)
        C.need(row is not None and row["kind"] == "file" and C.raw_hash(raw) == row["sha256"] and len(raw) == row["size"],
               "FRESH_FILE_DRIFT")
        permitted = name.startswith(("app/.pytest_cache/", "app/src/flop_agent/__pycache__/"))
        sensitive = any(s in name.lower() for s in ("seed", "secret", "credential", "private", "did", "nonce", "receipt", "sqlite", "-wal", "tradebot"))
        if permitted and not sensitive:
            candidates.append({"path_digest": C.raw_hash(name.encode()), "bytes": row["size"], "sha256": row["sha256"]})
    return {**C.decisions("REVIEW_CANDIDATES_ONLY"), "candidates": candidates, "deletion_authority": "NONE",
            "excluded": ["ALL_STATE", "SQLITE_WAL_SHM", "DID_AND_CUSTODY", "FIVE_ROUTE_HISTORY", "TRADEBOT", "UNKNOWN_OBJECTS"]}


def dry_run(control, *, now):
    C.shape(control, "enrollment plan")
    enrollment = C.Enrollment(control["enrollment"])
    plan = control["plan"]
    C.shape(plan, "schema_version context census review owner barrier_plan g4 g5 g6 destination source_bytes legacy_plan_digest host_pins")
    C.need(type(plan["schema_version"]) is int and plan["schema_version"] == 1 and plan["context"] == enrollment.context, "PLAN_BINDING_STOP")
    C.digest(plan["legacy_plan_digest"])
    pins = plan["host_pins"]
    C.shape(pins, "original_host_key_digest destination_host_key_digest")
    for v in pins.values(): C.digest(v)
    C.need(len(set(pins.values())) == 2, "HOST_PIN_STOP")
    binding = {"plan_digest": C.G.sha({k: v for k, v in plan.items() if k != "owner"}),
               "mode": "DRY_RUN_ONLY", "original_head": C.G.SOURCE_HEAD}
    C.need(enrollment.verify(plan["owner"], "owner-dryrun", "owner", now) == binding, "OWNER_BINDING_STOP")
    census_digest = B.bind_review(plan["census"], plan["review"], enrollment, now=now)
    g4 = enrollment.verify(plan["g4"], "G4", "independent", now)
    C.shape(g4, "plan_digest epoch census_digest backend_digest sequence previous ledger_digest global_deny")
    bp = plan["barrier_plan"]
    C.shape(bp, "context roots_digest uid census_digest epoch backend_digest capabilities")
    proposed = B.Controller(enrollment, None).propose(bp["census_digest"], bp["epoch"], bp["backend_digest"])
    C.need(type(bp["uid"]) is int and bp["uid"] == 0 and bp == proposed and g4["plan_digest"] == C.G.sha(bp) and g4["epoch"] == bp["epoch"] and
           g4["backend_digest"] == bp["backend_digest"] and g4["census_digest"] == census_digest and
           bp["census_digest"] == census_digest and g4["global_deny"] is True, "G4_NOT_PROVABLE")
    C.integer(g4["sequence"], 1); C.digest(g4["previous"]); C.digest(g4["ledger_digest"])
    g5 = enrollment.verify(plan["g5"], "G5-retained", "upstream", now)
    C.shape(g5, "epoch ledger_digest routes semantics")
    C.need(g5["epoch"] == g4["epoch"] and g5["ledger_digest"] == g4["ledger_digest"] and
           set(g5["routes"]) == set(P.ROUTES) and g5["semantics"] == "RETAINED_POSITIVE_ONLY", "G5_BINDING_STOP")
    for row in g5["routes"].values():
        C.shape(row, "known_attempts retained_positive_matches")
        C.integer(row["known_attempts"], 0, P.MAX_RECORDS)
        C.integer(row["retained_positive_matches"], 0, row["known_attempts"])
    g6 = enrollment.verify(plan["g6"], "G6", "independent", now)
    C.shape(g6, "epoch manifest_digest ledger_digest images source_head barrier_plan_digest whole_state_verified source_bytes evidence_mode")
    C.need(g6["epoch"] == g4["epoch"] and g6["ledger_digest"] == g4["ledger_digest"] and
           g6["barrier_plan_digest"] == g4["plan_digest"] and g6["source_head"] == C.G.SOURCE_HEAD and
           g6["whole_state_verified"] is True and set(g6["images"]) == set(C.G.DATABASES) and
           g6["source_bytes"] == plan["source_bytes"] and g6["evidence_mode"] == "HELD_ORIGINAL_SCOPE", "G6_EPOCH_STOP")
    C.digest(g6["manifest_digest"])
    for image in g6["images"].values():
        C.shape(image, "sha256 wal_sha256 shm_sha256 count seq epoch")
        C.digest(image["sha256"]); C.digest(image["wal_sha256"])
        if image["shm_sha256"] is not None: C.digest(image["shm_sha256"])
        C.integer(image["count"]); C.integer(image["seq"])
        C.need(image["epoch"] == g4["epoch"], "G6_EPOCH_STOP")
    dest = enrollment.verify(plan["destination"], "destination", "destination", now)
    C.shape(dest, "host_pins capacity")
    C.need(dest["host_pins"] == pins, "HOST_PIN_STOP")
    resource = capacity(dest["capacity"], source_bytes=plan["source_bytes"], now=now)
    # This official retained endpoint cannot certify missing historical POSTs.
    # Even a signed all-positive summary must NOT unlock old SourceGuard.
    return {**C.decisions("G5_NOT_PROVABLE_FROM_RETAINED_HISTORY"), "G1": "SIGNED_CENSUS_REVIEWED",
            "G2": resource["capacity"], "G3": "NO_GO", "G4": "EXTERNAL_EVIDENCE_ONLY_NOT_LIVE_PROVEN",
            "G5": "NO_GO", "G6": "SIGNED_EPOCH_REVIEWED_NOT_LIVE_PROVEN", "G7": "NOT_PERFORMED",
            "legacy_source_guard_used": False, "r987_custody_accessed": False,
            "transfer": "DISABLED", "signer_portability": "NOT_PROVEN", "testnet": "REUSE_R1105_NO_REAL_ADAPTER"}


def main():
    try:
        C.need(sys.argv[1:] == ["--dry-run"], "DRY_RUN_ONLY")
        # Reuse the existing audited native public-control framing, not a PS
        # text pipe. No recovery material follows this public plan.
        control = C.R.frame_read(sys.stdin.buffer, C.R.MAGIC)
        C.need(sys.stdin.buffer.read(1) == b"", "INPUT_BOUND_STOP")
        result = dry_run(control, now=int(time.time()))
        print(C.G.canonical(result).decode("ascii"))
        return 0
    except Exception as error:
        code = str(error) if type(error) is C.Stop else "EVIDENCE_INVALID_OR_UNAVAILABLE"
        # C.Stop is only constructed from fixed source constants.
        print(C.G.canonical(C.decisions(code)).decode("ascii"))
        return 42


if __name__ == "__main__":
    raise SystemExit(main())
