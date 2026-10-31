"""R1117 systemd v249 metadata adapter and durable DI-only barrier backend.

No production stop/mount/firewall/kill primitive. An external real global-denial
driver and independently signed capability admission remain mandatory.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import stat
import sys
import time

spec = importlib.util.spec_from_file_location("flop_r1107_contract", Path(__file__).with_name("r1107_contract.py"))
C = sys.modules.get(spec.name)
if C is None:
    C = importlib.util.module_from_spec(spec); sys.modules[spec.name] = C; spec.loader.exec_module(C)
B = C.legacy("r1107_g1g4_boundary.py")
NAME = re.compile(r"[A-Za-z0-9_.:@\\-]{1,220}\.(service|timer|socket|path|target|scope|slice|mount|automount|device|swap)\Z")
COMMON = {"Id", "Names", "LoadState", "ActiveState"}
LOAD_STATES = {"loaded", "not-found", "stub", "merged", "masked", "error", "bad-setting"}
ACTIVE_STATES = {"active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing"}
FILE_STATES = {"enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "masked", "masked-runtime",
               "static", "disabled", "indirect", "generated", "transient", "bad"}
CAPABILITIES = {"future_launch_denied", "all_five_posts_denied", "all_namespaces", "inode_aliases",
                "directory_fds", "deleted_open", "mmap_writers", "root_manual_transient", "durable_undo"}


def rows(raw, *, files):
    C.need(type(raw) is bytes and len(raw) <= 2 * 1024**2, "G4_UNIT_BOUND_STOP")
    output = {}
    for line in raw.decode("utf8", "strict").splitlines():
        cols = line.lstrip("● ").split()
        if not cols: continue
        C.need(len(cols) >= (2 if files else 4) and NAME.fullmatch(cols[0]) and cols[0] not in output,
               "G4_UNIT_SCHEMA_STOP")
        C.need(cols[1] in (FILE_STATES if files else LOAD_STATES) and
               (files or cols[2] in ACTIVE_STATES), "G4_UNIT_SCHEMA_STOP")
        C.need(len(output) < 8192, "G4_UNIT_BOUND_STOP")
        output[cols[0]] = cols[1:]  # private, bounded; never printed
    return output


class MetadataReader(B.LinuxMetadataReader):
    def unit_files(self):
        return list(rows(self._run(["--no-legend", "--full", "list-unit-files", "--all"]), files=True))

    def loaded(self):
        return list(rows(self._run(["--no-legend", "--plain", "--full", "list-units", "--all"]), files=False))

    def observed(self, name):
        C.need(NAME.fullmatch(name), "G4_UNIT_SCHEMA_STOP")
        if name.endswith("@.service"):
            raw = self._run(["cat", "--", name])
            C.need(0 < len(raw) <= 131072, "G4_TEMPLATE_STOP")
            return {"disk_digest": C.raw_hash(raw), "scope": "DISK_ONLY_NOT_LIVE_EQUIVALENCE"}
        raw = self._run(["--all", "show", "--property=" + ",".join(B.PROPERTIES), "--", name])
        result = {}
        for line in raw.decode("utf8", "strict").splitlines():
            key, value = line.split("=", 1)
            C.need(key in B.PROPERTIES and key not in result and len(value) <= 65536, "G4_PROPERTY_STOP")
            result[key] = value
        C.need(COMMON <= set(result) and (result["Id"] == name or name in result["Names"].split()), "G4_IDENTITY_STOP")
        C.need(result["LoadState"] in LOAD_STATES and result["ActiveState"] in ACTIVE_STATES, "G4_PROPERTY_STOP")
        for key in ("Names", "Wants", "Requires", "PartOf", "BindsTo", "Triggers", "TriggeredBy"):
            C.need(all(NAME.fullmatch(n) for n in result.get(key, "").split()), "G4_PROPERTY_STOP")
        return {"properties": result, "unsupported_properties": sorted(set(B.PROPERTIES) - set(result)),
                "scope": "MANAGER_OBSERVED_NOT_GLOBAL_CLOSURE"}


def plan_source(reader, *, now, clock=time.monotonic):
    """All observed identities, including non-prefixed wrappers. No missing show.

    Runtime budget is bounded by command limits/count; incomplete/unsupported
    surfaces stay unknown. Templates are disk evidence only, not live proof.
    """
    deadline = clock() + 35
    identity = reader.identity()
    C.shape(identity, "host_digest source_head uid roots_digest")
    C.need(identity["source_head"] == C.G.SOURCE_HEAD and type(identity["uid"]) is int and identity["uid"] == 0 and
           identity["roots_digest"] == C.G.sha(C.ROOTS), "G4_SCOPE_STOP")
    C.digest(identity["host_digest"])
    files, loaded = set(reader.unit_files()), set(reader.loaded())
    names = sorted(files | loaded)
    C.need(len(names) <= 1024, "G4_UNIT_BOUND_STOP")
    def snapshot():
        result = {}
        for name in names:
            C.need(clock() <= deadline, "G4_TIME_BUDGET_STOP")
            result[name] = reader.observed(name)
        return result
    first = snapshot()
    C.need(files == set(reader.unit_files()) and loaded == set(reader.loaded()) and
           first == snapshot() and identity == reader.identity(), "G4_CENSUS_RACE")
    missing = sorted(C.U.EXPECTED - files)
    relevant = {n for n, value in first.items() if n in C.U.EXPECTED or n.startswith(("technocore-", "flop-")) or
                any(root in C.G.canonical(value).decode() for root in C.ROOTS)}
    private = {"identity": identity, "observed_at": now, "unit_files": sorted(files), "loaded": sorted(loaded),
               "units": first, "missing_expected": missing, "extras": sorted(relevant - C.U.EXPECTED),
               "surfaces": reader.surfaces()}
    C.need(len(C.G.canonical(private)) <= C.MAX_BYTES, "G4_UNIT_BOUND_STOP")
    return private


def review_source(private, packet, enrollment, *, now):
    C.fresh(private["observed_at"], now)
    data = enrollment.verify(packet, "r1117-G1", "independent", now)
    C.shape(data, "census_digest coverage")
    C.need(data["census_digest"] == C.G.sha(private) and private["identity"]["host_digest"] == enrollment.context["host"], "G4_CENSUS_BINDING_STOP")
    coverage = data["coverage"]
    C.need(C.U.assess(coverage, now=now)["counts"] is not None, "G4_COVERAGE_STOP")
    for name, row in coverage["units"]["expected"].items():
        absent = name in private["missing_expected"]
        expected = {"absent_from_unit_files_and_loaded": name} if absent else private["units"].get(name)
        C.need(not absent or name not in private["loaded"], "G4_MISSING_UNRESOLVED")
        C.need(row["status"] == ("audited_absent" if absent else "audited_present") and
               row["config_digest"] == C.G.sha(expected), "G4_IDENTITY_STOP")
    extras = {C.raw_hash(n.encode()): C.G.sha(private["units"][n]) for n in private["extras"]}
    C.need({r["name_digest"]: r["config_digest"] for r in coverage["units"]["extras"]} == extras, "G4_EXTRA_IDENTITY_STOP")
    # No self-promotion of disk-only/template or unknown future activation.
    C.need(all(v.get("scope") != "DISK_ONLY_NOT_LIVE_EQUIVALENCE" for v in private["units"].values()) and
           all(x["complete"] is True and x["unknown"] == 0 for x in private["surfaces"].values()), "G4_NOT_PROVABLE")
    return C.G.sha(private)


class UndoJournal:
    """Private POSIX append-once sequence + fsync, before any driver mutation.

    Does not edit source/TradeBot paths. Windows uses its native custody path,
    not chmod-as-ACL. Orphan sequence files fail closed; never erase recovery.
    """
    def __init__(self, root):
        self.root = C.R.T.private_dir(Path(root))
        C.need(os.name == "posix" and not any(self.root == Path(p) or Path(p) in self.root.parents
               for p in C.R.T.BLOCKED_ROOTS), "G4_UNDO_CUSTODY_STOP")
        self.previous, self.sequence, self.latest = "0" * 64, 0, None
        names = sorted(self.root.iterdir())
        C.need(len(names) <= 4096, "G4_UNDO_BOUND_STOP")
        for i, path in enumerate(names, 1):
            C.need(path.name == f"{i:06d}.json", "G4_UNDO_SEQUENCE_STOP")
            s = path.lstat()
            C.need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600 and
                   s.st_uid == os.geteuid() and s.st_size <= 1024**2, "G4_UNDO_CUSTODY_STOP")
            record = C.decode(path.read_bytes())
            C.shape(record, "sequence previous value")
            C.need(record["sequence"] == i and record["previous"] == self.previous, "G4_UNDO_SEQUENCE_STOP")
            self.previous, self.sequence, self.latest = C.G.sha(record), i, record["value"]

    def save(self, value):
        C.need(self.sequence < 4096, "G4_UNDO_BOUND_STOP")
        raw = C.G.canonical({"sequence": self.sequence + 1, "previous": self.previous, "value": value})
        C.need(len(raw) <= 1024**2, "G4_UNDO_BOUND_STOP")
        path = self.root / f"{self.sequence + 1:06d}.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)  # Only this newly created private record.
            with os.fdopen(fd, "wb") as out:
                out.write(raw); out.flush(); os.fsync(out.fileno())
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory)
            finally: os.close(directory)
        except Exception:
            raise C.Stop("G4_UNDO_DURABILITY_STOP") from None
        self.sequence += 1; self.previous = C.raw_hash(raw); self.latest = C.decode(raw)["value"]


class JournalBackend:
    """No Linux enforcement implementation bundled. Typed capability DI only."""
    def __init__(self, driver, journal, enrollment, admission, *, now, clock=time.time):
        self.driver, self.journal = driver, journal
        data = enrollment.verify(admission, "r1117-backend", "independent", now)
        C.shape(data, "backend_digest capabilities boot_digest original_context")
        C.need(data["original_context"] == enrollment.context and data["backend_digest"] == driver.identity() and
               set(data["capabilities"]) == CAPABILITIES and len(data["capabilities"]) == len(CAPABILITIES) and
               data["boot_digest"] == driver.boot_digest(), "G4_NOT_PROVABLE")
        self.admission, self.enrollment, self.clock = admission, enrollment, clock
        self.operation = None

    def identity(self): return self.driver.identity()
    def enforceable(self): return self.driver.enforceable() is True

    def inspect(self, plan):
        C.need(self.driver.boot_digest() == self.admission["body"]["data"]["boot_digest"], "G4_REBOOT_REVIEW_REQUIRED")
        result = self.driver.inspect(plan)
        C.need(set(result) == CAPABILITIES and all(x is True for x in result.values()), "G4_NOT_PROVABLE")

    def authorize(self, plan, owner, permit, *, now):
        self.enrollment.verify(self.admission, "r1117-backend", "independent", now)
        expected = B.Controller(self.enrollment, None).propose(plan["census_digest"], plan["epoch"], self.identity())
        C.need(type(plan.get("uid")) is int and plan == expected, "G4_SCOPE_STOP")
        C.need(self.driver.boot_digest() == self.admission["body"]["data"]["boot_digest"], "G4_REBOOT_REVIEW_REQUIRED")
        C.need(self.enforceable(), "G4_NOT_PROVABLE")
        for packet, role in ((owner, "owner"), (permit, "independent")):
            C.need(self.enrollment.verify(packet, "apply", role, now) ==
                   {"plan_digest": C.G.sha(plan)}, "G4_EXACT_APPROVAL_REQUIRED")
        self.operation = C.decode(C.G.canonical({"plan_digest": C.G.sha(plan), "owner": owner, "permit": permit}))

    def apply(self, plan):
        C.need(self.operation is not None and self.operation["plan_digest"] == C.G.sha(plan), "G4_EXACT_APPROVAL_REQUIRED")
        self.authorize(plan, self.operation["owner"], self.operation["permit"], now=int(self.clock()))
        self.inspect(plan)
        C.need(self.journal.latest is None, "G4_REPLAY_STOP")
        prior = self.driver.snapshot_undo(plan)
        C.need(type(prior) is dict, "G4_UNDO_REQUIRED")
        value = {"plan": plan, "undo": prior, "phase": "PREPARED", "boot_digest": self.driver.boot_digest(),
                 "approval_digest": C.G.sha(self.operation)}
        self.journal.save(value)  # MUST succeed before first side effect
        try:
            self.driver.deny_launch_and_posts(plan)
            self.inspect(plan)
            self.journal.save({**value, "phase": "DENIED"})
            self.driver.quiesce_exact(plan)
            self.inspect(plan)
            self.journal.save({**value, "phase": "HELD"})
            return prior
        except Exception:
            self.journal.save({**value, "phase": "FAULT_CLOSED"})
            raise C.Stop("G4_APPLY_INCOMPLETE") from None

    def recover_undo(self, digest):
        C.need(self.journal.latest is not None and C.G.sha(self.journal.latest["undo"]) == digest, "G4_UNDO_REQUIRED")
        return self.journal.latest["undo"]

    def restore_exact(self, undo):
        C.need(self.journal.latest is not None and self.journal.latest["undo"] == undo, "G4_UNDO_REQUIRED")
        try:
            self.driver.restore_exact(undo)
            C.need(self.driver.verify_restored(undo) is True, "G4_UNDO_FAILED")
            self.journal.save({**self.journal.latest, "phase": "RESTORED"})
        except Exception:
            self.journal.save({**self.journal.latest, "phase": "RESTORE_FAILED_REVIEW_REQUIRED"})
            raise C.Stop("G4_UNDO_FAILED") from None

    def recover_interrupted(self, owner, independent, *, now):
        C.need(self.journal.latest is not None, "G4_UNDO_REQUIRED")
        value = self.journal.latest
        binding = {"journal_digest": self.journal.previous, "plan_digest": C.G.sha(value["plan"]),
                   "undo_digest": C.G.sha(value["undo"]), "destination_writers_fenced": True,
                   "five_post_finality_verified": True, "current_boot_digest": self.driver.boot_digest()}
        for packet, role in ((owner, "owner"), (independent, "independent")):
            C.need(self.enrollment.verify(packet, "r1117-recovery", role, now) == binding, "G4_RECOVERY_APPROVAL_STOP")
        self.restore_exact(value["undo"])  # never re-apply, re-POST or auto-unfence


class Controller(B.Controller):
    """Retain old lease/rollback semantics; make backend apply unbypassable."""
    def apply(self, plan, owner, permit, *, now):
        self.backend.authorize(plan, owner, permit, now=now)
        super().apply(plan, owner, permit, now=now)
