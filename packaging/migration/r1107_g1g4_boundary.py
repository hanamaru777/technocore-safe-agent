"""Private G1 collection and independent reversible G4 controller contract.

The Linux metadata reader is READ ONLY. It cannot implement root-wide future
denial and therefore has NO apply/stop/mount/rollback primitive. Trial adapters
can exercise the complete controller lifecycle without production operations.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

spec = importlib.util.spec_from_file_location("flop_r1107_contract", Path(__file__).with_name("r1107_contract.py"))
C = sys.modules.get(spec.name)
if C is None:
    C = importlib.util.module_from_spec(spec); sys.modules[spec.name] = C; spec.loader.exec_module(C)
NAME = re.compile(r"[A-Za-z0-9_.:@\\-]{1,220}\.(?:service|timer|socket|path|target|scope|slice|mount|automount)\Z")
PROPERTIES = ("Id", "Names", "LoadState", "ActiveState", "UnitFileState", "FragmentPath", "DropInPaths",
              "ExecStart", "ExecStartPre", "ExecStartPost", "Restart", "Wants", "Requires", "PartOf", "BindsTo",
              "Triggers", "TriggeredBy", "Transient", "ControlGroup", "SourcePath")
SURFACES = frozenset({"system_units", "user_units", "generators", "cron", "interpreters",
                      "boot", "manual", "transient", "namespaces", "inode_aliases", "cgroups"})


def unit_name(value):
    C.need(type(value) is str and NAME.fullmatch(value), "UNIT_IDENTITY_STOP")
    return value


def bounded_names(values):
    C.need(type(values) is list and len(values) <= 16384, "UNIT_BOUND_STOP")
    for n in values: unit_name(n)
    C.need(len(set(values)) == len(values), "DUPLICATE_UNIT_STOP")
    return set(values)


def kernel_observation(roots, proc=Path("/proc")):
    """Metadata only; inode matching survives path aliases/deleted-open names.

    Even a clean observation is NOT future denial: unlinked-before-census
    aliases, memory/namespace races and new root/manual actions require an
    independent enforcement boundary. Never read cmdline, environ or DB bytes.
    """
    index, paths, links = {}, {}, {}
    def walk(path, depth):
        C.need(depth <= 64 and len(paths) < 100000, "KERNEL_BOUND_STOP")
        s = path.lstat(); paths[str(path)] = (s.st_dev, s.st_ino)
        if stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode):
            key = s.st_dev, s.st_ino
            index[key] = {"directory": stat.S_ISDIR(s.st_mode), "links": s.st_nlink}
            links[key] = links.get(key, 0) + 1
        if stat.S_ISDIR(s.st_mode):
            for child in path.iterdir(): walk(child, depth + 1)
    for root in roots: walk(root, 0)
    def read(path, limit):
        with path.open("rb") as f: value = f.read(limit + 1)
        C.need(len(value) <= limit, "KERNEL_BOUND_STOP")
        return value
    pids = sorted((p for p in proc.iterdir() if p.name.isdigit()), key=lambda p: int(p.name))
    C.need(len(pids) <= 4096, "KERNEL_BOUND_STOP")
    result = {"source_objects": len(paths), "writable_fds": 0, "directory_fds": 0,
              "writable_mappings": 0, "unknown_or_raced": 0, "namespace_count": 0,
              "external_hardlinks": sum(not v["directory"] and v["links"] > links[k] for k, v in index.items()),
              "source_inode_digest": C.G.sha(sorted([list(k) for k in index])),
              "mount_views": [], "future_denial": "NOT_PROVEN", "unlinked_before_census": "NOT_PROVEN"}
    namespaces = set(); fd_count = 0
    devices = {x[0] for x in index}
    for pid in pids:
        try:
            ns = (pid / "ns/mnt").stat(); token = ns.st_dev, ns.st_ino
            if token not in namespaces:
                namespaces.add(token)
                mounts = read(pid / "mountinfo", 1024**2).decode("utf8", "strict").splitlines()
                aliases = []
                for line in mounts:
                    fields = line.split()
                    C.need(len(fields) >= 10 and "-" in fields and fields[0].isdigit(), "MOUNT_SCHEMA_STOP")
                    major, minor = fields[2].split(":")
                    if os.makedev(int(major), int(minor)) in devices:
                        aliases.append({"root_digest": C.raw_hash(fields[3].encode()),
                                        "mount_digest": C.raw_hash(fields[4].encode()),
                                        "read_only": "ro" in fields[5].split(",")})
                result["mount_views"].append({"namespace_digest": C.G.sha(token), "source_device_mounts": aliases})
            for fd in (pid / "fd").iterdir():
                fd_count += 1; C.need(fd_count <= 65536, "KERNEL_BOUND_STOP")
                s = fd.stat(); target = os.readlink(fd)
                C.need(len(os.fsencode(target)) <= 4096, "KERNEL_BOUND_STOP")
                known = (s.st_dev, s.st_ino) in index
                named = any(target == str(r) or target.startswith(str(r) + "/") for r in roots)
                if known or named:
                    flags = re.findall(rb"^flags:\s+([0-7]+)$", read(pid / "fdinfo" / fd.name, 4096), re.M)
                    C.need(len(flags) == 1, "FD_SCHEMA_STOP")
                    if int(flags[0], 8) & os.O_ACCMODE != os.O_RDONLY: result["writable_fds"] += 1
                    if stat.S_ISDIR(s.st_mode): result["directory_fds"] += 1
                    if not known or target.endswith(" (deleted)"): result["unknown_or_raced"] += 1
            for line in read(pid / "maps", 1024**2).decode("utf8", "strict").splitlines():
                fields = line.split(None, 5)
                C.need(len(fields) >= 5, "MAP_SCHEMA_STOP")
                major, minor = fields[3].split(":")
                key = os.makedev(int(major, 16), int(minor, 16)), int(fields[4])
                if key in index and "w" in fields[1]: result["writable_mappings"] += 1
                elif len(fields) == 6 and any(fields[5].startswith(str(r) + "/") for r in roots):
                    result["unknown_or_raced"] += 1
        except (OSError, ValueError, UnicodeError):
            result["unknown_or_raced"] += 1
    result["namespace_count"] = len(namespaces)
    return result


class LinuxMetadataReader:
    """Fixed systemctl READ commands only, no secret/env/cron body output.

    Explicit future authorized caller must collect all remaining surfaces with
    independent privilege. This reader never guesses that no match means safe.
    No CLI automatically runs it. Tests inject a fake command runner.
    """
    def __init__(self, runner=None):
        self.runner = runner or subprocess.run

    def _run(self, args):
        # Fixed arguments from methods below; not a generic caller command API.
        try:
            p = self.runner(["/usr/bin/systemctl", "--no-pager", *args],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=10, env={"PATH": "/usr/bin:/bin", "LANG": "C"}, shell=False)
            C.need(p.returncode == 0 and len(p.stdout) <= 2 * 1024**2, "SYSTEMD_READ_STOP")
            return p.stdout
        except (OSError, subprocess.SubprocessError):
            raise C.Stop("SYSTEMD_READ_STOP") from None

    def unit_files(self):
        raw = C.decode(self._run(["list-unit-files", "--all", "--output=json"]))
        C.need(type(raw) is list and len(raw) <= 16384)
        return [unit_name(x["unit_file"]) for x in raw]

    def identity(self):
        C.need(sys.platform == "linux" and os.geteuid() == 0, "ORIGINAL_SCOPE_STOP")
        p = self.runner(["/usr/bin/git", "-c", "safe.directory=" + C.ROOTS[0], "-C", C.ROOTS[0],
                         "rev-parse", "--verify", "HEAD"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, timeout=5, shell=False,
                        env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0"})
        C.need(p.returncode == 0 and p.stdout == (C.G.SOURCE_HEAD + "\n").encode(), "ORIGINAL_HEAD_STOP")
        with Path("/etc/machine-id").open("rb") as f: raw = f.read(129)
        C.need(1 <= len(raw) <= 128, "ORIGINAL_SCOPE_STOP")
        return {"host_digest": C.raw_hash(raw.strip()), "source_head": C.G.SOURCE_HEAD,
                "uid": 0, "roots_digest": C.G.sha(C.ROOTS)}

    def loaded(self):
        raw = C.decode(self._run(["list-units", "--all", "--output=json"]))
        C.need(type(raw) is list and len(raw) <= 16384)
        return [unit_name(x["unit"]) for x in raw]

    def properties(self, name):
        unit_name(name)
        raw = self._run(["show", "--property=" + ",".join(PROPERTIES), "--", name])
        values = {}
        try:
            for line in raw.decode("utf8", "strict").splitlines():
                key, value = line.split("=", 1)
                C.need(key in PROPERTIES and key not in values and len(value) <= 65536,
                       "UNIT_PROPERTY_STOP")
                values[key] = value
        except (ValueError, UnicodeError):
            raise C.Stop("UNIT_PROPERTY_STOP") from None
        C.need(set(values) == set(PROPERTIES), "UNIT_PROPERTY_STOP")
        return values

    def properties_many(self, names):
        output = {}
        for at in range(0, len(names), 128):
            group = names[at:at+128]
            for name in group: unit_name(name)
            raw = self._run(["show", "--property=" + ",".join(PROPERTIES), "--", *group])
            for block in raw.decode("utf8", "strict").strip().split("\n\n"):
                p = {}
                for line in block.splitlines():
                    key, value = line.split("=", 1)
                    C.need(key in PROPERTIES and key not in p and len(value) <= 65536, "UNIT_PROPERTY_STOP")
                    p[key] = value
                C.shape(p, " ".join(PROPERTIES))
                matches = set(p["Names"].split() + [p["Id"]]) & set(group)
                C.need(matches and not matches.intersection(output), "DUPLICATE_UNIT_STOP")
                for name in matches: output[name] = dict(p)
        C.need(set(output) == set(names), "UNIT_PROPERTY_STOP")
        return output

    def surfaces(self):
        # systemctl alone cannot prove user managers, wrapper scripts, cron,
        # root/manual/transient launch rights, aliases or every mount namespace.
        try:
            self.kernel_private = kernel_observation(tuple(Path(p) for p in C.ROOTS))
        except (OSError, ValueError):
            self.kernel_private = {"unknown_or_raced": 1, "future_denial": "NOT_PROVEN"}
        return {k: {"complete": False, "unknown": max(1, self.kernel_private["unknown_or_raced"]),
                    "digest": C.G.sha({"surface": k, "kernel": self.kernel_private})} for k in SURFACES}

    def enforceable(self):
        return False


def collect(reader, *, now):
    """Private identity/effective-config census, not count-only keyword matching.

    Names and metadata remain in caller's private memory. Only report() is safe
    for logs. No claim of root-wide completeness from systemctl properties.
    """
    identity = reader.identity()
    C.shape(identity, "host_digest source_head uid roots_digest")
    C.need(identity["source_head"] == C.G.SOURCE_HEAD and type(identity["uid"]) is int and identity["uid"] == 0 and
           identity["roots_digest"] == C.G.sha(C.ROOTS), "ORIGINAL_SCOPE_STOP")
    C.digest(identity["host_digest"])
    files, loaded = bounded_names(reader.unit_files()), bounded_names(reader.loaded())
    universe = files | loaded | set(C.U.EXPECTED)
    C.need(len(universe) <= 16384, "UNIT_BOUND_STOP")
    units = {}
    ordered = sorted(universe)
    values = reader.properties_many(ordered) if hasattr(reader, "properties_many") else {n: reader.properties(n) for n in ordered}
    for name in ordered:
        props = values[name]
        C.shape(props, " ".join(PROPERTIES))
        C.need(all(type(v) is str and len(v) <= 65536 for v in props.values()), "UNIT_PROPERTY_STOP")
        aliases = props["Names"].split()
        for a in aliases: unit_name(a)
        for key in ("Wants", "Requires", "PartOf", "BindsTo", "Triggers", "TriggeredBy"):
            for target in props[key].split(): unit_name(target)
        C.need(props["LoadState"] in ("loaded", "not-found", "masked", "error", "bad-setting", "merged", "stub"), "UNIT_PROPERTY_STOP")
        C.need(name in aliases or props["LoadState"] == "not-found", "UNIT_ALIAS_STOP")
        units[name] = props
    C.need(files == bounded_names(reader.unit_files()) and loaded == bounded_names(reader.loaded()), "CENSUS_RACE_STOP")
    # Re-read every effective property; same top-level lists alone miss drop-in
    # or ExecStart replacement during collection.
    again = reader.properties_many(ordered) if hasattr(reader, "properties_many") else {n: reader.properties(n) for n in ordered}
    C.need(again == units, "CENSUS_RACE_STOP")
    surfaces = reader.surfaces()
    C.shape(surfaces, " ".join(SURFACES))
    for row in surfaces.values():
        C.shape(row, "complete unknown digest")
        C.need(type(row["complete"]) is bool)
        C.integer(row["unknown"]); C.digest(row["digest"])
    C.need(reader.identity() == identity, "ORIGINAL_IDENTITY_RACE")
    private = {"observed_at": C.integer(now, 1), "identity": identity, "files": sorted(files), "loaded": sorted(loaded),
               "units": units, "surfaces": surfaces, "kernel_private": getattr(reader, "kernel_private", None)}
    C.need(len(C.G.canonical(private)) <= C.MAX_BYTES, "CENSUS_BOUND_STOP")
    return private


def bind_review(private, signed_review, enrollment, *, now):
    """Reuse R1104 coverage semantics, bind independent review to actual census."""
    C.fresh(private["observed_at"], now)
    C.need(private["identity"]["host_digest"] == enrollment.context["host"], "ORIGINAL_SCOPE_STOP")
    data = enrollment.verify(signed_review, "G1", "independent", now)
    C.shape(data, "census_digest coverage scope_uid roots_digest")
    C.need(data["scope_uid"] == 0 and type(data["scope_uid"]) is int and
           data["roots_digest"] == C.G.sha(C.ROOTS) and data["census_digest"] == C.G.sha(private), "CENSUS_BINDING_STOP")
    coverage = data["coverage"]
    result = C.U.assess(coverage, now=now)
    C.need(result["counts"] is not None, "G1_COVERAGE_STOP")
    expected = coverage["units"]["expected"]
    for name in C.U.EXPECTED:
        p = private["units"][name]
        present = p["LoadState"] == "loaded" and bool(p["FragmentPath"])
        absent = p["LoadState"] == "not-found" and not p["FragmentPath"] and name not in private["files"]
        C.need((present and expected[name]["status"] == "audited_present") or
               (absent and expected[name]["status"] == "audited_absent"), "EXPECTED_IDENTITY_STOP")
        C.need(expected[name]["config_digest"] == C.G.sha(p), "EFFECTIVE_CONFIG_STOP")
    actual_extras = {n for n, p in private["units"].items() if n not in C.U.EXPECTED and
                     (n.startswith(("technocore-", "flop-")) or any(root in C.G.canonical(p).decode("ascii") for root in C.ROOTS))}
    reviewed = {r["name_digest"]: r for r in coverage["units"]["extras"]}
    C.need({C.raw_hash(n.encode()) for n in actual_extras} == set(reviewed), "EXTRA_IDENTITY_STOP")
    for n in actual_extras:
        C.need(reviewed[C.raw_hash(n.encode())]["config_digest"] == C.G.sha(private["units"][n]), "EFFECTIVE_CONFIG_STOP")
    C.need(all(r["complete"] and r["unknown"] == 0 for r in private["surfaces"].values()), "LAUNCH_CLOSURE_UNPROVEN")
    for category, row in coverage["launchers"].items():
        C.need(row["census_digest"] == C.G.sha({"category": category, "surfaces": private["surfaces"]}),
               "LAUNCH_CLOSURE_BINDING_STOP")
    C.need(coverage["host_digest"] == enrollment.context["host"] and
           coverage["source_head"] == C.G.SOURCE_HEAD, "BINDING_STOP")
    return C.G.sha(private)


class Controller:
    """Explicit-capability lifecycle; no generic shell or production backend.

    A reviewed real all-namespace/inode/POST denial backend is NOT bundled.
    A source process cannot issue or renew its own independent lease. Losing a
    lease faults CLOSED; it never silently restarts writers or rolls back.
    """
    def __init__(self, enrollment, backend):
        self.enrollment, self.backend = enrollment, backend
        self.state = "NEW"
        self.plan = self.packet = self.undo = None

    def propose(self, census_digest, epoch, backend_digest):
        for v in (census_digest, epoch, backend_digest): C.digest(v)
        return {"context": self.enrollment.context, "roots_digest": C.G.sha(C.ROOTS), "uid": 0,
                "census_digest": census_digest, "epoch": epoch, "backend_digest": backend_digest,
                "capabilities": ["prevent_launch", "prevent_post", "quiesce", "inspect_global", "restore_exact"]}

    def preflight(self, plan, owner, *, now):
        C.shape(plan, "context roots_digest uid census_digest epoch backend_digest capabilities")
        C.need(type(plan["uid"]) is int and plan["uid"] == 0, "PLAN_BINDING_STOP")
        C.need(plan == self.propose(plan["census_digest"], plan["epoch"], plan["backend_digest"]), "PLAN_BINDING_STOP")
        data = self.enrollment.verify(owner, "apply", "owner", now)
        C.need(data == {"plan_digest": C.G.sha(plan)}, "OWNER_BINDING_STOP")
        C.need(self.backend.enforceable() is True and self.backend.identity() == plan["backend_digest"], "G4_NOT_PROVABLE")
        self.backend.inspect(plan)  # must reject FDs/aliases/launch uncertainty

    def _lease(self, packet, plan, now, previous=None):
        data = self.enrollment.verify(packet, "G4", "independent", now)
        C.shape(data, "plan_digest epoch census_digest backend_digest sequence previous ledger_digest global_deny")
        C.need(data["plan_digest"] == C.G.sha(plan) and data["epoch"] == plan["epoch"] and
               data["census_digest"] == plan["census_digest"] and data["backend_digest"] == plan["backend_digest"] and
               data["global_deny"] is True, "LEASE_BINDING_STOP")
        C.digest(data["ledger_digest"])
        old = previous["body"]["data"] if previous else None
        C.need(type(data["sequence"]) is int and data["sequence"] == (old["sequence"] + 1 if old else 1) and
               data["previous"] == (C.G.sha(previous) if old else "0" * 64), "LEASE_REPLAY_STOP")
        if previous:
            C.need(packet["signer"] == previous["signer"] and data["ledger_digest"] == old["ledger_digest"] and
                   packet["body"]["observed_at"] >= previous["body"]["observed_at"], "LEASE_REPLACED_STOP")
        return data

    def apply(self, plan, owner, permit, *, now):
        C.need(self.state == "NEW", "STATE_STOP")
        self.preflight(plan, owner, now=now)
        C.need(self.enrollment.verify(permit, "apply", "independent", now) ==
               {"plan_digest": C.G.sha(plan)}, "APPLY_PERMISSION_STOP")
        self.state = "APPLYING"
        self.plan = plan
        try:
            # Backend must atomically deny future launch/POST BEFORE quiescing.
            # It owns private durable undo custody and independently observable
            # admission generation. No stop-only implementation is accepted.
            self.undo = self.backend.apply(plan)
            self.backend.inspect(plan)
            # Actual G4 is acquired AFTER enforcement, never a pre-signed
            # promise that a future stop/mount will succeed.
            self.state = "AWAITING_LEASE"
        except Exception:
            self.state = "FAULT_CLOSED"
            raise C.Stop("G4_APPLY_INCOMPLETE") from None

    def guard(self, *, now):
        C.need(self.state == "HELD", "G4_NOT_HELD")
        try:
            data = self.enrollment.verify(self.packet, "G4", "independent", now)
            C.need(data["plan_digest"] == C.G.sha(self.plan) and data["epoch"] == self.plan["epoch"] and
                   data["census_digest"] == self.plan["census_digest"] and
                   data["backend_digest"] == self.backend.identity() == self.plan["backend_digest"] and
                   data["global_deny"] is True, "LEASE_BINDING_STOP")
            self.backend.inspect(self.plan)
        except Exception:
            self.state = "FAULT_CLOSED"
            raise C.Stop("G4_LOST") from None
        return self.packet["body"]["data"]

    def renew(self, lease, *, now):
        C.need(self.state in ("AWAITING_LEASE", "HELD"), "STATE_STOP")
        try:
            if self.state == "HELD": self.guard(now=now)
            self._lease(lease, self.plan, now, self.packet)
            self.backend.inspect(self.plan)
            self.packet = lease
            self.state = "HELD"
        except Exception:
            self.state = "FAULT_CLOSED"
            raise C.Stop("G4_RENEWAL_STOP") from None

    def rollback(self, owner, independent, *, now):
        C.need(self.state in ("AWAITING_LEASE", "HELD", "FAULT_CLOSED") and self.undo is not None, "STATE_STOP")
        binding = {"plan_digest": C.G.sha(self.plan), "undo_digest": C.G.sha(self.undo),
                   "destination_writers_fenced": True, "post_finality_reconciled": True}
        C.need(self.enrollment.verify(owner, "rollback", "owner", now) == binding and
               self.enrollment.verify(independent, "rollback", "independent", now) == binding, "ROLLBACK_AUTHORITY_STOP")
        try:
            self.backend.restore_exact(self.undo)
        except Exception:
            self.state = "FAULT_CLOSED"
            raise C.Stop("ROLLBACK_INCOMPLETE") from None
        self.state = "ROLLED_BACK"

    def checkpoint(self):
        C.need(self.state in ("HELD", "FAULT_CLOSED"), "STATE_STOP")
        return {"plan": self.plan, "lease": self.packet, "undo_digest": C.G.sha(self.undo), "state": self.state}

    def resume(self, saved, independent, *, now):
        C.need(self.state == "NEW", "STATE_STOP")
        C.shape(saved, "plan lease undo_digest state")
        C.need(saved["state"] == "HELD", "RECOVERY_REVIEW_REQUIRED")
        data = self.enrollment.verify(independent, "resume", "independent", now)
        C.need(data == {"checkpoint_digest": C.G.sha(saved)}, "RECOVERY_BINDING_STOP")
        self.enrollment.verify(saved["lease"], "G4", "independent", now)
        p, d = saved["plan"], saved["lease"]["body"]["data"]
        C.need(type(p["uid"]) is int and p["uid"] == 0 and p == self.propose(p["census_digest"], p["epoch"], p["backend_digest"]) and
               d["plan_digest"] == C.G.sha(p) and d["epoch"] == p["epoch"] and
               d["backend_digest"] == p["backend_digest"] and d["census_digest"] == p["census_digest"] and
               d["global_deny"] is True, "RECOVERY_BINDING_STOP")
        C.need(self.backend.enforceable() and self.backend.identity() == saved["plan"]["backend_digest"], "G4_NOT_PROVABLE")
        self.backend.inspect(saved["plan"])
        undo = self.backend.recover_undo(saved["undo_digest"])
        C.need(C.G.sha(undo) == saved["undo_digest"], "RECOVERY_BINDING_STOP")
        self.plan, self.packet, self.undo = saved["plan"], saved["lease"], undo
        self.state = "HELD"


def report(private=None):
    return {**C.decisions("G4_NOT_PROVABLE"), "G1": "IDENTITIES_REQUIRE_PRIVATE_INDEPENDENT_REVIEW",
            "G4": "NO_GO", "known_templates": len(C.U.EXPECTED),
            "census_digest": C.G.sha(private) if private else None,
            "missing_capabilities": ["ROOT_WIDE_FUTURE_LAUNCH_AND_POST_DENIAL", "ALL_NAMESPACE_INODE_CLOSURE", "INDEPENDENT_LEASE_ISSUER"]}
