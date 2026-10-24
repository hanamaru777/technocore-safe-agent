#!/usr/bin/env python3
"""R1041 OCI signer ledger and fixed unknown-unit/cron read-only witness.

New distinct single-use diagnosis AFTER count-only inventory; compares only
in-memory keys of four bounded files. No names, IDs, nonces or DIDs printed.
No writes, external calls, service changes, or SQLite/rich-state reads.
"""
from collections import Counter
import hashlib
import hmac
import json
import os
import re
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import time

ROOT = Path("/var/lib/technocore-safe-agent")
APP = Path("/opt/technocore-safe-agent")
PINNED_LIVE_HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
INPUTS = (
    "signer/oracle-signer-receipts.json",
    "autopilot/autopilot-outbox.json",
    "nonces.json",
    "verified-did.json",
)
MAX_JSON = 1024 * 1024
MAX_SEC = 12

class Stop(Exception):
    pass

def require(ok, reason):
    if not ok:
        raise Stop(reason)

def read_small(relative):
    path = ROOT
    require(relative in INPUTS, "NOT_ALLOWLISTED_STOP")
    for component in relative.split("/")[:-1]:
        path /= component
        s = path.lstat()
        require(stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode),
                "INPUT_PARENT_INVALID_STOP")
    leaf = path / relative.split("/")[-1]
    mode = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
            getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOATIME", 0))
    fd = os.open(str(leaf), mode)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and
                1 <= s.st_size <= MAX_JSON and not s.st_mode & 0o002,
                "INPUT_SIZE_TYPE_PERM_STOP")
        data = os.read(fd, MAX_JSON + 1)
        require(len(data) <= MAX_JSON and len(data) == s.st_size,
                "INPUT_SIZE_DRIFT_STOP")
        return json.loads(data.decode("utf-8"))
    finally:
        os.close(fd)

def schema(value, keys, label):
    require(isinstance(value, dict) and all(k in value for k in keys),
            label + "_SCHEMA_STOP")

def report(receipts, outbox, nonces, did):
    schema(receipts, ("schema_version", "receipts"), "SIGNER_RECEIPTS")
    schema(outbox, ("schema_version", "enabled", "paused", "outbox", "receipts"), "AUTOPILOT")
    schema(did, ("did",), "DID")
    require(receipts["schema_version"] == 1 and
            outbox["schema_version"] == 1 and
            isinstance(receipts["receipts"], dict) and
            isinstance(outbox["outbox"], dict) and
            isinstance(outbox["receipts"], dict) and
            type(outbox["paused"]) is bool and type(outbox["enabled"]) is bool,
            "SIGNER_STATE_SCHEMA_STOP")
    require(isinstance(nonces, dict) and len(nonces) <= 10000,
            "NONCE_SCHEMA_STOP")
    didtext = did["did"]
    require(isinstance(didtext, str) and
            didtext.startswith("did:key:z") and 40 <= len(didtext) <= 200,
            "VERIFIED_DID_FORMAT_STOP")
    sign_state = Counter()
    for item in receipts["receipts"].values():
        require(isinstance(item, dict) and
                item.get("state") in ("prepared", "posted", "acknowledged") and
                item.get("did") == didtext,
                "RECEIPT_VALUE_STOP")
        sign_state[item["state"]] += 1
    queue_state = Counter()
    for item in outbox["outbox"].values():
        require(isinstance(item, dict), "OUTBOX_VALUE_STOP")
        state = item.get("status", "queued")
        require(state in ("queued", "posted", "acknowledged",
                          "ambiguous", "quarantined", "expired"),
                "OUTBOX_UNEXPECTED_STATUS_STOP")
        queue_state[state] += 1
    summary = {
        "signer_prepared": sign_state["prepared"],
        "signer_posted": sign_state["posted"],
        "signer_acknowledged": sign_state["acknowledged"],
        "outbox_queued": queue_state["queued"],
        "outbox_posted": queue_state["posted"],
        "outbox_acknowledged": queue_state["acknowledged"],
        "outbox_ambiguous": queue_state["ambiguous"],
        "outbox_quarantined": queue_state["quarantined"],
        "outbox_expired": queue_state["expired"],
        "outbox_receipts_total": len(outbox["receipts"]),
        "nonce_entries": len(nonces),
        "autopilot_enabled": outbox["enabled"],
        "autopilot_paused": outbox["paused"],
    }
    require(sum(sign_state.values()) <= 100000 and
            sum(queue_state.values()) <= 100000,
            "COUNTER_LIMIT_STOP")
    return summary

def valid_receipt_hash(value):
    """Require complete, canonical SHA-256 shape, not empty defaults."""
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def nonce_binding(receipts, outbox, nonces, did):
    """Fail closed unless every receipt nonce is bound to its outbox room.

    Nonce high-watermarks are local evidence only, not remote submission proof.
    The original source uses core.make_nonce(room, did) to save an integer
    under "<did>|<room>" before creating the signer prepared receipt.
    """
    signer = receipts["receipts"]
    entries = outbox["outbox"]
    if not signer:
        return False
    seen = set()
    for intent_id, receipt in signer.items():
        entry = entries.get(intent_id)
        if not isinstance(entry, dict):
            return False
        room = entry.get("room")
        nonce = receipt.get("nonce")
        if (not isinstance(room, str) or not 1 <= len(room) <= 128
                or "|" in room or not isinstance(nonce, str)
                or re.fullmatch(r"[1-9][0-9]{0,18}", nonce) is None):
            return False
        issued = int(nonce)
        latest = nonces.get(f"{did}|{room}")
        if (type(latest) is not int or not 1 <= issued <= latest
                or latest > 9999999999999999999
                or (room, nonce) in seen):
            return False
        seen.add((room, nonce))
    return True


def pairing(receipts, outbox, nonces, did):
    """Assess identity/state congruence; print no sensitive keys or data."""
    summary = report(receipts, outbox, nonces, did)
    signer = receipts["receipts"]
    entries = outbox["outbox"]
    acknowledged = outbox["receipts"]

    # Equal number of IDs is NOT enough. Match exact IDs and receipt hashes
    # in memory, without printing either.
    signer_acked = {key for key, value in signer.items()
                    if value.get("state") == "acknowledged"}
    outbox_acked = {key for key, value in entries.items()
                    if value.get("status") == "acknowledged"}
    ack_keys_match = signer_acked == outbox_acked == set(acknowledged)
    receipt_hash_match = ack_keys_match and all(
        isinstance(acknowledged.get(key), dict)
        and isinstance(entries.get(key), dict)
        and all(valid_receipt_hash(row.get("receipt_hash")) for row in (
            signer[key], acknowledged[key], entries[key]
        ))
        and hmac.compare_digest(signer[key]["receipt_hash"],
                                acknowledged[key]["receipt_hash"])
        and hmac.compare_digest(signer[key]["receipt_hash"],
                                entries[key]["receipt_hash"])
        for key in signer_acked
    )

    prepared = {key for key, value in signer.items()
                if value.get("state") == "prepared"}
    quarantined = {key for key, value in entries.items()
                   if value.get("status") == "quarantined"}
    # The deployed code creates exactly v1/v2 controlled E2E IDs by SHA256,
    # and quarantine_controlled_e2e() intentionally retains signer receipts
    # in prepared state. No test intent may be submitted or retried here.
    ids = {
        v: hashlib.sha256(("controlled-e2e-" + v).encode()).hexdigest()[:20]
        for v in ("v1", "v2")
    }
    recognized = set()
    for version, key in ids.items():
        rec, entry = signer.get(key), entries.get(key)
        if not isinstance(rec, dict) or not isinstance(entry, dict):
            continue
        error = rec.get("last_error_code")
        attempts = rec.get("attempts")
        expected_error = (
            error == "submission_unknown" if version == "v1"
            else error is None and attempts == 0
        )
        if (rec.get("state") == "prepared"
                and entry.get("status") == "quarantined"
                and entry.get("category") == "controlled_e2e"
                and entry.get("topic") == "prompt_injection_safety"
                and entry.get("source_candidate_id") == "controlled-e2e-" + version
                and entry.get("quarantine_reason") ==
                    ("submission_unknown" if version == "v1" else
                     "legacy_unhandled_http_ambiguity")
                and expected_error):
            recognized.add(key)
    return {
        "prepared_total": len(prepared),
        "quarantined_total": len(quarantined),
        "recognized_quarantined_e2e": len(recognized),
        "unreconciled_prepared": len(prepared - recognized),
        "unreconciled_quarantined": len(quarantined - recognized),
        "ack_ids_consistent": receipt_hash_match,
        "nonce_binding_consistent": nonce_binding(receipts, outbox, nonces, did["did"]),
        "active_or_ambiguous_outbox": (
            summary["outbox_queued"] + summary["outbox_posted"] +
            summary["outbox_ambiguous"]
        ),
        "autopilot_enabled": summary["autopilot_enabled"],
        "autopilot_paused": summary["autopilot_paused"],
    }


def signer_main():
    start = time.monotonic()
    require(not sys.argv[1:] and os.geteuid() == 0,
            "ROOT_NO_ARGS_REQUIRED_STOP")
    require(pwd.getpwnam("technocore").pw_uid != 0 and
            pwd.getpwnam("technocore-signer").pw_uid != 0,
            "FLOP_OCI_ACCOUNT_MISSING_STOP")
    for path in (APP, ROOT):
        s = path.lstat()
        require(stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode),
                "FLOP_OCI_ROOT_INVALID_STOP")
    require((APP / "src/flop_agent/oracle_signer.py").is_file(),
            "FLOP_OCI_SOURCE_MISSING_STOP")
    p = subprocess.run(
        ["git", "-C", str(APP), "-c", "safe.directory=" + str(APP),
         "rev-parse", "--verify", "HEAD"],
        capture_output=True, text=True, timeout=3,
        env={"PATH":"/usr/bin:/bin", "HOME":"/nonexistent",
             "GIT_CONFIG_NOSYSTEM":"1", "GIT_CONFIG_GLOBAL":"/dev/null",
             "GIT_TERMINAL_PROMPT":"0", "GIT_OPTIONAL_LOCKS":"0"}
    )
    require(p.returncode == 0 and p.stdout.strip() == PINNED_LIVE_HEAD,
            "LIVE_SOURCE_HEAD_DRIFT_STOP")
    results = []
    for unit in ("technocore-safe-agent-resident.service",
                 "technocore-safe-agent-signer.service"):
        p = subprocess.run(
            ["systemctl", "show", unit, "--no-pager",
             "-p", "ActiveState", "-p", "SubState", "-p", "NRestarts"],
            capture_output=True, text=True, timeout=2,
            env={"PATH":"/usr/bin:/bin", "LANG":"C"}
        )
        require(p.returncode == 0, "FLOP_UNIT_QUERY_STOP")
        values = dict(row.split("=", 1) for row in p.stdout.splitlines()
                      if "=" in row)
        require(values.get("ActiveState") == "active" and
                values.get("SubState") == "running" and
                values.get("NRestarts") == "0",
                "FLOP_OCI_LIVE_UNIT_DRIFT_STOP")
        results.append(unit)
    before = [read_small(name) for name in INPUTS]
    result = pairing(*before)
    require(time.monotonic() - start < MAX_SEC, "SIGNER_READ_TIME_BUDGET_STOP")
    return result


# R1041: added fixed-names metadata-only unknown-services/cron classification.
# The read_small, report, nonce_binding, pairing, and signer_main source above
# was mechanically carried over from previously reviewed Draft PR #849.
# No signer POST, changes to writer state, or service management.
SYSTEMD_UNKNOWNS = (
    "technocore-safe-agent-close1-discord-activation.service",
    "technocore-safe-agent-postreboot-check.service",
)
SHOW_KEYS = (
    "Id", "LoadState", "ActiveState", "UnitFileState", "FragmentPath",
    "ExecStart", "ExecStartPre", "ExecStartPost", "User", "Type", "ReadWritePaths",
    "Requires", "Wants",
)
CRON_PATHS = (
    Path("/etc/crontab"), Path("/etc/cron.d"),
    Path("/var/spool/cron/crontabs"), Path("/var/spool/cron"),
)
FLAGS = {
    "original_source_pin": "PASS",
    "no_source_or_unit_modification": "YES",
    "all_writers_fenced": "NO",
    "cron_discovery_complete": "NO",
    "process_enumeration_complete": "NO",
    "signer_inflight_post_resolved": "NO",
    "capture_common_epoch_proven": "NO",
    "oci_retirement": "STRICT_NO_GO",
}

def show_fixed_unit(name):
    require(name in SYSTEMD_UNKNOWNS, "UNIT_ALLOWLIST_STOP")
    try:
        p = subprocess.run(
            ("systemctl", "show", "--no-pager",
             "--property=" + ",".join(SHOW_KEYS), name),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=3, check=False, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    except (OSError, subprocess.TimeoutExpired):
        raise Stop("UNIT_SHOW_STOP") from None
    require(p.returncode == 0 and len(p.stdout) <= 16384, "UNIT_SHOW_STOP")
    try:
        lines = p.stdout.decode("utf-8", "strict").splitlines()
    except UnicodeError:
        raise Stop("UNIT_SHOW_STOP") from None
    values = {}
    for line in lines:
        require("=" in line, "UNIT_SCHEMA_STOP")
        key, value = line.split("=", 1)
        require(key in SHOW_KEYS and key not in values, "UNIT_SCHEMA_STOP")
        values[key] = value
    require(set(("Id", "LoadState", "ActiveState", "UnitFileState",
                 "FragmentPath", "ExecStart")) <= values.keys(), "UNIT_SCHEMA_STOP")
    require(values["Id"] == name, "UNIT_ID_STOP")
    require(values["LoadState"] in ("loaded", "masked", "not-found", "bad-setting",
                                    "error"), "UNIT_STATE_STOP")
    require(values["ActiveState"] in ("active", "inactive", "activating",
                                      "deactivating", "failed", "reloading"),
            "UNIT_STATE_STOP")
    command = values["ExecStart"].lower()
    if not command:
        kind = "EMPTY"
    elif "flop_agent." in command and "/opt/technocore-safe-agent" in command:
        kind = "FLOP_PYTHON"
    elif "/bin/bash" in command or "/bin/sh " in command or "/bin/sh;" in command:
        kind = "SHELL_WRAPPER"
    elif "systemctl " in command:
        kind = "SYSTEMCTL_WRAPPER"
    elif "python" in command:
        kind = "PYTHON_UNVERIFIED"
    else:
        kind = "OTHER_UNVERIFIED"
    readwrite = values.get("ReadWritePaths", "")
    if "/var/lib/technocore-safe-agent" in readwrite:
        scope = "FLOP_STATE_DECLARED"
    elif readwrite:
        scope = "OTHER_PATH_DECLARED"
    else:
        scope = "NO_EXPLICIT_READWRITE"
    dependency = "FLOP_SERVICE_REFERENCE" if any(
        "technocore-safe-agent-" in values.get(k, "")
        for k in ("Requires", "Wants")) else "NO_FLOP_DEPENDENCY_REFERENCE"
    fragment = values["FragmentPath"]
    origin = ("ETC_SYSTEMD" if fragment.startswith("/etc/systemd/system/") and
              len(fragment) <= 192 else "OTHER_UNVERIFIED")
    # No ExecStart raw, arguments, user identity, folder name or env printed.
    return {
        "identity": name, "active": values["ActiveState"],
        "command_kind": kind, "declared_write_scope": scope,
        "dependency_kind": dependency, "fragment_origin": origin,
        "pre_exec_configured": bool(values.get("ExecStartPre", "")),
        "post_exec_configured": bool(values.get("ExecStartPost", "")),
        "service_type": (values.get("Type", "") if values.get("Type", "") in
                         ("simple", "oneshot", "forking", "notify", "exec", "dbus",
                          "idle") else "OTHER_UNVERIFIED"),
    }

def cron_metadata_reason():
    items = []
    for parent in CRON_PATHS:
        try:
            meta = parent.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(meta.st_mode):
            items.append(parent)
        elif stat.S_ISDIR(meta.st_mode):
            try:
                children = list(parent.iterdir())
            except OSError:
                raise Stop("CRON_DIR_STOP") from None
            require(len(children) <= 120, "CRON_BOUND_STOP")
            items.extend(children)
        else:
            # Never follow unknown cron root file or symlink.
            items.append(parent)
    require(len(items) <= 120, "CRON_BOUND_STOP")
    out = {"regular_size_bounded": 0, "symlink": 0,
           "oversized": 0, "nonregular": 0, "multiple_links": 0,
           "raced": 0}
    for path in items:
        try:
            m = path.lstat()
            if stat.S_ISLNK(m.st_mode):
                out["symlink"] += 1
            elif not stat.S_ISREG(m.st_mode):
                out["nonregular"] += 1
            elif m.st_nlink != 1:
                out["multiple_links"] += 1
            elif m.st_size > 65536:
                out["oversized"] += 1
            else:
                out["regular_size_bounded"] += 1
        except (PermissionError, FileNotFoundError, OSError):
            out["raced"] += 1
    return out

def run_combined():
    started = time.monotonic()
    require(sys.platform == "linux" and os.geteuid() == 0 and not sys.argv[1:],
            "ORIGINAL_ROOT_ONLY_STOP")
    # Inspect exactly the two not-yet-classified guest service metadata objects.
    units = [show_fixed_unit(n) for n in SYSTEMD_UNKNOWNS]
    cron = cron_metadata_reason()
    try:
        signer = {"validation": "PASS", "result": signer_main()}
    except (Stop, OSError, ValueError, KeyError, UnicodeError,
            subprocess.TimeoutExpired, json.JSONDecodeError):
        # Fail closed but retain distinct, non-sensitive unit/cron evidence.
        signer = {"validation": "GUARD_STOP", "result": None}
    require(time.monotonic() - started <= 29, "R1041_TIME_STOP")
    report = {
        "schema_version": 1, "original_head": PINNED_LIVE_HEAD,
        "units": units, "cron": cron, "signer": signer, "flags": FLAGS,
    }
    raw = json.dumps(report, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True) + "\n"
    require(len(raw) <= 16384, "REPORT_BOUND_STOP")
    print(raw, end="")

if __name__ == "__main__":
    try:
        run_combined()
    except (Stop, OSError, ValueError, KeyError, UnicodeError,
            subprocess.TimeoutExpired, json.JSONDecodeError, TypeError):
        print("FLOP_R1041_STOP=GUEST_GUARD_STOP")
        sys.exit(42)
