#!/usr/bin/env python3
"""Flop OCI signer transfer risk readiness inventory.

Read only; exact three small JSON data files and public DID; no secrets/env,
no network, no file write, no service changes, no large SQLite/state content.
An active writer ALWAYS blocks actual cutover even when counts are zero.
"""
from collections import Counter
import json
import os
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
    mode = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
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

def main():
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
    summary = report(*before)
    require(time.monotonic() - start < MAX_SEC, "SIGNER_READ_TIME_BUDGET_STOP")
    print("FLOP_OCI_SIGNER_LIVE_UNITS_UNCHANGED_PASS", flush=True)
    for field, value in summary.items():
        print("FLOP_OCI_GATE_" + field.upper() + "=" +
              (str(int(value)).lower() if isinstance(value, bool) else str(value)),
              flush=True)
    pending = (summary["signer_prepared"] + summary["signer_posted"] +
               summary["outbox_queued"] + summary["outbox_posted"] +
               summary["outbox_ambiguous"])
    print("FLOP_OCI_PENDING_OR_AMBIGUOUS_COUNT=" + str(pending), flush=True)
    print("FLOP_OCI_SIGNER_CUTOVER_NOT_AUTHORIZED_WHILE_LIVE", flush=True)
    print("FLOP_OCI_SIGNER_GATE_READ_ONLY_PASS", flush=True)

if __name__ == "__main__":
    try:
        main()
    except (Stop, OSError, ValueError, KeyError, UnicodeError,
            subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        print("FLOP_OCI_SIGNER_GATE_STOP=" +
              (str(e) if isinstance(e, Stop) else type(e).__name__), flush=True)
        sys.exit(42)
